'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const { PassThrough } = require('node:stream');
const { spawn, spawnSync } = require('node:child_process');

async function closeGate(gate) {
    if (!gate) return;
    gate.terminate();
    if (typeof gate.start === 'function') {
        await Promise.race([
            gate.start(),
            new Promise((r) => setTimeout(r, 1500)),
        ]);
    }
}

const {
    createHarness,
    createMcpGate,
    ROLE_LEVEL_DENY_CODES,
    canonicalJson,
} = require('../src/index');

const fixturesDir = path.join(__dirname, 'fixtures');
const rolesFile = path.join(fixturesDir, 'roles.json');
const assignmentsFile = path.join(fixturesDir, 'assignments.json');
const toolNamesFile = path.join(fixturesDir, 'tool-names.json');
const fakeServerScript = path.join(fixturesDir, 'fake-mcp-server.js');
const gateBinPath = path.join(__dirname, '..', 'bin', 'agent-harness-mcp-gate.js');
const hookBinPath = path.join(__dirname, '..', 'bin', 'agent-harness-hook.js');

function waitNextLine(stream, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
        let buffer = '';
        const timer = setTimeout(() => {
            cleanup();
            reject(new Error(`waitNextLine timed out after ${timeoutMs}ms (received: ${buffer})`));
        }, timeoutMs);

        function onData(chunk) {
            buffer += chunk.toString('utf8');
            const idx = buffer.indexOf('\n');
            if (idx !== -1) {
                const line = buffer.slice(0, idx).trim();
                cleanup();
                resolve(line);
            }
        }

        function cleanup() {
            clearTimeout(timer);
            stream.removeListener('data', onData);
        }

        stream.on('data', onData);
    });
}

function waitLogContains(filePath, predicate, timeoutMs = 4000) {
    const start = Date.now();
    return new Promise((resolve, reject) => {
        function check() {
            try {
                if (fs.existsSync(filePath)) {
                    const content = fs.readFileSync(filePath, 'utf8');
                    const lines = content.split('\n').filter((l) => l.trim().length > 0);
                    const parsed = lines.map((l) => {
                        try { return JSON.parse(l); } catch (_) { return { raw: l }; }
                    });
                    if (predicate(parsed)) {
                        return resolve(parsed);
                    }
                }
            } catch (_) {}

            if (Date.now() - start > timeoutMs) {
                reject(new Error(`waitLogContains timed out after ${timeoutMs}ms`));
            } else {
                setTimeout(check, 50);
            }
        }
        check();
    });
}

describe('Enforcers: MCP Gate (in-process)', () => {
    let tmpDir;
    let harness;

    before(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-gate-test-'));
        harness = createHarness({
            roles: rolesFile,
            assignments: assignmentsFile,
            toolNames: toolNamesFile,
        });
    });

    after(() => {
        try {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        } catch (_) {}
    });

    it('exports ROLE_LEVEL_DENY_CODES as expected set', () => {
        assert.ok(ROLE_LEVEL_DENY_CODES instanceof Set);
        assert.ok(ROLE_LEVEL_DENY_CODES.has('tool_not_allowed'));
        assert.ok(ROLE_LEVEL_DENY_CODES.has('tool_denied'));
        assert.ok(ROLE_LEVEL_DENY_CODES.has('mcp_server_forbidden'));
        assert.ok(ROLE_LEVEL_DENY_CODES.has('exec_disabled'));
    });

    it('allowed call forwarded to upstream, answered by upstream, logged', async () => {
        const testLog = path.join(tmpDir, 'allowed-call.log');
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            const nextLinePromise = waitNextLine(output);
            input.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'tools/call',
                params: {
                    name: 'read_data',
                    arguments: { key: 'secret_value' },
                },
            }) + '\n');

            const respLine = await nextLinePromise;
            const resp = JSON.parse(respLine);

            assert.strictEqual(resp.id, 1);
            assert.strictEqual(resp.result.isError, false);
            assert.ok(resp.result.content[0].text.includes('echo:'));

            // Verify logged in upstream
            const logs = await waitLogContains(testLog, (entries) =>
                entries.some((e) => e.method === 'tools/call' && e.name === 'read_data' && e.id === 1)
            );
            assert.ok(logs.some((e) => e.name === 'read_data'));
        } finally {
            await closeGate(gate);
        }
    });

    it('denied call answered by gate with isError and absent from upstream log', async () => {
        const testLog = path.join(tmpDir, 'denied-call.log');
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            const nextLinePromise = waitNextLine(output);
            input.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 2,
                method: 'tools/call',
                params: {
                    name: 'delete_all',
                    arguments: { force: true },
                },
            }) + '\n');

            const respLine = await nextLinePromise;
            const resp = JSON.parse(respLine);

            assert.strictEqual(resp.id, 2);
            assert.strictEqual(resp.result.isError, true);
            assert.ok(resp.result.content[0].text.includes('tool_denied'));

            // Wait a moment and ensure it was NOT forwarded to upstream
            await new Promise((r) => setTimeout(r, 150));
            if (fs.existsSync(testLog)) {
                const logs = fs.readFileSync(testLog, 'utf8');
                assert.strictEqual(logs.includes('delete_all'), false);
            }
        } finally {
            await closeGate(gate);
        }
    });

    it('batch mixed allow/deny: gate answers denied, upstream answers allowed, merged correctly', async () => {
        const testLog = path.join(tmpDir, 'batch-call.log');
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            const nextLinePromise = waitNextLine(output);
            const batchRequest = [
                {
                    jsonrpc: '2.0',
                    id: 101,
                    method: 'tools/call',
                    params: { name: 'read_data', arguments: { item: 1 } },
                },
                {
                    jsonrpc: '2.0',
                    id: 102,
                    method: 'tools/call',
                    params: { name: 'delete_all', arguments: { item: 2 } },
                },
            ];

            input.write(JSON.stringify(batchRequest) + '\n');

            const respLine = await nextLinePromise;
            const batchResp = JSON.parse(respLine);

            assert.ok(Array.isArray(batchResp));
            assert.strictEqual(batchResp.length, 2);

            const resp101 = batchResp.find((r) => r.id === 101);
            const resp102 = batchResp.find((r) => r.id === 102);

            assert.ok(resp101);
            assert.strictEqual(resp101.result.isError, false);
            assert.ok(resp101.result.content[0].text.includes('echo:'));

            assert.ok(resp102);
            assert.strictEqual(resp102.result.isError, true);
            assert.ok(resp102.result.content[0].text.includes('tool_denied'));

            // Upstream only received item 101
            const logs = await waitLogContains(testLog, (entries) =>
                entries.some((e) => e.id === 101 && e.name === 'read_data')
            );
            assert.strictEqual(logs.some((e) => e.id === 102), false);
            assert.strictEqual(logs.some((e) => e.name === 'delete_all'), false);
        } finally {
            await closeGate(gate);
        }
    });

    it('batch mixed with only notifications allowed: gate answers denied items promptly without hanging', async () => {
        const testLog = path.join(tmpDir, 'batch-notification-only-allowed.log');
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            const nextLinePromise = waitNextLine(output, 2000);
            const batchRequest = [
                {
                    jsonrpc: '2.0',
                    id: 7,
                    method: 'tools/call',
                    params: { name: 'delete_all', arguments: {} },
                },
                {
                    jsonrpc: '2.0',
                    method: 'notifications/initialized',
                    params: { info: 'test' },
                },
            ];

            input.write(JSON.stringify(batchRequest) + '\n');

            const respLine = await nextLinePromise;
            const batchResp = JSON.parse(respLine);

            assert.ok(Array.isArray(batchResp));
            assert.strictEqual(batchResp.length, 1);
            assert.strictEqual(batchResp[0].id, 7);
            assert.strictEqual(batchResp[0].result.isError, true);

            // Upstream log receives only the notification
            const logs = await waitLogContains(testLog, (entries) =>
                entries.some((e) => e.method === 'notifications/initialized')
            );
            assert.strictEqual(logs.some((e) => e.id === 7), false);
            assert.strictEqual(logs.some((e) => e.name === 'delete_all'), false);
        } finally {
            await closeGate(gate);
        }
    });

    it('batch all denied: gate answers immediately without forwarding to upstream', async () => {
        const testLog = path.join(tmpDir, 'batch-all-deny.log');
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            const nextLinePromise = waitNextLine(output);
            const batchRequest = [
                {
                    jsonrpc: '2.0',
                    id: 111,
                    method: 'tools/call',
                    params: { name: 'delete_all', arguments: {} },
                },
            ];

            input.write(JSON.stringify(batchRequest) + '\n');

            const respLine = await nextLinePromise;
            const batchResp = JSON.parse(respLine);

            assert.ok(Array.isArray(batchResp));
            assert.strictEqual(batchResp.length, 1);
            assert.strictEqual(batchResp[0].id, 111);
            assert.strictEqual(batchResp[0].result.isError, true);

            await new Promise((r) => setTimeout(r, 100));
            assert.strictEqual(fs.existsSync(testLog), false);
        } finally {
            await closeGate(gate);
        }
    });

    it('tools/list filtering: enforce drops role-denied tools, audit does not filter', async () => {
        // Enforce mode
        {
            const input = new PassThrough();
            const output = new PassThrough();

            const gate = createMcpGate({
                harness,
                agentId: 'mcp-agent',
                serverName: 'test-server',
                mode: 'enforce',
                stdin: input,
                stdout: output,
                onExit: () => {},
                upstream: {
                    command: process.execPath,
                    args: [fakeServerScript],
                },
            });

            try {
                const nextLinePromise = waitNextLine(output);
                input.write(JSON.stringify({
                    jsonrpc: '2.0',
                    id: 201,
                    method: 'tools/list',
                    params: {},
                }) + '\n');

                const respLine = await nextLinePromise;
                const resp = JSON.parse(respLine);

                assert.strictEqual(resp.id, 201);
                assert.ok(Array.isArray(resp.result.tools));
                const toolNames = resp.result.tools.map((t) => t.name);

                // read_data is allowed; delete_all (tool_denied), exec_cmd (tool_not_allowed),
                // and whitespace-padded tool names are dropped in enforce mode
                assert.ok(toolNames.includes('read_data'));
                assert.strictEqual(toolNames.includes('delete_all'), false);
                assert.strictEqual(toolNames.includes('exec_cmd'), false);
                assert.strictEqual(toolNames.includes(' read_data'), false);
                assert.strictEqual(toolNames.includes('read_data '), false);
            } finally {
                gate.terminate();
            }
        }

        // Audit mode
        {
            const input = new PassThrough();
            const output = new PassThrough();

            const gate = createMcpGate({
                harness,
                agentId: 'mcp-agent',
                serverName: 'test-server',
                mode: 'audit',
                stdin: input,
                stdout: output,
                onExit: () => {},
                upstream: {
                    command: process.execPath,
                    args: [fakeServerScript],
                },
            });

            try {
                const nextLinePromise = waitNextLine(output);
                input.write(JSON.stringify({
                    jsonrpc: '2.0',
                    id: 202,
                    method: 'tools/list',
                    params: {},
                }) + '\n');

                const respLine = await nextLinePromise;
                const resp = JSON.parse(respLine);

                assert.strictEqual(resp.id, 202);
                assert.ok(Array.isArray(resp.result.tools));
                const toolNames = resp.result.tools.map((t) => t.name);

                // In audit mode, all tools are preserved
                assert.ok(toolNames.includes('read_data'));
                assert.ok(toolNames.includes('delete_all'));
                assert.ok(toolNames.includes('exec_cmd'));
                assert.ok(toolNames.includes(' read_data'));
                assert.ok(toolNames.includes('read_data '));
            } finally {
                gate.terminate();
            }
        }
    });

    it('audit mode forwards denied call with wouldBlock in onDecision record', async () => {
        const testLog = path.join(tmpDir, 'audit-forward.log');
        const input = new PassThrough();
        const output = new PassThrough();
        let capturedDecision = null;

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'audit',
            stdin: input,
            stdout: output,
            onDecision: (record) => {
                capturedDecision = record;
            },
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            const nextLinePromise = waitNextLine(output);
            input.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 250,
                method: 'tools/call',
                params: {
                    name: 'delete_all',
                    arguments: { key: 'val' },
                },
            }) + '\n');

            const respLine = await nextLinePromise;
            const resp = JSON.parse(respLine);

            // Upstream answers because it was forwarded
            assert.strictEqual(resp.id, 250);
            assert.strictEqual(resp.result.isError, false);
            assert.ok(resp.result.content[0].text.includes('echo:'));

            // Verified forwarded to upstream
            const logs = await waitLogContains(testLog, (entries) =>
                entries.some((e) => e.method === 'tools/call' && e.name === 'delete_all' && e.id === 250)
            );
            assert.ok(logs.some((e) => e.name === 'delete_all'));

            // Verified audit record was created with wouldBlock: true
            assert.ok(capturedDecision);
            assert.strictEqual(capturedDecision.mode, 'audit');
            assert.strictEqual(capturedDecision.wouldBlock, true);
            assert.strictEqual(capturedDecision.allow, true);
            assert.ok(capturedDecision.reason.includes('tool_denied'));
            assert.strictEqual(capturedDecision.toolName, 'mcp__test-server__delete_all');
        } finally {
            await closeGate(gate);
        }
    });

    it('parse error: returns JSON-RPC -32700 on invalid JSON and does not forward', async () => {
        const testLog = path.join(tmpDir, 'parse-err.log');
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            const nextLinePromise = waitNextLine(output);
            input.write('{"jsonrpc":"2.0", "id": 999, invalid-json-here\n');

            const respLine = await nextLinePromise;
            const resp = JSON.parse(respLine);

            assert.strictEqual(resp.error.code, -32700);
            assert.ok(resp.error.message.includes('Parse error'));

            await new Promise((r) => setTimeout(r, 150));
            if (fs.existsSync(testLog)) {
                const content = fs.readFileSync(testLog, 'utf8');
                assert.strictEqual(content.includes('999'), false);
            }
        } finally {
            await closeGate(gate);
        }
    });

    it('oversize line (> 4 MiB): returns -32600 for request with id, drops for notification', async () => {
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
            },
        });

        try {
            // Request with ID
            const padding = 'x'.repeat(4 * 1024 * 1024 + 100);
            const oversizeRequest = `{"jsonrpc":"2.0","id":301,"method":"tools/call","params":{"name":"read_data","padding":"${padding}"}}\n`;

            const nextLinePromise = waitNextLine(output);
            input.write(oversizeRequest);

            const respLine = await nextLinePromise;
            const resp = JSON.parse(respLine);

            assert.strictEqual(resp.id, 301);
            assert.strictEqual(resp.error.code, -32600);
            assert.ok(resp.error.message.includes('exceeded maximum size'));

            // Notification without ID (oversize) -> dropped silently
            let notificationReceived = false;
            output.on('data', () => { notificationReceived = true; });

            const oversizeNotification = `{"jsonrpc":"2.0","method":"notifications/test","params":{"padding":"${padding}"}}\n`;
            input.write(oversizeNotification);

            await new Promise((r) => setTimeout(r, 150));
            assert.strictEqual(notificationReceived, false);
        } finally {
            await closeGate(gate);
        }
    });

    it('notification passthrough in both directions', async () => {
        const testLog = path.join(tmpDir, 'notify-pass.log');
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            // Direction 1: Client -> Upstream notification
            input.write(JSON.stringify({
                jsonrpc: '2.0',
                method: 'notifications/initialized',
                params: { ready: true },
            }) + '\n');

            const logs = await waitLogContains(testLog, (entries) =>
                entries.some((e) => e.method === 'notifications/initialized')
            );
            assert.ok(logs.some((e) => e.method === 'notifications/initialized'));

            // Direction 2: Upstream -> Client notification
            const line1Promise = waitNextLine(output);
            input.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 350,
                method: 'test/send_notification',
            }) + '\n');

            // The fake server emits a notification line first, then the method response
            const firstReceived = await line1Promise;
            const parsed1 = JSON.parse(firstReceived);

            assert.strictEqual(parsed1.method, 'notifications/server_alert');
            assert.strictEqual(parsed1.params.text, 'alert from server');

            // Then response for test/send_notification
            const line2Promise = waitNextLine(output);
            const secondReceived = await line2Promise;
            const parsed2 = JSON.parse(secondReceived);
            assert.strictEqual(parsed2.id, 350);
            assert.strictEqual(parsed2.result.status, 'sent');
        } finally {
            await closeGate(gate);
        }
    });

    it('homoglyph tool name denied with isError: true', async () => {
        const testLog = path.join(tmpDir, 'homoglyph.log');
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            // Cyrillic 'а' (U+0430) and 'е' (U+0435) inside "read_data"
            const spoofedName = 'r\u0435\u0430d_d\u0430t\u0430';
            const nextLinePromise = waitNextLine(output);

            input.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 401,
                method: 'tools/call',
                params: {
                    name: spoofedName,
                    arguments: {},
                },
            }) + '\n');

            const respLine = await nextLinePromise;
            const resp = JSON.parse(respLine);

            assert.strictEqual(resp.id, 401);
            assert.strictEqual(resp.result.isError, true);
            assert.ok(resp.result.content[0].text.includes('tool_name_suspicious'));

            await new Promise((r) => setTimeout(r, 150));
            if (fs.existsSync(testLog)) {
                const content = fs.readFileSync(testLog, 'utf8');
                assert.strictEqual(content.includes('401'), false);
            }
        } finally {
            await closeGate(gate);
        }
    });

    it('stdin close terminates upstream with SIGTERM', async () => {
        const testLog = path.join(tmpDir, 'stdin-term.log');
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            // Initialize connection
            const nextLinePromise = waitNextLine(output);
            input.write(JSON.stringify({ jsonrpc: '2.0', id: 501, method: 'initialize', params: {} }) + '\n');
            await nextLinePromise;

            // Close stdin
            input.end();

            // Wait for SIGTERM logged by fake server
            const logs = await waitLogContains(testLog, (entries) =>
                entries.some((e) => e.event === 'SIGTERM')
            );
            assert.ok(logs.some((e) => e.event === 'SIGTERM'));
        } finally {
            await closeGate(gate);
        }
    });

    it('upstream exit code propagates to gate onExit and start()', async () => {
        const input = new PassThrough();
        const output = new PassThrough();

        let exitReported = null;

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: (code) => {
                exitReported = code;
            },
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
            },
        });

        try {
            // Send command instructing fake server to exit with code 42
            input.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 601,
                method: 'test/exit',
                params: { code: 42 },
            }) + '\n');

            const code = await gate.start();
            assert.strictEqual(code, 42);
            assert.strictEqual(exitReported, 42);
        } finally {
            await closeGate(gate);
        }
    });

    it('audit mode with missing agentId/serverName logs to onDecision and passes through', async () => {
        const testLog = path.join(tmpDir, 'audit-missing-start.log');
        let auditRecord = null;
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness: null,
            agentId: null,
            serverName: null,
            mode: 'audit',
            stdin: input,
            stdout: output,
            onDecision: (r) => { auditRecord = r; },
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            assert.ok(auditRecord);
            assert.strictEqual(auditRecord.mode, 'audit');
            assert.strictEqual(auditRecord.wouldBlock, true);
            assert.ok(auditRecord.reason.includes('enforcer_error'));

            // Verify that requests still pass through in audit mode
            const nextLinePromise = waitNextLine(output);
            input.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 701,
                method: 'initialize',
                params: {},
            }) + '\n');

            const respLine = await nextLinePromise;
            const resp = JSON.parse(respLine);
            assert.strictEqual(resp.id, 701);
            assert.strictEqual(resp.result.serverInfo.name, 'fake-mcp');
        } finally {
            await closeGate(gate);
        }
    });

    it('missing or invalid params.name in tools/call is denied in enforce mode', async () => {
        const testLog = path.join(tmpDir, 'missing-name.log');
        const input = new PassThrough();
        const output = new PassThrough();
        let capturedRecord = null;

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onDecision: (r) => { capturedRecord = r; },
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            const nextLinePromise = waitNextLine(output);
            input.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 801,
                method: 'tools/call',
                params: {
                    arguments: { foo: 'bar' },
                },
            }) + '\n');

            const respLine = await nextLinePromise;
            const resp = JSON.parse(respLine);

            assert.strictEqual(resp.id, 801);
            assert.strictEqual(resp.result.isError, true);
            assert.ok(resp.result.content[0].text.includes('tool_name_invalid'));
            assert.ok(capturedRecord);
            assert.strictEqual(capturedRecord.allow, false);
            assert.strictEqual(capturedRecord.wouldBlock, true);
        } finally {
            await closeGate(gate);
        }
    });

    it('tools/list filtering fails closed when decide() throws or returns garbage', async () => {
        // Enforce mode with throwing decide()
        {
            const throwingHarness = {
                decide: () => { throw new Error('simulated decide failure'); },
                resolveRole: () => 'ops',
                resolveAgent: () => ({ role: 'ops' }),
            };
            const input = new PassThrough();
            const output = new PassThrough();
            const gate = createMcpGate({
                harness: throwingHarness,
                agentId: 'mcp-agent',
                serverName: 'test-server',
                mode: 'enforce',
                stdin: input,
                stdout: output,
                onExit: () => {},
                upstream: { command: process.execPath, args: [fakeServerScript] },
            });
            try {
                const nextLinePromise = waitNextLine(output);
                input.write(JSON.stringify({ jsonrpc: '2.0', id: 211, method: 'tools/list', params: {} }) + '\n');
                const resp = JSON.parse(await nextLinePromise);
                assert.strictEqual(resp.id, 211);
                assert.deepStrictEqual(resp.result.tools, []);
            } finally {
                gate.terminate();
            }
        }

        // Enforce mode with garbage decide()
        {
            const garbageHarness = {
                decide: () => null,
                resolveRole: () => 'ops',
                resolveAgent: () => ({ role: 'ops' }),
            };
            const input = new PassThrough();
            const output = new PassThrough();
            const gate = createMcpGate({
                harness: garbageHarness,
                agentId: 'mcp-agent',
                serverName: 'test-server',
                mode: 'enforce',
                stdin: input,
                stdout: output,
                onExit: () => {},
                upstream: { command: process.execPath, args: [fakeServerScript] },
            });
            try {
                const nextLinePromise = waitNextLine(output);
                input.write(JSON.stringify({ jsonrpc: '2.0', id: 212, method: 'tools/list', params: {} }) + '\n');
                const resp = JSON.parse(await nextLinePromise);
                assert.strictEqual(resp.id, 212);
                assert.deepStrictEqual(resp.result.tools, []);
            } finally {
                gate.terminate();
            }
        }

        // Audit mode with throwing decide(): tools are NOT filtered
        {
            const throwingHarness = {
                decide: () => { throw new Error('simulated decide failure'); },
                resolveRole: () => 'ops',
                resolveAgent: () => ({ role: 'ops' }),
            };
            const input = new PassThrough();
            const output = new PassThrough();
            const gate = createMcpGate({
                harness: throwingHarness,
                agentId: 'mcp-agent',
                serverName: 'test-server',
                mode: 'audit',
                stdin: input,
                stdout: output,
                onExit: () => {},
                upstream: { command: process.execPath, args: [fakeServerScript] },
            });
            try {
                const nextLinePromise = waitNextLine(output);
                input.write(JSON.stringify({ jsonrpc: '2.0', id: 213, method: 'tools/list', params: {} }) + '\n');
                const resp = JSON.parse(await nextLinePromise);
                assert.strictEqual(resp.id, 213);
                assert.strictEqual(resp.result.tools.length, 5);
            } finally {
                gate.terminate();
            }
        }

        // Audit mode with garbage decide(): tools are NOT filtered
        {
            const garbageHarness = {
                decide: () => null,
                resolveRole: () => 'ops',
                resolveAgent: () => ({ role: 'ops' }),
            };
            const input = new PassThrough();
            const output = new PassThrough();
            const gate = createMcpGate({
                harness: garbageHarness,
                agentId: 'mcp-agent',
                serverName: 'test-server',
                mode: 'audit',
                stdin: input,
                stdout: output,
                onExit: () => {},
                upstream: { command: process.execPath, args: [fakeServerScript] },
            });
            try {
                const nextLinePromise = waitNextLine(output);
                input.write(JSON.stringify({ jsonrpc: '2.0', id: 214, method: 'tools/list', params: {} }) + '\n');
                const resp = JSON.parse(await nextLinePromise);
                assert.strictEqual(resp.id, 214);
                assert.strictEqual(resp.result.tools.length, 5);
            } finally {
                gate.terminate();
            }
        }
    });

    it('exact tool name matching in tools/call: whitespace tool name rejected and not forwarded', async () => {
        const testLog = path.join(tmpDir, 'exact-name-call.log');
        const input = new PassThrough();
        const output = new PassThrough();

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: () => {},
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: { ...process.env, FAKE_MCP_LOG_FILE: testLog },
            },
        });

        try {
            // 1. Tool name with trailing whitespace "read_data " -> rejected by gate
            const line1Promise = waitNextLine(output);
            input.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 221,
                method: 'tools/call',
                params: {
                    name: 'read_data ',
                    arguments: { foo: 'bar' },
                },
            }) + '\n');

            const resp1 = JSON.parse(await line1Promise);
            assert.strictEqual(resp1.id, 221);
            assert.strictEqual(resp1.result.isError, true);
            assert.ok(resp1.result.content[0].text.includes('tool_name_invalid'));

            // Assert upstream log NEVER received "read_data "
            await new Promise((r) => setTimeout(r, 100));
            if (fs.existsSync(testLog)) {
                const content = fs.readFileSync(testLog, 'utf8');
                assert.strictEqual(content.includes('read_data '), false);
            }

            // 2. Exact valid tool name "read_data" -> allowed and forwarded
            const line2Promise = waitNextLine(output);
            input.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 222,
                method: 'tools/call',
                params: {
                    name: 'read_data',
                    arguments: { foo: 'bar' },
                },
            }) + '\n');

            const resp2 = JSON.parse(await line2Promise);
            assert.strictEqual(resp2.id, 222);
            assert.strictEqual(resp2.result.isError, false);
            assert.ok(resp2.result.content[0].text.includes('echo:'));

            // Assert logged in upstream
            const logs = await waitLogContains(testLog, (entries) =>
                entries.some((e) => e.method === 'tools/call' && e.name === 'read_data' && e.id === 222)
            );
            assert.ok(logs.some((e) => e.id === 222));
        } finally {
            await closeGate(gate);
        }
    });

    it('SIGKILL escalation: upstream ignoring SIGTERM is terminated by SIGKILL after ~3s', async () => {
        const testLog = path.join(tmpDir, 'sigkill-escalation.log');
        const input = new PassThrough();
        const output = new PassThrough();

        let gateExitCode = null;
        let gateExitSignal = null;

        const gate = createMcpGate({
            harness,
            agentId: 'mcp-agent',
            serverName: 'test-server',
            mode: 'enforce',
            stdin: input,
            stdout: output,
            onExit: (code, signal) => {
                gateExitCode = code;
                gateExitSignal = signal;
            },
            upstream: {
                command: process.execPath,
                args: [fakeServerScript],
                env: {
                    ...process.env,
                    FAKE_MCP_LOG_FILE: testLog,
                    FAKE_MCP_IGNORE_SIGTERM: '1',
                },
            },
        });

        try {
            // Initialize connection
            const initPromise = waitNextLine(output);
            input.write(JSON.stringify({ jsonrpc: '2.0', id: 900, method: 'initialize', params: {} }) + '\n');
            await initPromise;

            const startTime = Date.now();
            input.end();

            // Wait 1s and assert upstream is still alive with SIGTERM_IGNORED
            await new Promise((r) => setTimeout(r, 1000));
            assert.strictEqual(gateExitCode, null, 'Gate should not have exited yet at ~1s');
            const midLogs = fs.existsSync(testLog) ? fs.readFileSync(testLog, 'utf8') : '';
            assert.ok(midLogs.includes('SIGTERM_IGNORED'), 'Upstream should have logged SIGTERM_IGNORED');

            // Await gate exit
            const exitCode = await gate.start();
            const elapsed = Date.now() - startTime;

            assert.ok(elapsed >= 2500, `Expected elapsed >= 2500ms, got ${elapsed}ms`);
            assert.ok(elapsed < 6000, `Expected elapsed < 6000ms, got ${elapsed}ms`);
            assert.ok(exitCode === 137 || gateExitSignal === 'SIGKILL', `Expected 137 or SIGKILL, got code ${exitCode}, signal ${gateExitSignal}`);
        } finally {
            await closeGate(gate);
        }
    });
});

describe('Enforcers: MCP Gate CLI binary end-to-end', () => {
    let tmpDir;

    before(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-bin-test-'));
    });

    after(() => {
        try {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        } catch (_) {}
    });

    it('fails closed with exit code 2 when missing --agent in enforce mode', () => {
        const res = spawnSync(
            process.execPath,
            [
                gateBinPath,
                '--server', 'test-server',
                '--roles', rolesFile,
                '--assignments', assignmentsFile,
                '--',
                process.execPath,
                fakeServerScript,
            ],
            { encoding: 'utf8' }
        );

        assert.strictEqual(res.status, 2);
        assert.ok(res.stderr.includes('Usage:'));
        assert.ok(res.stderr.includes('Missing required argument'));
    });

    it('fails closed with exit code 2 when missing --server in enforce mode', () => {
        const res = spawnSync(
            process.execPath,
            [
                gateBinPath,
                '--agent', 'mcp-agent',
                '--roles', rolesFile,
                '--assignments', assignmentsFile,
                '--',
                process.execPath,
                fakeServerScript,
            ],
            { encoding: 'utf8' }
        );

        assert.strictEqual(res.status, 2);
        assert.ok(res.stderr.includes('Usage:'));
        assert.ok(res.stderr.includes('Missing required argument'));
    });

    it('fails closed with exit code 2 when missing upstream command after "--"', () => {
        const res = spawnSync(
            process.execPath,
            [
                gateBinPath,
                '--agent', 'mcp-agent',
                '--server', 'test-server',
                '--roles', rolesFile,
                '--assignments', assignmentsFile,
            ],
            { encoding: 'utf8' }
        );

        assert.strictEqual(res.status, 2);
        assert.ok(res.stderr.includes('Usage:'));
        assert.ok(res.stderr.includes('Missing required argument'));
    });

    it('runs end-to-end with --audit-log recording entries with sha256 and byte length', async () => {
        const auditLogPath = path.join(tmpDir, 'mcp-audit.log');
        const upstreamLogPath = path.join(tmpDir, 'mcp-bin-upstream.log');

        const child = spawn(
            process.execPath,
            [
                gateBinPath,
                '--server', 'test-server',
                '--agent', 'mcp-agent',
                '--mode', 'enforce',
                '--roles', rolesFile,
                '--assignments', assignmentsFile,
                '--tool-names', toolNamesFile,
                '--audit-log', auditLogPath,
                '--',
                process.execPath,
                fakeServerScript,
            ],
            {
                env: { ...process.env, FAKE_MCP_LOG_FILE: upstreamLogPath },
            }
        );

        try {
            // 1. Send allowed call
            const line1Promise = waitNextLine(child.stdout);
            child.stdin.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'tools/call',
                params: {
                    name: 'read_data',
                    arguments: { foo: 'bar' },
                },
            }) + '\n');

            const resp1Line = await line1Promise;
            const resp1 = JSON.parse(resp1Line);
            assert.strictEqual(resp1.id, 1);
            assert.strictEqual(resp1.result.isError, false);

            // 2. Send denied call
            const line2Promise = waitNextLine(child.stdout);
            child.stdin.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 2,
                method: 'tools/call',
                params: {
                    name: 'delete_all',
                    arguments: { secret: 'do-not-leak' },
                },
            }) + '\n');

            const resp2Line = await line2Promise;
            const resp2 = JSON.parse(resp2Line);
            assert.strictEqual(resp2.id, 2);
            assert.strictEqual(resp2.result.isError, true);

            // Check audit log
            const auditContent = fs.readFileSync(auditLogPath, 'utf8');
            const lines = auditContent.trim().split('\n').map((l) => JSON.parse(l));

            assert.strictEqual(lines.length, 2);

            // Check record 1 (allowed)
            assert.strictEqual(lines[0].allow, true);
            assert.strictEqual(lines[0].wouldBlock, false);
            assert.strictEqual(lines[0].toolName, 'mcp__test-server__read_data');
            assert.ok(lines[0].paramsSha256);
            assert.ok(lines[0].paramsBytes > 0);
            assert.strictEqual(lines[0].params, undefined);

            // Check record 2 (denied)
            assert.strictEqual(lines[1].allow, false);
            assert.strictEqual(lines[1].wouldBlock, true);
            assert.strictEqual(lines[1].toolName, 'mcp__test-server__delete_all');
            assert.ok(lines[1].paramsSha256);
            assert.ok(lines[1].paramsBytes > 0);
            assert.strictEqual(lines[1].params, undefined);

            // Ensure parameter value "do-not-leak" is NEVER in audit log
            assert.strictEqual(auditContent.includes('do-not-leak'), false);
        } finally {
            const exitPromise = new Promise((resolve) => child.once('exit', resolve));
            try {
                child.stdin.end();
            } catch (_) {}
            try {
                child.kill('SIGTERM');
            } catch (_) {}
            await Promise.race([exitPromise, new Promise((r) => setTimeout(r, 1000))]);
            try {
                if (child.exitCode === null) child.kill('SIGKILL');
            } catch (_) {}
            await Promise.race([exitPromise, new Promise((r) => setTimeout(r, 500))]);
        }
    });

    it('audit log file verification: distinctive secrets not leaked, paramsSha256/paramsBytes match, mode is 0600', async () => {
        const mcpAuditLog = path.join(tmpDir, 'audit-secrets-mcp.log');
        const hookAuditLog = path.join(tmpDir, 'audit-secrets-hook.log');

        const secretArgs = {
            secret: 'SECRET_VALUE_7f3a',
            nested: { token: 'TOKEN_SECRET_987', count: 987654321 },
        };
        const expectedCanon = canonicalJson(secretArgs);
        const expectedHash = crypto.createHash('sha256').update(expectedCanon, 'utf8').digest('hex');
        const expectedBytes = Buffer.byteLength(expectedCanon, 'utf8');

        // 1. Test bin/agent-harness-mcp-gate.js
        const mcpChild = spawn(
            process.execPath,
            [
                gateBinPath,
                '--server', 'test-server',
                '--agent', 'mcp-agent',
                '--mode', 'enforce',
                '--roles', rolesFile,
                '--assignments', assignmentsFile,
                '--tool-names', toolNamesFile,
                '--audit-log', mcpAuditLog,
                '--',
                process.execPath,
                fakeServerScript,
            ],
            { env: process.env }
        );

        try {
            const linePromise = waitNextLine(mcpChild.stdout);
            mcpChild.stdin.write(JSON.stringify({
                jsonrpc: '2.0',
                id: 991,
                method: 'tools/call',
                params: {
                    name: 'read_data',
                    arguments: secretArgs,
                },
            }) + '\n');

            const resp = JSON.parse(await linePromise);
            assert.strictEqual(resp.id, 991);
            assert.strictEqual(resp.result.isError, false);
        } finally {
            const exitPromise = new Promise((resolve) => mcpChild.once('exit', resolve));
            try {
                mcpChild.stdin.end();
            } catch (_) {}
            try {
                mcpChild.kill('SIGTERM');
            } catch (_) {}
            await Promise.race([exitPromise, new Promise((r) => setTimeout(r, 1000))]);
            try {
                if (mcpChild.exitCode === null) mcpChild.kill('SIGKILL');
            } catch (_) {}
            await Promise.race([exitPromise, new Promise((r) => setTimeout(r, 500))]);
        }

        // Verify mcpAuditLog file
        const mcpRaw = fs.readFileSync(mcpAuditLog, 'utf8');
        assert.strictEqual(mcpRaw.includes('SECRET_VALUE_7f3a'), false, 'MCP audit log must not contain secret string');
        assert.strictEqual(mcpRaw.includes('TOKEN_SECRET_987'), false, 'MCP audit log must not contain token');
        assert.strictEqual(mcpRaw.includes('987654321'), false, 'MCP audit log must not contain secret number');

        const mcpStat = fs.statSync(mcpAuditLog);
        assert.strictEqual(mcpStat.mode & 0o777, 0o600, 'MCP audit log file mode must be 0600');

        const mcpRecords = mcpRaw.trim().split('\n').map((l) => JSON.parse(l));
        assert.strictEqual(mcpRecords.length, 1);
        assert.strictEqual(mcpRecords[0].paramsSha256, expectedHash);
        assert.strictEqual(mcpRecords[0].paramsBytes, expectedBytes);
        assert.strictEqual(/^[0-9a-f]{64}$/.test(mcpRecords[0].paramsSha256), true);
        assert.strictEqual(mcpRecords[0].params, undefined);

        // 2. Test bin/agent-harness-hook.js
        const hookChild = spawnSync(
            process.execPath,
            [
                hookBinPath,
                '--format', 'claude-code',
                '--agent', 'main',
                '--mode', 'enforce',
                '--roles', rolesFile,
                '--assignments', assignmentsFile,
                '--tool-names', toolNamesFile,
                '--audit-log', hookAuditLog,
            ],
            {
                input: JSON.stringify({
                    tool_name: 'read_data',
                    tool_input: secretArgs,
                }),
                encoding: 'utf8',
            }
        );

        // Verify hookAuditLog file
        const hookRaw = fs.readFileSync(hookAuditLog, 'utf8');
        assert.strictEqual(hookRaw.includes('SECRET_VALUE_7f3a'), false, 'Hook audit log must not contain secret string');
        assert.strictEqual(hookRaw.includes('TOKEN_SECRET_987'), false, 'Hook audit log must not contain token');
        assert.strictEqual(hookRaw.includes('987654321'), false, 'Hook audit log must not contain secret number');

        const hookStat = fs.statSync(hookAuditLog);
        assert.strictEqual(hookStat.mode & 0o777, 0o600, 'Hook audit log file mode must be 0600');

        const hookRecords = hookRaw.trim().split('\n').map((l) => JSON.parse(l));
        assert.strictEqual(hookRecords.length, 1);
        assert.strictEqual(hookRecords[0].paramsSha256, expectedHash);
        assert.strictEqual(hookRecords[0].paramsBytes, expectedBytes);
        assert.strictEqual(/^[0-9a-f]{64}$/.test(hookRecords[0].paramsSha256), true);
        assert.strictEqual(hookRecords[0].params, undefined);
    });
});
