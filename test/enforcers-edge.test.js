'use strict';

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { PassThrough } = require('node:stream');

const {
    createHarness,
    runDecision,
    createCliEnforcer,
    createMcpGate,
    createToolCallHook,
} = require('../src/index');

const fixturesDir = path.join(__dirname, 'fixtures');
const rolesFile = path.join(fixturesDir, 'roles.json');
const assignmentsFile = path.join(fixturesDir, 'assignments.json');
const toolNamesFile = path.join(fixturesDir, 'tool-names.json');

async function closeGate(gate) {
    if (!gate) return;
    gate.terminate();
    if (typeof gate.start === 'function') {
        await Promise.race([
            gate.start(),
            new Promise((r) => setTimeout(r, 1000)),
        ]);
    }
}

describe('Adversarial Enforcer Edge Tests (DEV-47)', () => {
    let harness;

    before(() => {
        harness = createHarness({
            roles: rolesFile,
            assignments: assignmentsFile,
            toolNames: toolNamesFile,
        });
    });

    describe('CLI enforcer: claude-code edge cases & fail-closed', () => {
        it('tool_input as null fails closed with exitCode 2 in enforce mode', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });
            const res = enforcer.handle({
                tool_name: 'read',
                tool_input: null,
            });
            assert.strictEqual(res.exitCode, 2, 'tool_input as null must fail closed with exitCode 2');
            assert.ok(res.stderr.length > 0, 'stderr must contain denial reason');
        });

        it('tool_input as array fails closed with exitCode 2 in enforce mode', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });
            const res = enforcer.handle({
                tool_name: 'read',
                tool_input: ['unexpected', 'array'],
            });
            assert.strictEqual(res.exitCode, 2, 'tool_input as array must fail closed with exitCode 2');
            assert.ok(res.stderr.length > 0, 'stderr must contain denial reason');
        });

        it('tool_input as unparsable string fails closed in enforce, allows with wouldBlock in audit', () => {
            let auditRecord = null;
            const enforceCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });
            const auditCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'audit',
                onDecision: (r) => { auditRecord = r; },
            });

            const badInput = { tool_name: 'read', tool_input: '{ broken json' };
            const resEnforce = enforceCli.handle(badInput);
            assert.strictEqual(resEnforce.exitCode, 2);
            assert.ok(resEnforce.stderr.includes('params_invalid'));

            const resAudit = auditCli.handle(badInput);
            assert.strictEqual(resAudit.exitCode, 0);
            assert.strictEqual(resAudit.stderr, '');
            assert.ok(auditRecord);
            assert.strictEqual(auditRecord.allow, true);
            assert.strictEqual(auditRecord.wouldBlock, true);
        });

        it('tool_name with whitespace-only fails closed in enforce, allows with wouldBlock in audit', () => {
            let auditRecord = null;
            const enforceCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });
            const auditCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'audit',
                onDecision: (r) => { auditRecord = r; },
            });

            const resEnforce = enforceCli.handle({ tool_name: '   ', tool_input: { path: '/tmp' } });
            assert.strictEqual(resEnforce.exitCode, 2);
            assert.ok(resEnforce.stderr.includes('tool_name_invalid'));

            const resAudit = auditCli.handle({ tool_name: '   ', tool_input: { path: '/tmp' } });
            assert.strictEqual(resAudit.exitCode, 0);
            assert.strictEqual(resAudit.stderr, '');
            assert.ok(auditRecord);
            assert.strictEqual(auditRecord.wouldBlock, true);
        });

        it('tool_name with zero-width / invisible characters fails closed with tool_name_suspicious', () => {
            let auditRecord = null;
            const enforceCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });
            const auditCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'audit',
                onDecision: (r) => { auditRecord = r; },
            });

            const resEnforce = enforceCli.handle({ tool_name: 'read\u200B', tool_input: { path: '/tmp' } });
            assert.strictEqual(resEnforce.exitCode, 2);
            assert.ok(resEnforce.stderr.includes('tool_name_suspicious'));

            const resAudit = auditCli.handle({ tool_name: 'read\u200B', tool_input: { path: '/tmp' } });
            assert.strictEqual(resAudit.exitCode, 0);
            assert.ok(auditRecord);
            assert.strictEqual(auditRecord.wouldBlock, true);
        });

        it('tool_name with Cyrillic homoglyph fails closed with tool_name_suspicious', () => {
            let auditRecord = null;
            const enforceCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });
            const auditCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'audit',
                onDecision: (r) => { auditRecord = r; },
            });

            // Cyrillic small letter 'е' (U+0435) inside 'read'
            const resEnforce = enforceCli.handle({ tool_name: 'r\u0435ad', tool_input: { path: '/tmp' } });
            assert.strictEqual(resEnforce.exitCode, 2);
            assert.ok(resEnforce.stderr.includes('tool_name_suspicious'));

            const resAudit = auditCli.handle({ tool_name: 'r\u0435ad', tool_input: { path: '/tmp' } });
            assert.strictEqual(resAudit.exitCode, 0);
            assert.ok(auditRecord);
            assert.strictEqual(auditRecord.wouldBlock, true);
        });

        it('mcp__ name with extra "__" segments fails closed in enforce, allows with wouldBlock in audit', () => {
            let auditRecord = null;
            const enforceCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });
            const auditCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'audit',
                onDecision: (r) => { auditRecord = r; },
            });

            const resEnforceExtra = enforceCli.handle({ tool_name: 'mcp__test-server__read__extra', tool_input: {} });
            assert.strictEqual(resEnforceExtra.exitCode, 2);
            assert.ok(resEnforceExtra.stderr.includes('server_mismatch') || resEnforceExtra.stderr.includes('tool_name_invalid'));

            const resEnforceTriple = enforceCli.handle({ tool_name: 'mcp___test-server___read', tool_input: {} });
            assert.strictEqual(resEnforceTriple.exitCode, 2);
            assert.ok(resEnforceTriple.stderr.includes('mcp_tool_name_invalid'));

            const resAudit = auditCli.handle({ tool_name: 'mcp___test-server___read', tool_input: {} });
            assert.strictEqual(resAudit.exitCode, 0);
            assert.ok(auditRecord);
            assert.strictEqual(auditRecord.wouldBlock, true);
        });

        it('tool_input as JSON string parsing to non-object array, string, or null fails closed in enforce', () => {
            const enforceCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            // array as JSON string
            const resArray = enforceCli.handle({ tool_name: 'read', tool_input: '[1, 2, 3]' });
            assert.strictEqual(resArray.exitCode, 2);
            assert.ok(resArray.stderr.includes('params_invalid'));

            // primitive string as JSON string (e.g. '"{}"' or '"plain"')
            const resQuotedObj = enforceCli.handle({ tool_name: 'read', tool_input: '"{}"' });
            assert.strictEqual(resQuotedObj.exitCode, 2);
            assert.ok(resQuotedObj.stderr.includes('params_invalid'));

            // null as JSON string
            const resNull = enforceCli.handle({ tool_name: 'read', tool_input: 'null' });
            assert.strictEqual(resNull.exitCode, 2);
            assert.ok(resNull.stderr.includes('params_invalid'));
        });

        it('tool_input as JSON string parsing to valid object is decided normally', () => {
            const enforceCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            const resValid = enforceCli.handle({
                tool_name: 'read',
                tool_input: JSON.stringify({ path: '/tmp/test.txt' }),
            });
            assert.strictEqual(resValid.exitCode, 0);
            assert.strictEqual(resValid.stdout, '');
            assert.strictEqual(resValid.stderr, '');
        });

        it('tool_input as JSON string parsing to non-object allows with wouldBlock in audit mode', () => {
            let auditRecord = null;
            const auditCli = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'audit',
                onDecision: (r) => { auditRecord = r; },
            });

            const resAudit = auditCli.handle({
                tool_name: 'read',
                tool_input: '[1, 2, 3]',
            });
            assert.strictEqual(resAudit.exitCode, 0);
            assert.strictEqual(resAudit.stderr, '');
            assert.ok(auditRecord);
            assert.strictEqual(auditRecord.allow, true);
            assert.strictEqual(auditRecord.wouldBlock, true);
            assert.ok(auditRecord.reason.includes('params_invalid'));
        });
    });

    describe('CLI enforcer: agy format edge cases & fail-closed', () => {
        it('args as invalid JSON string fails closed in enforce, allows in audit', () => {
            let auditRecord = null;
            const enforceCli = createCliEnforcer(harness, {
                format: 'agy',
                agentId: 'operator-agent',
                mode: 'enforce',
            });
            const auditCli = createCliEnforcer(harness, {
                format: 'agy',
                agentId: 'operator-agent',
                mode: 'audit',
                onDecision: (r) => { auditRecord = r; },
            });

            const badInput = { toolCall: { name: 'read', args: '{ not-json' } };
            const resEnforce = enforceCli.handle(badInput);
            assert.strictEqual(resEnforce.exitCode, 0);
            const parsedEnforce = JSON.parse(resEnforce.stdout);
            assert.strictEqual(parsedEnforce.decision, 'deny');
            assert.ok(parsedEnforce.reason.includes('params_invalid'));

            const resAudit = auditCli.handle(badInput);
            assert.strictEqual(resAudit.exitCode, 0);
            const parsedAudit = JSON.parse(resAudit.stdout);
            assert.strictEqual(parsedAudit.decision, 'allow');
            assert.ok(auditRecord);
            assert.strictEqual(auditRecord.wouldBlock, true);
        });

        it('call_mcp_tool with missing ServerName or ToolName fails closed', () => {
            const enforceCli = createCliEnforcer(harness, {
                format: 'agy',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            const resMissingServer = enforceCli.handle({
                toolCall: { name: 'call_mcp_tool', args: { ToolName: 'read' } },
            });
            const parsedMissingServer = JSON.parse(resMissingServer.stdout);
            assert.strictEqual(parsedMissingServer.decision, 'deny');
            assert.ok(parsedMissingServer.reason.includes('call_mcp_missing_target'));

            const resMissingTool = enforceCli.handle({
                toolCall: { name: 'call_mcp_tool', args: { ServerName: 'test-server' } },
            });
            const parsedMissingTool = JSON.parse(resMissingTool.stdout);
            assert.strictEqual(parsedMissingTool.decision, 'deny');
            assert.ok(parsedMissingTool.reason.includes('call_mcp_missing_target'));
        });

        it('nested call_mcp_tool inside Arguments fails closed', () => {
            const enforceCli = createCliEnforcer(harness, {
                format: 'agy',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            const resDirectNested = enforceCli.handle({
                toolCall: {
                    name: 'call_mcp_tool',
                    args: {
                        ServerName: 'test-server',
                        ToolName: 'call_mcp_tool',
                        Arguments: { ServerName: 'sub', ToolName: 'subtool' },
                    },
                },
            });
            const parsedDirect = JSON.parse(resDirectNested.stdout);
            assert.strictEqual(parsedDirect.decision, 'deny');
            assert.ok(parsedDirect.reason.includes('nested_call_mcp_tool'));

            const resInnerNested = enforceCli.handle({
                toolCall: {
                    name: 'call_mcp_tool',
                    args: {
                        ServerName: 'test-server',
                        ToolName: 'run',
                        Arguments: {
                            nested: { toolName: 'call_mcp_tool' },
                        },
                    },
                },
            });
            const parsedInner = JSON.parse(resInnerNested.stdout);
            assert.strictEqual(parsedInner.decision, 'deny');
            assert.ok(parsedInner.reason.includes('nested_call_mcp_tool'));
        });
    });

    describe('MCP gate: edge cases & fail-closed', () => {
        it('tools/call with params.name missing or non-string returns error and forwards nothing', async () => {
            const clientIn = new PassThrough();
            const clientOut = new PassThrough();

            let upstreamReceived = '';
            const gate = createMcpGate({
                harness,
                agentId: 'operator-agent',
                serverName: 'test-server',
                mode: 'enforce',
                stdin: clientIn,
                stdout: clientOut,
                onExit: () => {},
                upstream: {
                    command: 'node',
                    args: ['-e', 'process.stdin.on("data", d => console.error("UPSTREAM:" + d.toString()));'],
                    stderr: 'pipe',
                },
            });

            gate.child.stderr.on('data', (d) => { upstreamReceived += d.toString(); });

            const outLines = [];
            clientOut.on('data', (d) => {
                const lines = d.toString('utf8').trim().split('\n');
                for (const l of lines) {
                    if (l) outLines.push(JSON.parse(l));
                }
            });

            clientIn.write(JSON.stringify({ jsonrpc: '2.0', id: 101, method: 'tools/call', params: {} }) + '\n');
            clientIn.write(JSON.stringify({ jsonrpc: '2.0', id: 102, method: 'tools/call', params: { name: 999 } }) + '\n');

            await new Promise((r) => setTimeout(r, 200));
            await closeGate(gate);

            assert.strictEqual(upstreamReceived, '', 'Upstream must receive nothing for invalid tools/call');
            assert.strictEqual(outLines.length, 2);
            assert.strictEqual(outLines[0].id, 101);
            assert.strictEqual(outLines[0].result.isError, true);
            assert.ok(outLines[0].result.content[0].text.includes('tool_name_invalid'));
            assert.strictEqual(outLines[1].id, 102);
            assert.strictEqual(outLines[1].result.isError, true);
            assert.ok(outLines[1].result.content[0].text.includes('tool_name_invalid'));
        });

        it('batch where all elements are denied responds directly and forwards nothing', async () => {
            const clientIn = new PassThrough();
            const clientOut = new PassThrough();

            let upstreamReceived = '';
            const gate = createMcpGate({
                harness,
                agentId: 'reader-agent', // cannot exec
                serverName: 'test-server',
                mode: 'enforce',
                stdin: clientIn,
                stdout: clientOut,
                onExit: () => {},
                upstream: {
                    command: 'node',
                    args: ['-e', 'process.stdin.on("data", d => console.error("UPSTREAM:" + d.toString()));'],
                    stderr: 'pipe',
                },
            });

            gate.child.stderr.on('data', (d) => { upstreamReceived += d.toString(); });

            let responseBatch = null;
            clientOut.on('data', (d) => {
                responseBatch = JSON.parse(d.toString('utf8').trim());
            });

            const batch = [
                { jsonrpc: '2.0', id: 'b-1', method: 'tools/call', params: { name: 'exec' } },
                { jsonrpc: '2.0', id: 'b-2', method: 'tools/call', params: { name: 'bash' } },
            ];
            clientIn.write(JSON.stringify(batch) + '\n');

            await new Promise((r) => setTimeout(r, 200));
            await closeGate(gate);

            assert.strictEqual(upstreamReceived, '', 'Upstream must receive nothing when all batch items are denied');
            assert.ok(Array.isArray(responseBatch));
            assert.strictEqual(responseBatch.length, 2);
            assert.strictEqual(responseBatch[0].id, 'b-1');
            assert.strictEqual(responseBatch[0].result.isError, true);
            assert.strictEqual(responseBatch[1].id, 'b-2');
            assert.strictEqual(responseBatch[1].result.isError, true);
        });

        it('preserves null and string JSON-RPC ids on denied tools/call requests', async () => {
            const clientIn = new PassThrough();
            const clientOut = new PassThrough();

            const gate = createMcpGate({
                harness,
                agentId: 'reader-agent',
                serverName: 'test-server',
                mode: 'enforce',
                stdin: clientIn,
                stdout: clientOut,
                onExit: () => {},
                upstream: {
                    command: 'node',
                    args: ['-e', 'process.stdin.resume();'],
                },
            });

            const outLines = [];
            clientOut.on('data', (d) => {
                const lines = d.toString('utf8').trim().split('\n');
                for (const l of lines) {
                    if (l) outLines.push(JSON.parse(l));
                }
            });

            clientIn.write(JSON.stringify({ jsonrpc: '2.0', id: null, method: 'tools/call', params: { name: 'exec' } }) + '\n');
            clientIn.write(JSON.stringify({ jsonrpc: '2.0', id: 'req-uuid-abc-123', method: 'tools/call', params: { name: 'exec' } }) + '\n');

            await new Promise((r) => setTimeout(r, 200));
            await closeGate(gate);

            assert.strictEqual(outLines.length, 2);
            assert.strictEqual(outLines[0].id, null, 'id null must be preserved');
            assert.strictEqual(outLines[0].result.isError, true);
            assert.strictEqual(outLines[1].id, 'req-uuid-abc-123', 'string id must be preserved');
            assert.strictEqual(outLines[1].result.isError, true);
        });

        it('tools/list upstream response with non-array tools does not crash and passes through', async () => {
            const clientIn = new PassThrough();
            const clientOut = new PassThrough();

            const gate = createMcpGate({
                harness,
                agentId: 'operator-agent',
                serverName: 'test-server',
                mode: 'enforce',
                stdin: clientIn,
                stdout: clientOut,
                onExit: () => {},
                upstream: {
                    command: 'node',
                    args: ['-e', `
                        const readline = require("node:readline");
                        const rl = readline.createInterface({ input: process.stdin });
                        rl.on("line", l => {
                            const req = JSON.parse(l);
                            if (req.id === 501) console.log(JSON.stringify({ jsonrpc: "2.0", id: 501, result: { tools: null } }));
                            if (req.id === 502) console.log(JSON.stringify({ jsonrpc: "2.0", id: 502, result: { tools: "malformed-string" } }));
                            if (req.id === 503) console.log(JSON.stringify({ jsonrpc: "2.0", id: 503, result: {} }));
                        });
                    `],
                },
            });

            const outLines = [];
            clientOut.on('data', (d) => {
                const lines = d.toString('utf8').trim().split('\n');
                for (const l of lines) {
                    if (l) outLines.push(JSON.parse(l));
                }
            });

            clientIn.write(JSON.stringify({ jsonrpc: '2.0', id: 501, method: 'tools/list' }) + '\n');
            clientIn.write(JSON.stringify({ jsonrpc: '2.0', id: 502, method: 'tools/list' }) + '\n');
            clientIn.write(JSON.stringify({ jsonrpc: '2.0', id: 503, method: 'tools/list' }) + '\n');

            await new Promise((r) => setTimeout(r, 200));
            await closeGate(gate);

            assert.strictEqual(outLines.length, 3);
            assert.strictEqual(outLines[0].id, 501);
            assert.strictEqual(outLines[0].result.tools, null);
            assert.strictEqual(outLines[1].id, 502);
            assert.strictEqual(outLines[1].result.tools, 'malformed-string');
            assert.strictEqual(outLines[2].id, 503);
            assert.deepStrictEqual(outLines[2].result, {});
        });
    });

    describe('API hook & audit record edge cases', () => {
        it('event.params is never mutated by createToolCallHook', () => {
            const hook = createToolCallHook(harness, { mode: 'enforce' });

            const originalParams = {
                cmd: 'status',
                options: { verbose: true, flags: ['-a', '-b'] },
                deep: { a: { b: { c: [1, 2, 3] } } },
            };
            const event = {
                toolName: 'read',
                params: JSON.parse(JSON.stringify(originalParams)),
            };
            Object.freeze(event.params.options.flags);

            // Allowed invocation
            hook(event, { agentId: 'operator-agent' });
            assert.deepStrictEqual(event.params, originalParams, 'Allowed call must not mutate event.params');

            // Denied invocation
            const deniedEvent = {
                toolName: 'exec',
                params: JSON.parse(JSON.stringify(originalParams)),
            };
            hook(deniedEvent, { agentId: 'reader-agent' });
            assert.deepStrictEqual(deniedEvent.params, originalParams, 'Blocked call must not mutate event.params');
        });

        it('onDecision throwing in enforce mode still blocks forbidden tool and missing agentId', () => {
            const hook = createToolCallHook(harness, {
                mode: 'enforce',
                onDecision: () => {
                    throw new Error('Audit logger failed unexpectedly');
                },
            });

            // Forbidden tool for reader-agent
            const resForbidden = hook({ toolName: 'exec', params: {} }, { agentId: 'reader-agent' });
            assert.ok(resForbidden, 'Hook must return a blocking object');
            assert.strictEqual(resForbidden.block, true);
            assert.ok(resForbidden.blockReason.includes('exec_disabled'));

            // Missing agentId
            const resMissingAgent = hook({ toolName: 'read', params: {} }, {});
            assert.ok(resMissingAgent, 'Hook must return a blocking object when agentId is missing');
            assert.strictEqual(resMissingAgent.block, true);
            assert.ok(resMissingAgent.blockReason.includes('no_agent'));
        });

        it('audit record: deeply nested params with secret string is hashed and secret never appears in record JSON', () => {
            const secret = 'SUPER_SECRET_TOKEN_XYZ_987654321';
            let capturedRecord = null;

            const res = runDecision(
                harness,
                {
                    agentId: 'operator-agent',
                    toolName: 'read',
                    params: {
                        nested: {
                            level1: {
                                level2: {
                                    level3: {
                                        secretField: secret,
                                        arrayWithSecret: [secret, 'safe'],
                                    },
                                },
                            },
                        },
                    },
                },
                {
                    mode: 'enforce',
                    onDecision: (rec) => {
                        capturedRecord = rec;
                    },
                }
            );

            assert.strictEqual(res.allow, true);
            assert.ok(capturedRecord);
            const recordJson = JSON.stringify(capturedRecord);
            assert.strictEqual(
                recordJson.includes(secret),
                false,
                'Secret string from nested params must never appear in audit record JSON'
            );
            assert.ok(typeof capturedRecord.paramsSha256 === 'string' && capturedRecord.paramsSha256.length === 64);
            assert.ok(typeof capturedRecord.paramsBytes === 'number' && capturedRecord.paramsBytes > 0);
        });
    });
});
