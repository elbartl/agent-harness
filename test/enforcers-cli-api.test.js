'use strict';

const { test, describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawn, spawnSync } = require('node:child_process');

const {
    createHarness,
    runDecision,
    computeParamsHash,
    canonicalJson,
    createCliEnforcer,
    createToolCallHook,
} = require('../src/index');

const fixturesDir = path.join(__dirname, 'fixtures');
const rolesFile = path.join(fixturesDir, 'roles.json');
const assignmentsFile = path.join(fixturesDir, 'assignments.json');
const toolNamesFile = path.join(fixturesDir, 'tool-names.json');
const binPath = path.join(__dirname, '..', 'bin', 'agent-harness-hook.js');

describe('Enforcers: Common (runDecision & audit)', () => {
    let harness;

    before(() => {
        harness = createHarness({
            roles: rolesFile,
            assignments: assignmentsFile,
            toolNames: toolNamesFile,
        });
    });

    it('enforce mode: allows permitted tool with wouldBlock: false', () => {
        let loggedRecord = null;
        const res = runDecision(
            harness,
            { agentId: 'operator-agent', toolName: 'read', params: { path: '/tmp/allowed.txt' } },
            {
                mode: 'enforce',
                onDecision: (r) => { loggedRecord = r; },
                enforcer: 'test',
            }
        );

        assert.strictEqual(res.allow, true);
        assert.strictEqual(res.wouldBlock, false);
        assert.strictEqual(res.mode, 'enforce');
        assert.ok(loggedRecord);
        assert.strictEqual(loggedRecord.allow, true);
        assert.strictEqual(loggedRecord.wouldBlock, false);
        assert.strictEqual(loggedRecord.toolName, 'read');
        assert.strictEqual(loggedRecord.agentId, 'operator-agent');
        assert.strictEqual(loggedRecord.mode, 'enforce');
        assert.strictEqual(loggedRecord.enforcer, 'test');
        assert.ok(loggedRecord.paramsSha256);
        assert.ok(loggedRecord.paramsBytes > 0);
    });

    it('enforce mode: denies forbidden tool with wouldBlock: true', () => {
        let loggedRecord = null;
        const res = runDecision(
            harness,
            { agentId: 'reader-agent', toolName: 'exec', params: { command: 'echo hello' } },
            {
                mode: 'enforce',
                onDecision: (r) => { loggedRecord = r; },
            }
        );

        assert.strictEqual(res.allow, false);
        assert.strictEqual(res.wouldBlock, true);
        assert.ok(res.reason.includes('tool_not_allowed') || res.reason.includes('exec_disabled'));
        assert.ok(loggedRecord);
        assert.strictEqual(loggedRecord.allow, false);
        assert.strictEqual(loggedRecord.wouldBlock, true);
    });

    it('audit mode: returns allow: true but preserves reason and sets wouldBlock: true', () => {
        let loggedRecord = null;
        const res = runDecision(
            harness,
            { agentId: 'reader-agent', toolName: 'exec', params: { command: 'id' } },
            {
                mode: 'audit',
                onDecision: (r) => { loggedRecord = r; },
                enforcer: 'audit-test',
            }
        );

        assert.strictEqual(res.allow, true);
        assert.strictEqual(res.wouldBlock, true);
        assert.strictEqual(res.mode, 'audit');
        assert.ok(res.reason.includes('tool_not_allowed') || res.reason.includes('exec_disabled'));

        assert.ok(loggedRecord);
        assert.strictEqual(loggedRecord.allow, true);
        assert.strictEqual(loggedRecord.wouldBlock, true);
        assert.strictEqual(loggedRecord.mode, 'audit');
        assert.strictEqual(loggedRecord.enforcer, 'audit-test');
    });

    it('audit record must NOT contain params values (only sha256 and byte length)', () => {
        let loggedRecord = null;
        const secretValue = 'super-sensitive-secret-token-12345';
        runDecision(
            harness,
            { agentId: 'operator-agent', toolName: 'read', params: { token: secretValue, deeply: { secret: secretValue } } },
            {
                mode: 'enforce',
                onDecision: (r) => { loggedRecord = r; },
            }
        );

        assert.ok(loggedRecord);
        assert.strictEqual(loggedRecord.params, undefined);
        const recordStr = JSON.stringify(loggedRecord);
        assert.strictEqual(recordStr.includes(secretValue), false);
        assert.ok(loggedRecord.paramsSha256);
        assert.ok(loggedRecord.paramsBytes > 0);
    });

    it('canonicalJson handles nested key sorting, arrays, and undefined params', () => {
        const h1 = computeParamsHash({ b: 2, a: 1 });
        const h2 = computeParamsHash({ a: 1, b: 2 });
        assert.strictEqual(h1.paramsSha256, h2.paramsSha256);
        assert.strictEqual(h1.paramsBytes, h2.paramsBytes);

        const hEmpty = computeParamsHash(undefined);
        assert.strictEqual(hEmpty.paramsBytes, 0);
        assert.ok(hEmpty.paramsSha256);
    });

    it('canonicalJson skips object keys whose value is undefined like JSON.stringify', () => {
        assert.strictEqual(canonicalJson({ a: undefined }), '{}');
        assert.strictEqual(canonicalJson({ a: undefined, b: 1 }), '{"b":1}');
        assert.strictEqual(canonicalJson({ x: { a: undefined, b: 2 } }), '{"x":{"b":2}}');
    });

    it('swallows exceptions thrown by onDecision and does not alter the decision', () => {
        const res = runDecision(
            harness,
            { agentId: 'operator-agent', toolName: 'read', params: { path: '/tmp/test' } },
            {
                mode: 'enforce',
                onDecision: () => {
                    throw new Error('Exploding logger');
                },
            }
        );

        assert.strictEqual(res.allow, true);
        assert.strictEqual(res.wouldBlock, false);
    });

    it('handles harness exception/invalid result fail-closed (code enforcer_error)', () => {
        const brokenHarness = {
            decide: () => {
                throw new Error('Database connection failed');
            },
        };

        let loggedRecord = null;
        const resEnforce = runDecision(
            brokenHarness,
            { agentId: 'operator-agent', toolName: 'read' },
            {
                mode: 'enforce',
                onDecision: (r) => { loggedRecord = r; },
            }
        );

        assert.strictEqual(resEnforce.allow, false);
        assert.strictEqual(resEnforce.wouldBlock, true);
        assert.ok(resEnforce.reason.startsWith('enforcer_error:'));
        assert.ok(loggedRecord);
        assert.strictEqual(loggedRecord.allow, false);
        assert.strictEqual(loggedRecord.wouldBlock, true);
        assert.ok(loggedRecord.reason.startsWith('enforcer_error:'));

        // In audit mode: exception allows, wouldBlock: true, logged
        const resAudit = runDecision(
            brokenHarness,
            { agentId: 'operator-agent', toolName: 'read' },
            { mode: 'audit' }
        );
        assert.strictEqual(resAudit.allow, true);
        assert.strictEqual(resAudit.wouldBlock, true);
        assert.ok(resAudit.reason.startsWith('enforcer_error:'));
    });
});

describe('Enforcers: CLI Enforcer (createCliEnforcer)', () => {
    let harness;

    before(() => {
        harness = createHarness({
            roles: rolesFile,
            assignments: assignmentsFile,
            toolNames: toolNamesFile,
        });
    });

    describe('claude-code format', () => {
        it('allows permitted tool: exitCode 0, empty stdout and stderr', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            const res = enforcer.handle({
                tool_name: 'read',
                tool_input: { path: '/tmp/test.txt' },
            });

            assert.strictEqual(res.exitCode, 0);
            assert.strictEqual(res.stdout, '');
            assert.strictEqual(res.stderr, '');
        });

        it('denies forbidden tool: exitCode 2, reason on stderr', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'reader-agent',
                mode: 'enforce',
            });

            const res = enforcer.handle({
                tool_name: 'exec',
                tool_input: { command: 'ls' },
            });

            assert.strictEqual(res.exitCode, 2);
            assert.strictEqual(res.stdout, '');
            assert.ok(res.stderr.includes('tool_not_allowed') || res.stderr.includes('exec_disabled'));
        });

        it('passes mcp__<server>__<tool> through harness canonicalization', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            // test-server is allowed for operator-agent
            const resAllowed = enforcer.handle({
                tool_name: 'mcp__test-server__read',
                tool_input: { path: '/tmp/ok' },
            });
            assert.strictEqual(resAllowed.exitCode, 0);

            // unconfigured-server is forbidden for operator-agent
            const resDenied = enforcer.handle({
                tool_name: 'mcp__unconfigured-server__read',
                tool_input: { path: '/tmp/ok' },
            });
            assert.strictEqual(resDenied.exitCode, 2);
            assert.ok(resDenied.stderr.includes('mcp_server_forbidden'));
        });

        it('denies homoglyph / bidi tool name', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            const bidiTool = 'read\u202Etxt';
            const res = enforcer.handle({
                tool_name: bidiTool,
                tool_input: {},
            });

            assert.strictEqual(res.exitCode, 2);
            assert.ok(res.stderr.includes('tool_name_suspicious'));
        });

        it('fail-closed on malformed / unparsable event input', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            const res = enforcer.handle('this is not json at all {');
            assert.strictEqual(res.exitCode, 2);
            assert.ok(res.stderr.includes('enforcer_error: Unparsable event JSON'));
        });

        it('fail-closed on missing tool name', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            const res = enforcer.handle({ tool_input: { path: '/tmp/x' } });
            assert.strictEqual(res.exitCode, 2);
            assert.ok(res.stderr.includes('tool_name_invalid'));
        });

        it('fail-closed on missing agentId', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'claude-code',
                mode: 'enforce',
            });

            const res = enforcer.handle({ tool_name: 'read', tool_input: {} });
            assert.strictEqual(res.exitCode, 2);
            assert.ok(res.stderr.includes('no_agent'));
        });

        it('audit mode: allows denied tool, exitCode 0, onDecision called with wouldBlock: true', () => {
            let loggedRecord = null;
            const enforcer = createCliEnforcer(harness, {
                format: 'claude-code',
                agentId: 'reader-agent',
                mode: 'audit',
                onDecision: (r) => { loggedRecord = r; },
            });

            const res = enforcer.handle({
                tool_name: 'exec',
                tool_input: { command: 'rm -rf /' },
            });

            assert.strictEqual(res.exitCode, 0);
            assert.strictEqual(res.stdout, '');
            assert.strictEqual(res.stderr, '');
            assert.ok(loggedRecord);
            assert.strictEqual(loggedRecord.allow, true);
            assert.strictEqual(loggedRecord.wouldBlock, true);
            assert.strictEqual(loggedRecord.mode, 'audit');
        });
    });

    describe('agy format', () => {
        it('allows permitted tool: stdout {"decision":"allow"}, exitCode 0', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'agy',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            const res = enforcer.handle({
                toolCall: {
                    name: 'read',
                    args: { path: '/tmp/test.txt' },
                },
            });

            assert.strictEqual(res.exitCode, 0);
            assert.strictEqual(res.stderr, '');
            const parsed = JSON.parse(res.stdout);
            assert.strictEqual(parsed.decision, 'allow');
        });

        it('denies forbidden tool: stdout {"decision":"deny","reason":...}, exitCode 0', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'agy',
                agentId: 'reader-agent',
                mode: 'enforce',
            });

            const res = enforcer.handle({
                toolCall: {
                    name: 'exec',
                    args: '{"command":"reboot"}', // args as JSON string
                },
            });

            assert.strictEqual(res.exitCode, 0);
            assert.strictEqual(res.stderr, '');
            const parsed = JSON.parse(res.stdout);
            assert.strictEqual(parsed.decision, 'deny');
            assert.ok(parsed.reason.includes('tool_not_allowed') || parsed.reason.includes('exec_disabled'));
        });

        it('decides agy call_mcp_tool as the inner tool with Arguments', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'agy',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            // Allowed inner tool on test-server
            const resAllowed = enforcer.handle({
                toolCall: {
                    name: 'call_mcp_tool',
                    args: {
                        ServerName: 'test-server',
                        ToolName: 'read',
                        Arguments: { path: '/tmp/allowed.txt' },
                    },
                },
            });
            assert.strictEqual(JSON.parse(resAllowed.stdout).decision, 'allow');

            // Forbidden inner server
            const resForbiddenServer = enforcer.handle({
                toolCall: {
                    name: 'call_mcp_tool',
                    args: {
                        ServerName: 'disallowed-server',
                        ToolName: 'read',
                        Arguments: { path: '/tmp/test.txt' },
                    },
                },
            });
            const parsedDeny = JSON.parse(resForbiddenServer.stdout);
            assert.strictEqual(parsedDeny.decision, 'deny');
            assert.ok(parsedDeny.reason.includes('mcp_server_forbidden'));
        });

        it('blocks nested call_mcp_tool in ToolName and in Arguments', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'agy',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            // Nested call_mcp_tool as ToolName
            const resNestedTool = enforcer.handle({
                toolCall: {
                    name: 'call_mcp_tool',
                    args: {
                        ServerName: 'test-server',
                        ToolName: 'call_mcp_tool',
                        Arguments: {},
                    },
                },
            });
            const p1 = JSON.parse(resNestedTool.stdout);
            assert.strictEqual(p1.decision, 'deny');
            assert.ok(p1.reason.includes('nested_call_mcp_tool'));

            // Nested call_mcp_tool hidden inside Arguments
            const resNestedArgs = enforcer.handle({
                toolCall: {
                    name: 'call_mcp_tool',
                    args: {
                        ServerName: 'test-server',
                        ToolName: 'read',
                        Arguments: {
                            nested: {
                                ServerName: 'test-server',
                                ToolName: 'exec',
                            },
                        },
                    },
                },
            });
            const p2 = JSON.parse(resNestedArgs.stdout);
            assert.strictEqual(p2.decision, 'deny');
            assert.ok(p2.reason.includes('nested_call_mcp_tool'));
        });

        it('denies homoglyph tool name in agy format', () => {
            const enforcer = createCliEnforcer(harness, {
                format: 'agy',
                agentId: 'operator-agent',
                mode: 'enforce',
            });

            const res = enforcer.handle({
                toolCall: {
                    name: 'read\u2066test',
                    args: {},
                },
            });
            const parsed = JSON.parse(res.stdout);
            assert.strictEqual(parsed.decision, 'deny');
            assert.ok(parsed.reason.includes('tool_name_suspicious'));
        });

        it('audit mode: allows denied tool, decision: allow, onDecision called with wouldBlock: true', () => {
            let loggedRecord = null;
            const enforcer = createCliEnforcer(harness, {
                format: 'agy',
                agentId: 'reader-agent',
                mode: 'audit',
                onDecision: (r) => { loggedRecord = r; },
            });

            const res = enforcer.handle({
                toolCall: {
                    name: 'exec',
                    args: { command: 'reboot' },
                },
            });

            assert.strictEqual(res.exitCode, 0);
            assert.strictEqual(JSON.parse(res.stdout).decision, 'allow');
            assert.ok(loggedRecord);
            assert.strictEqual(loggedRecord.allow, true);
            assert.strictEqual(loggedRecord.wouldBlock, true);
            assert.strictEqual(loggedRecord.mode, 'audit');
        });
    });

    it('fail-closed on unknown CLI format: deny in enforce mode', () => {
        const enforcer = createCliEnforcer(harness, {
            format: 'unsupported-format',
            agentId: 'operator-agent',
            mode: 'enforce',
        });

        const res = enforcer.handle({ tool_name: 'read' });
        assert.strictEqual(res.exitCode, 2);
        assert.ok(res.stderr.includes('enforcer_error: Unknown CLI enforcer format'));
    });
});

describe('Enforcers: API Hook (createToolCallHook)', () => {
    let harness;

    before(() => {
        harness = createHarness({
            roles: rolesFile,
            assignments: assignmentsFile,
            toolNames: toolNamesFile,
        });
    });

    it('enforce mode: returns undefined for allowed tool call', () => {
        const hook = createToolCallHook(harness, { mode: 'enforce' });
        const event = { toolName: 'read', params: { path: '/tmp/test.txt' } };
        const ctx = { agentId: 'operator-agent' };

        const res = hook(event, ctx);
        assert.strictEqual(res, undefined);
    });

    it('enforce mode: returns { block: true, blockReason } for denied tool call', () => {
        const hook = createToolCallHook(harness, { mode: 'enforce' });
        const event = { toolName: 'exec', params: { command: 'whoami' } };
        const ctx = { agentId: 'reader-agent' };

        const res = hook(event, ctx);
        assert.deepStrictEqual(res.block, true);
        assert.ok(res.blockReason.includes('tool_not_allowed') || res.blockReason.includes('exec_disabled'));
    });

    it('audit mode: returns undefined for denied tool call and logs wouldBlock: true', () => {
        let loggedRecord = null;
        const hook = createToolCallHook(harness, {
            mode: 'audit',
            onDecision: (r) => { loggedRecord = r; },
        });
        const event = { toolName: 'exec', params: { command: 'whoami' } };
        const ctx = { agentId: 'reader-agent' };

        const res = hook(event, ctx);
        assert.strictEqual(res, undefined);
        assert.ok(loggedRecord);
        assert.strictEqual(loggedRecord.allow, true);
        assert.strictEqual(loggedRecord.wouldBlock, true);
        assert.strictEqual(loggedRecord.mode, 'audit');
    });

    it('missing agentId: blocks in enforce mode, returns undefined in audit mode', () => {
        const hookEnforce = createToolCallHook(harness, { mode: 'enforce' });
        const resEnforce = hookEnforce({ toolName: 'read', params: {} }, {});
        assert.deepStrictEqual(resEnforce.block, true);
        assert.ok(resEnforce.blockReason.includes('no_agent'));

        let loggedAudit = null;
        const hookAudit = createToolCallHook(harness, {
            mode: 'audit',
            onDecision: (r) => { loggedAudit = r; },
        });
        const resAudit = hookAudit({ toolName: 'read', params: {} }, {});
        assert.strictEqual(resAudit, undefined);
        assert.ok(loggedAudit);
        assert.strictEqual(loggedAudit.allow, true);
        assert.strictEqual(loggedAudit.wouldBlock, true);
    });

    it('never rewrites or mutates event.params', () => {
        const hook = createToolCallHook(harness, { mode: 'enforce' });
        const originalParams = { path: '/tmp/test.txt', nested: { a: 1, b: [1, 2] } };
        const clone = JSON.parse(JSON.stringify(originalParams));
        const event = { toolName: 'read', params: originalParams };
        const ctx = { agentId: 'operator-agent' };

        hook(event, ctx);
        assert.deepStrictEqual(event.params, clone);
    });

    it('swallows onDecision exception without failing or altering decision', () => {
        const hook = createToolCallHook(harness, {
            mode: 'enforce',
            onDecision: () => {
                throw new Error('Metrics sink failed');
            },
        });

        const res = hook({ toolName: 'read', params: {} }, { agentId: 'operator-agent' });
        assert.strictEqual(res, undefined);
    });

    it('custom toolNameMap maps toolName before evaluation', () => {
        const hook = createToolCallHook(harness, {
            mode: 'enforce',
            toolNameMap: (ev) => `mapped_${ev.toolName}`,
        });

        const res = hook({ toolName: 'read' }, { agentId: 'operator-agent' });
        // mapped_read is not allowed for operator-agent
        assert.deepStrictEqual(res.block, true);
        assert.ok(res.blockReason.includes('tool_not_allowed'));
    });
});

describe('CLI Bin: agent-harness-hook.js spawned CLI tests', () => {
    let tmpDir;

    before(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'harness-bin-test-'));
    });

    after(() => {
        if (tmpDir && fs.existsSync(tmpDir)) {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    });

    function runHookSync(input, args = [], env = {}) {
        return spawnSync(process.execPath, [binPath, ...args], {
            input,
            encoding: 'utf8',
            env: {
                ...process.env,
                AGENT_HARNESS_ROLES_FILE: rolesFile,
                AGENT_HARNESS_ASSIGNMENTS_FILE: assignmentsFile,
                AGENT_HARNESS_TOOL_NAMES_FILE: toolNamesFile,
                ...env,
            },
        });
    }

    describe('claude-code format CLI invocation', () => {
        it('allow: exit 0, empty stdout and stderr', () => {
            const input = JSON.stringify({
                tool_name: 'read',
                tool_input: { path: '/tmp/test.txt' },
            });
            const res = runHookSync(input, ['--format', 'claude-code', '--agent', 'operator-agent']);
            assert.strictEqual(res.status, 0);
            assert.strictEqual(res.stdout, '');
            assert.strictEqual(res.stderr, '');
        });

        it('deny: exit 2, stderr with reason', () => {
            const input = JSON.stringify({
                tool_name: 'exec',
                tool_input: { command: 'uptime' },
            });
            const res = runHookSync(input, ['--format', 'claude-code', '--agent', 'reader-agent']);
            assert.strictEqual(res.status, 2);
            assert.ok(res.stderr.includes('tool_not_allowed') || res.stderr.includes('exec_disabled'));
        });

        it('malformed input: exit 2', () => {
            const res = runHookSync('{ not valid json', ['--format', 'claude-code', '--agent', 'operator-agent']);
            assert.strictEqual(res.status, 2);
            assert.ok(res.stderr.includes('enforcer_error'));
        });

        it('oversize (> 1 MiB): exit 2', () => {
            const bigInput = 'a'.repeat(1024 * 1024 + 10);
            const res = runHookSync(bigInput, ['--format', 'claude-code', '--agent', 'operator-agent']);
            assert.strictEqual(res.status, 2);
            assert.ok(res.stderr.includes('size cap exceeded'));
        });

        it('timeout (> timeout cap): exit 2', () => {
            // Using small timeout via --timeout flag to verify timeout handler
            const proc = spawn(process.execPath, [binPath, '--format', 'claude-code', '--agent', 'operator-agent', '--timeout', '60'], {
                env: {
                    ...process.env,
                    AGENT_HARNESS_ROLES_FILE: rolesFile,
                    AGENT_HARNESS_ASSIGNMENTS_FILE: assignmentsFile,
                    AGENT_HARNESS_TOOL_NAMES_FILE: toolNamesFile,
                },
                stdio: ['pipe', 'pipe', 'pipe'],
            });

            let stderrData = '';
            proc.stderr.on('data', (d) => { stderrData += d.toString('utf8'); });

            // Do not send EOF on stdin to trigger timeout
            return new Promise((resolve, reject) => {
                proc.on('close', (code) => {
                    try {
                        assert.strictEqual(code, 2);
                        assert.ok(stderrData.includes('timeout exceeded'));
                        resolve();
                    } catch (e) {
                        reject(e);
                    }
                });
            });
        });

        it('audit mode: exit 0, logs record with mode 0600', () => {
            const auditLogFile = path.join(tmpDir, 'audit-claude.jsonl');
            const input = JSON.stringify({
                tool_name: 'exec',
                tool_input: { command: 'hostname', secret: 'audit-secret-val-99' },
            });
            const res = runHookSync(input, [
                '--format', 'claude-code',
                '--agent', 'reader-agent',
                '--mode', 'audit',
                '--audit-log', auditLogFile,
            ]);

            assert.strictEqual(res.status, 0);
            assert.strictEqual(res.stdout, '');
            assert.strictEqual(res.stderr, '');

            assert.ok(fs.existsSync(auditLogFile));
            const stat = fs.statSync(auditLogFile);
            assert.strictEqual(stat.mode & 0o777, 0o600);

            const content = fs.readFileSync(auditLogFile, 'utf8').trim();
            const record = JSON.parse(content);
            assert.strictEqual(record.allow, true);
            assert.strictEqual(record.wouldBlock, true);
            assert.strictEqual(record.mode, 'audit');
            assert.strictEqual(record.toolName, 'exec');
            assert.strictEqual(record.agentId, 'reader-agent');
            // Ensure secret value is not logged in record
            assert.strictEqual(content.includes('audit-secret-val-99'), false);
        });
    });

    describe('agy format CLI invocation', () => {
        it('allow: exit 0, stdout {"decision":"allow"}', () => {
            const input = JSON.stringify({
                toolCall: {
                    name: 'read',
                    args: { path: '/tmp/test.txt' },
                },
            });
            const res = runHookSync(input, ['--format', 'agy', '--agent', 'operator-agent']);
            assert.strictEqual(res.status, 0);
            const parsed = JSON.parse(res.stdout);
            assert.strictEqual(parsed.decision, 'allow');
        });

        it('deny: exit 0, stdout {"decision":"deny","reason":...}', () => {
            const input = JSON.stringify({
                toolCall: {
                    name: 'exec',
                    args: { command: 'poweroff' },
                },
            });
            const res = runHookSync(input, ['--format', 'agy', '--agent', 'reader-agent']);
            assert.strictEqual(res.status, 0);
            const parsed = JSON.parse(res.stdout);
            assert.strictEqual(parsed.decision, 'deny');
            assert.ok(parsed.reason);
        });

        it('malformed input: exit 0, stdout {"decision":"deny",...}', () => {
            const res = runHookSync('not valid json', ['--format', 'agy', '--agent', 'operator-agent']);
            assert.strictEqual(res.status, 0);
            const parsed = JSON.parse(res.stdout);
            assert.strictEqual(parsed.decision, 'deny');
            assert.ok(parsed.reason.includes('enforcer_error'));
        });

        it('oversize (> 1 MiB): exit 0, stdout {"decision":"deny",...}', () => {
            const bigInput = 'b'.repeat(1024 * 1024 + 10);
            const res = runHookSync(bigInput, ['--format', 'agy', '--agent', 'operator-agent']);
            assert.strictEqual(res.status, 0);
            const parsed = JSON.parse(res.stdout);
            assert.strictEqual(parsed.decision, 'deny');
            assert.ok(parsed.reason.includes('size cap exceeded'));
        });

        it('timeout: exit 0, stdout {"decision":"deny",...}', () => {
            const proc = spawn(process.execPath, [binPath, '--format', 'agy', '--agent', 'operator-agent', '--timeout', '60'], {
                env: {
                    ...process.env,
                    AGENT_HARNESS_ROLES_FILE: rolesFile,
                    AGENT_HARNESS_ASSIGNMENTS_FILE: assignmentsFile,
                    AGENT_HARNESS_TOOL_NAMES_FILE: toolNamesFile,
                },
                stdio: ['pipe', 'pipe', 'pipe'],
            });

            let stdoutData = '';
            proc.stdout.on('data', (d) => { stdoutData += d.toString('utf8'); });

            return new Promise((resolve, reject) => {
                proc.on('close', (code) => {
                    try {
                        assert.strictEqual(code, 0);
                        const parsed = JSON.parse(stdoutData);
                        assert.strictEqual(parsed.decision, 'deny');
                        assert.ok(parsed.reason.includes('timeout exceeded'));
                        resolve();
                    } catch (e) {
                        reject(e);
                    }
                });
            });
        });

        it('audit mode: exit 0, stdout {"decision":"allow"}, audit log written', () => {
            const auditLogFile = path.join(tmpDir, 'audit-agy.jsonl');
            const input = JSON.stringify({
                toolCall: {
                    name: 'exec',
                    args: { command: 'shutdown -r now' },
                },
            });
            const res = runHookSync(input, [
                '--format', 'agy',
                '--agent', 'reader-agent',
                '--mode', 'audit',
                '--audit-log', auditLogFile,
            ]);

            assert.strictEqual(res.status, 0);
            const parsed = JSON.parse(res.stdout);
            assert.strictEqual(parsed.decision, 'allow');

            assert.ok(fs.existsSync(auditLogFile));
            const record = JSON.parse(fs.readFileSync(auditLogFile, 'utf8').trim());
            assert.strictEqual(record.allow, true);
            assert.strictEqual(record.wouldBlock, true);
            assert.strictEqual(record.mode, 'audit');
            assert.strictEqual(record.toolName, 'exec');
            assert.strictEqual(record.agentId, 'reader-agent');
        });
    });
});
