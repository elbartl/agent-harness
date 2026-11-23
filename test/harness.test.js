'use strict';

const { test, describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const {
    createHarness,
    decide,
    resolveRole,
    resolveAgent,
    normalizeForMatch,
    deepInspectParams,
} = require('../src/index');

const haDomainGuard = require('../examples/home-assistant/ha-domain-guard');

const fixturesDir = path.join(__dirname, 'fixtures');
const rolesFile = path.join(fixturesDir, 'roles.json');
const assignmentsFile = path.join(fixturesDir, 'assignments.json');
const toolNamesFile = path.join(fixturesDir, 'tool-names.json');

describe('agent-harness core test suite', () => {

    describe('Fail-closed & missing configurations', () => {
        it('returns allow:false when harness created without roles or assignments', () => {
            const emptyHarness = createHarness({});
            const res = emptyHarness.decide({
                agentId: 'any-agent',
                toolName: 'exec',
                params: { command: 'ls' },
            });
            assert.strictEqual(res.allow, false);
            assert.ok(res.reason);
        });

        it('returns role:none for unknown agent outside assignments', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const role = harness.resolveRole('unknown-ghost-agent');
            assert.strictEqual(role, 'none');

            const agent = harness.resolveAgent('unknown-ghost-agent');
            assert.deepStrictEqual(agent, {
                role: 'none',
                adapter: null,
                adapterConfig: null,
            });

            const res = harness.decide({
                agentId: 'unknown-ghost-agent',
                toolName: 'read',
                params: { path: '/tmp/test.txt' },
            });
            assert.strictEqual(res.allow, false);
            assert.strictEqual(res.role, 'none');
            assert.ok(res.reason.includes('tool_not_allowed'));
        });
    });

    describe('Home Assistant plugin vs Core without plugin', () => {
        it('core without HA plugin does NOT block homeassistant.restart if allowed by role', () => {
            const harnessWithoutHa = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [],
            });

            const res = harnessWithoutHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: {
                    domain: 'homeassistant',
                    service: 'restart',
                },
            });

            assert.strictEqual(res.allow, true);
            assert.strictEqual(res.reason, 'OK');
            assert.strictEqual(res.role, 'operator');
        });

        it('harness with HA plugin BLOCKS homeassistant.restart with descriptive reason', () => {
            const harnessWithHa = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const res = harnessWithHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: {
                    domain: 'homeassistant',
                    service: 'restart',
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.includes('homeassistant.restart'));
        });

        it('harness with HA plugin BLOCKS hassio domain services with ha_domain_blocked:hassio', () => {
            const harnessWithHa = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const res = harnessWithHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: {
                    domain: 'hassio',
                    service: 'addon_stop',
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.includes('ha_domain_blocked:hassio'));
        });

        it('harness with HA plugin allows restart for role with allowHaRestart: true', () => {
            const harnessWithHa = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const res = harnessWithHa.decide({
                agentId: 'admin-agent',
                toolName: 'ha:call_service',
                params: {
                    domain: 'homeassistant',
                    service: 'restart',
                },
            });

            assert.strictEqual(res.allow, true);
            assert.strictEqual(res.reason, 'OK');
        });
    });

    describe('Homoglyphs and Unicode security', () => {
        it('blocks homeassistant restart disguised with Cyrillic e (U+0435)', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const cyrillicRestart = 'r\u0435start'; // U+0435 is Cyrillic small ie
            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: {
                    domain: 'homeassistant',
                    service: cyrillicRestart,
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.includes('homeassistant.restart'));
        });

        it('catches disallowPattern .ssh when disguised with Cyrillic dze (U+0455)', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const cyrillicSshPath = '.\\u0455sh/id_rsa'; // U+0455 is Cyrillic small dze 'ѕ'
            const actualPath = '.\u0455sh/id_rsa';

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'read',
                params: {
                    path: actualPath,
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.includes('disallow_pattern_matched'));
        });

        it('rejects bidi override character U+202E in toolName', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const bidiToolName = 'read\u202Etxt';
            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: bidiToolName,
                params: { path: '/tmp/test.txt' },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.includes('tool_name_suspicious'));
        });

        it('rejects bidi override character U+202E in path parameter', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const bidiPath = '/var/log/\u202Eevil.sh';
            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'read',
                params: { path: bidiPath },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.includes('path_suspicious'));
        });

        it('normalizeForMatch does not mutate input params (deepEqual check)', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const inputParams = {
                domain: 'homeassistant',
                service: 'light_turn_on',
                target: {
                    entity_id: 'light.living_room',
                    nested: {
                        color: 'blu\u0435', // Cyrillic e
                    },
                },
                tags: ['alpha', 'b\u0435ta'],
            };

            const paramsCopy = JSON.parse(JSON.stringify(inputParams));

            harness.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: inputParams,
            });

            assert.deepStrictEqual(inputParams, paramsCopy);
        });
    });

    describe('Assignments adapter metadata & format handling', () => {
        it('supports string role format in assignments with null adapter', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const role = harness.resolveRole('operator-agent');
            assert.strictEqual(role, 'operator');

            const agent = harness.resolveAgent('operator-agent');
            assert.deepStrictEqual(agent, {
                role: 'operator',
                adapter: null,
                adapterConfig: null,
            });
        });

        it('supports object role format in assignments with adapter and adapterConfig', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const role = harness.resolveRole('adapter-agent');
            assert.strictEqual(role, 'operator');

            const agent = harness.resolveAgent('adapter-agent');
            assert.deepStrictEqual(agent, {
                role: 'operator',
                adapter: 'test-adapter',
                adapterConfig: {
                    timeoutMs: 5000,
                },
            });
        });

        it('falls back to none for unsupported entry types (number, array)', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            assert.strictEqual(harness.resolveRole('invalid-agent-number'), 'none');
            assert.deepStrictEqual(harness.resolveAgent('invalid-agent-number'), {
                role: 'none',
                adapter: null,
                adapterConfig: null,
            });

            assert.strictEqual(harness.resolveRole('invalid-agent-array'), 'none');
            assert.deepStrictEqual(harness.resolveAgent('invalid-agent-array'), {
                role: 'none',
                adapter: null,
                adapterConfig: null,
            });
        });
    });

    describe('Messages customization', () => {
        it('replaces reason text while preserving standard error code prefix', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                messages: {
                    tool_not_allowed: 'Custom denied tool: {tool}',
                },
            });

            const res = harness.decide({
                agentId: 'reader-agent',
                toolName: 'write',
                params: { path: '/tmp/test.txt', content: 'test' },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.startsWith('tool_not_allowed: Custom denied tool: write'));
        });
    });

    describe('Deep inspection and nesting limits', () => {
        it('blocks params exceeding maximum depth limit of 8', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            // Construct 10 levels deep object
            let deepObj = { leaf: 'value' };
            for (let i = 0; i < 10; i++) {
                deepObj = { nested: deepObj };
            }

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'write',
                params: deepObj,
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.includes('params_depth_exceeded'));
        });

        it('blocks params exceeding maximum node count limit of 2000', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const wideObj = {};
            for (let i = 0; i < 2500; i++) {
                wideObj[`key_${i}`] = i;
            }

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'write',
                params: wideObj,
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.includes('params_nodes_exceeded'));
        });

        it('blocks nested call_mcp_tool inside Arguments', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'call_mcp_tool',
                params: {
                    ServerName: 'test-server',
                    ToolName: 'read',
                    Arguments: {
                        path: '/tmp/test.txt',
                        nested: {
                            ServerName: 'test-server',
                            ToolName: 'exec',
                        },
                    },
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.includes('nested_call_mcp_tool'));
        });
    });
});
