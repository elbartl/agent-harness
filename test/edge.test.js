'use strict';

const { test, describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const {
    createHarness,
    decide,
    resolveRole,
    resolveAgent,
    normalizeForMatch,
    deepInspectParams,
    fullGrantValid,
    canonicalTool,
    canonicalize,
    getToolCategory,
    isExecTool,
    isWriteTool,
    isReadTool,
    matchTool,
    getEffectiveTools,
    loadRoles,
    loadAssignments,
    loadToolNames,
} = require('../src/index');

const haDomainGuard = require('../examples/home-assistant/ha-domain-guard');

const fixturesDir = path.join(__dirname, 'fixtures');
const rolesFile = path.join(fixturesDir, 'roles.json');
const assignmentsFile = path.join(fixturesDir, 'assignments.json');
const toolNamesFile = path.join(fixturesDir, 'tool-names.json');

describe('agent-harness edge-case & adversarial verification', () => {

    describe('1. Fail-closed behaviour', () => {
        it('fails closed when roles file path does not exist', () => {
            const harness = createHarness({
                roles: '/nonexistent/path/roles.json',
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });
            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'read',
                params: { path: '/tmp/test' },
            });
            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('internal_error'));
        });

        it('fails closed when roles file contains corrupted JSON', () => {
            const badRolesPath = path.join(os.tmpdir(), `corrupt_roles_${Date.now()}.json`);
            fs.writeFileSync(badRolesPath, '{ "roles": { "broken": ');
            try {
                const harness = createHarness({
                    roles: badRolesPath,
                    assignments: assignmentsFile,
                    toolNames: toolNamesFile,
                });
                const res = harness.decide({
                    agentId: 'operator-agent',
                    toolName: 'read',
                    params: { path: '/tmp/test' },
                });
                assert.strictEqual(res.allow, false);
                assert.ok(res.reason && res.reason.includes('internal_error'));
            } finally {
                if (fs.existsSync(badRolesPath)) fs.unlinkSync(badRolesPath);
            }
        });

        it('fails closed when assignments file contains corrupted JSON', () => {
            const badAssignPath = path.join(os.tmpdir(), `corrupt_assign_${Date.now()}.json`);
            fs.writeFileSync(badAssignPath, '{ "agents": [INVALID]');
            try {
                const harness = createHarness({
                    roles: rolesFile,
                    assignments: badAssignPath,
                    toolNames: toolNamesFile,
                });
                const res = harness.decide({
                    agentId: 'operator-agent',
                    toolName: 'read',
                    params: { path: '/tmp/test' },
                });
                assert.strictEqual(res.allow, false);
                assert.ok(res.reason && res.reason.includes('internal_error'));
            } finally {
                if (fs.existsSync(badAssignPath)) fs.unlinkSync(badAssignPath);
            }
        });

        it('fails closed when tool-names file contains corrupted JSON', () => {
            const badToolPath = path.join(os.tmpdir(), `corrupt_tools_${Date.now()}.json`);
            fs.writeFileSync(badToolPath, 'NOT_JSON');
            try {
                const harness = createHarness({
                    roles: rolesFile,
                    assignments: assignmentsFile,
                    toolNames: badToolPath,
                });
                const res = harness.decide({
                    agentId: 'operator-agent',
                    toolName: 'read',
                    params: { path: '/tmp/test' },
                });
                assert.strictEqual(res.allow, false);
                assert.ok(res.reason && res.reason.includes('internal_error'));
            } finally {
                if (fs.existsSync(badToolPath)) fs.unlinkSync(badToolPath);
            }
        });

        it('fails closed when agent is assigned an unknown role', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: {
                    default: 'none',
                    agents: {
                        'ghost-agent': 'nonexistent_super_role',
                    },
                },
                toolNames: toolNamesFile,
            });
            const res = harness.decide({
                agentId: 'ghost-agent',
                toolName: 'read',
                params: { path: '/tmp/test' },
            });
            assert.strictEqual(res.allow, false);
            assert.strictEqual(res.role, 'nonexistent_super_role');
            assert.ok(res.reason && res.reason.includes('unknown_role'));
        });

        it('fails closed for assignments with invalid value types (number, array, null, empty object)', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: {
                    default: 'none',
                    agents: {
                        'agent-num': 12345,
                        'agent-arr': ['operator'],
                        'agent-null': null,
                        'agent-empty-obj': {},
                        'agent-obj-no-role': { adapter: 'cc-proxy' },
                        'agent-obj-num-role': { role: 999 },
                    },
                },
                toolNames: toolNamesFile,
            });

            for (const id of ['agent-num', 'agent-arr', 'agent-null', 'agent-empty-obj', 'agent-obj-no-role', 'agent-obj-num-role']) {
                const role = harness.resolveRole(id);
                assert.strictEqual(role, 'none', `Expected role none for ${id}`);

                const agent = harness.resolveAgent(id);
                assert.deepStrictEqual(agent, { role: 'none', adapter: null, adapterConfig: null });

                const res = harness.decide({
                    agentId: id,
                    toolName: 'read',
                    params: { path: '/tmp/test' },
                });
                assert.strictEqual(res.allow, false);
                assert.strictEqual(res.role, 'none');
            }
        });

        it('requiresGrant role falls back to fallbackRole when grant file is missing', () => {
            const harness = createHarness({
                roles: {
                    roles: {
                        full: {
                            requiresGrant: true,
                            fallbackRole: 'reader',
                            exec: 'host',
                            allow: ['*'],
                        },
                        reader: {
                            exec: 'none',
                            allow: ['read'],
                        },
                    },
                },
                assignments: {
                    agents: {
                        'grant-agent': 'full',
                    },
                },
                grantFile: '/nonexistent/grant/file',
            });

            const role = harness.resolveRole('grant-agent');
            assert.strictEqual(role, 'reader');

            const res = harness.decide({
                agentId: 'grant-agent',
                toolName: 'exec',
                params: { command: 'ls' },
            });
            assert.strictEqual(res.allow, false);
            assert.strictEqual(res.role, 'reader');
        });

        it('requiresGrant role falls back when grant file has expired timestamp', () => {
            const grantPath = path.join(os.tmpdir(), `grant_exp_${Date.now()}`);
            fs.writeFileSync(grantPath, '1000000000'); // year 2001
            try {
                const harness = createHarness({
                    roles: {
                        roles: {
                            full: {
                                requiresGrant: true,
                                fallbackRole: 'reader',
                                exec: 'host',
                                allow: ['*'],
                            },
                            reader: {
                                exec: 'none',
                                allow: ['read'],
                            },
                        },
                    },
                    assignments: {
                        agents: {
                            'grant-agent': 'full',
                        },
                    },
                    grantFile: grantPath,
                });

                assert.strictEqual(harness.resolveRole('grant-agent'), 'reader');
            } finally {
                if (fs.existsSync(grantPath)) fs.unlinkSync(grantPath);
            }
        });

        it('requiresGrant role falls back when grant file content is malformed or non-numeric', () => {
            const grantPath = path.join(os.tmpdir(), `grant_bad_${Date.now()}`);
            fs.writeFileSync(grantPath, '9999999999evil');
            try {
                const harness = createHarness({
                    roles: {
                        roles: {
                            full: {
                                requiresGrant: true,
                                fallbackRole: 'reader',
                                exec: 'host',
                                allow: ['*'],
                            },
                            reader: {
                                exec: 'none',
                                allow: ['read'],
                            },
                        },
                    },
                    assignments: {
                        agents: {
                            'grant-agent': 'full',
                        },
                    },
                    grantFile: grantPath,
                });

                assert.strictEqual(harness.resolveRole('grant-agent'), 'reader');
            } finally {
                if (fs.existsSync(grantPath)) fs.unlinkSync(grantPath);
            }
        });

        it('requiresGrant role falls back when grant file has group/other write permissions (0o666)', () => {
            const grantPath = path.join(os.tmpdir(), `grant_perm_${Date.now()}`);
            fs.writeFileSync(grantPath, '9999999999', { mode: 0o666 });
            try {
                fs.chmodSync(grantPath, 0o666);
                const harness = createHarness({
                    roles: {
                        roles: {
                            full: {
                                requiresGrant: true,
                                fallbackRole: 'reader',
                                exec: 'host',
                                allow: ['*'],
                            },
                            reader: {
                                exec: 'none',
                                allow: ['read'],
                            },
                        },
                    },
                    assignments: {
                        agents: {
                            'grant-agent': 'full',
                        },
                    },
                    grantFile: grantPath,
                });

                assert.strictEqual(harness.resolveRole('grant-agent'), 'reader');
            } finally {
                if (fs.existsSync(grantPath)) fs.unlinkSync(grantPath);
            }
        });

        it('requiresGrant role fails closed when fallbackRole is missing or cyclic', () => {
            const harnessCycle = createHarness({
                roles: {
                    roles: {
                        roleA: { requiresGrant: true, fallbackRole: 'roleB' },
                        roleB: { requiresGrant: true, fallbackRole: 'roleA' },
                    },
                },
                assignments: {
                    agents: { 'cycle-agent': 'roleA' },
                },
            });
            const resCycle = harnessCycle.decide({ agentId: 'cycle-agent', toolName: 'read' });
            assert.strictEqual(resCycle.allow, false);
            assert.ok(resCycle.reason && resCycle.reason.includes('Cycle detected'));

            const harnessNoFallback = createHarness({
                roles: {
                    roles: {
                        roleSolo: { requiresGrant: true },
                    },
                },
                assignments: {
                    agents: { 'solo-agent': 'roleSolo' },
                },
            });
            const resSolo = harnessNoFallback.decide({ agentId: 'solo-agent', toolName: 'read' });
            assert.strictEqual(resSolo.allow, false);
            assert.ok(resSolo.reason && resSolo.reason.includes('Missing fallbackRole'));
        });
    });

    describe('2. Homoglyph and Unicode security', () => {
        it('blocks homeassistant restart disguised with Greek epsilon (U+03B5)', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const greekRestart = 'r\u03B5start'; // U+03B5 is Greek small letter epsilon
            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: {
                    domain: 'homeassistant',
                    service: greekRestart,
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('homeassistant.restart'));
        });

        it('blocks homeassistant stop disguised with Cyrillic o (U+043E) and p (U+0440)', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const cyrillicStop = 'st\u043E\u0440'; // U+043E is Cyrillic o, U+0440 is Cyrillic er
            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: {
                    domain: 'homeassistant',
                    service: cyrillicStop,
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('homeassistant.restart'));
        });

        it('catches disallowPattern secrets.yaml when disguised with Cyrillic e (U+0435)', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const cyrillicSecrets = 's\u0435crets.yaml'; // Cyrillic small ie
            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'read',
                params: {
                    path: `/config/${cyrillicSecrets}`,
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('disallow_pattern_matched'));
        });

        it('rejects bidi isolate character U+2066 in toolName', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'read\u2066tool',
                params: { path: '/tmp/test.txt' },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('tool_name_suspicious'));
        });

        it('rejects bidi override character U+202E in ServerName', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'call_mcp_tool',
                params: {
                    ServerName: 'test\u202Esrv',
                    ToolName: 'read',
                    Arguments: { path: '/tmp/test.txt' },
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('tool_name_suspicious'));
        });

        it('rejects bidi isolate character U+2066 in ServerName', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'call_mcp_tool',
                params: {
                    ServerName: 'test\u2066srv',
                    ToolName: 'read',
                    Arguments: { path: '/tmp/test.txt' },
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('tool_name_suspicious'));
        });

        it('rejects bidi isolate character U+2066 in path parameter', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'read',
                params: { path: '/etc/\u2066passwd' },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('path_suspicious'));
        });

        it('rejects bidi override character U+202E nested inside Arguments path', () => {
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
                        filePath: '/var/data/\u202Ebad.log',
                    },
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('path_suspicious'));
        });

        it('guarantees that input params object is never mutated by decide()', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const originalParams = {
                domain: 'homeassistant',
                service: 'light_turn_on',
                target: {
                    entity_id: 'light.corridor',
                    metadata: {
                        label: 't\u0435st', // Cyrillic e
                    },
                },
                sequence: [1, 2, 'th\u0440ee'], // Cyrillic er
            };

            const clone = JSON.parse(JSON.stringify(originalParams));

            harness.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: originalParams,
            });

            assert.deepStrictEqual(originalParams, clone);
            assert.strictEqual(originalParams.target.metadata.label, 't\u0435st');
            assert.strictEqual(originalParams.sequence[2], 'th\u0440ee');
        });

        // --- REGRESSION TESTS ---

        it('regression: ha-domain-guard fails to block domain "hаssio" containing Cyrillic homoglyph (U+0430)', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const cyrillicHassio = 'h\u0430ssio'; // Cyrillic 'а' U+0430
            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: {
                    domain: cyrillicHassio,
                    service: 'addon_start',
                },
            });

            // The hassio domain should be blocked fail-closed regardless of service name.
            // Due to missing normalizeForMatch on domain, this currently returns allow: true.
            assert.strictEqual(res.allow, false, 'Expected domain hаssio with Cyrillic homoglyph to be blocked fail-closed');
            assert.ok(res.reason && res.reason.includes('ha_domain_blocked:hassio'));
        });

        it('regression: ha-domain-guard fails to block domain "homeаssistant" restart containing Cyrillic homoglyph (U+0430)', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const cyrillicHomeAssistant = 'home\u0430ssistant'; // Cyrillic 'а' U+0430
            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: {
                    domain: cyrillicHomeAssistant,
                    service: 'restart',
                },
            });

            // homeassistant.restart should be blocked.
            // Due to missing normalizeForMatch on domain, this currently returns allow: true.
            assert.strictEqual(res.allow, false, 'Expected homeаssistant.restart with Cyrillic homoglyph to be blocked');
            assert.ok(res.reason && res.reason.includes('homeassistant.restart'));
        });

        it('regression: ha-domain-guard fails to block event_type containing Cyrillic homoglyphs', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const cyrillicEvent = 'homeassistant_r\u0435start'; // Cyrillic 'е' U+0435
            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_event',
                params: {
                    event_type: cyrillicEvent,
                },
            });

            // homeassistant_restart event must be blocked.
            // Due to missing normalizeForMatch on event_type, this currently returns allow: true.
            assert.strictEqual(res.allow, false, 'Expected homeassistant_rеstart event to be blocked');
            assert.ok(res.reason && res.reason.includes('ha_event_blocked'));
        });

        it('regression: hasInvisibleChars is stateful and fails on subsequent calls due to global /g flag', () => {
            const { hasInvisibleChars, INVISIBLE_CHARS_REGEX } = require('../src/core/normalize');

            // Reset regex lastIndex to 0 for a clean test
            INVISIBLE_CHARS_REGEX.lastIndex = 0;

            // Call 1 on a longer string containing invisible char sets lastIndex to a positive number
            const call1 = hasInvisibleChars('long_string_with_\u200B_char');
            assert.strictEqual(call1, true, 'First call with zero-width space must return true');

            // Call 2 on a short string with zero-width space:
            // Because INVISIBLE_CHARS_REGEX has /g, lastIndex is now ~18, which is > length of 'a\u200Bb' (3).
            // It searches past the end of the string and returns false!
            const call2 = hasInvisibleChars('a\u200Bb');
            assert.strictEqual(call2, true, 'Second call with short string must return true, but fails due to stateful /g flag');
        });
    });

    describe('3. deepInspectParams', () => {
        it('allows parameters at depth exactly 8 and blocks at depth 9', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            // Nest exactly 7 levels beneath root { target: ... } => depth 8
            let obj8 = 'leaf';
            for (let i = 0; i < 7; i++) {
                obj8 = { next: obj8 };
            }
            const res8 = harness.decide({
                agentId: 'operator-agent',
                toolName: 'write',
                params: { target: obj8 },
            });
            assert.strictEqual(res8.allow, true, 'Depth 8 should be allowed');

            // Nest 8 levels beneath root { target: ... } => depth 9
            let obj9 = 'leaf';
            for (let i = 0; i < 8; i++) {
                obj9 = { next: obj9 };
            }
            const res9 = harness.decide({
                agentId: 'operator-agent',
                toolName: 'write',
                params: { target: obj9 },
            });
            assert.strictEqual(res9.allow, false);
            assert.ok(res9.reason && res9.reason.includes('params_depth_exceeded'), 'Depth 9 should be blocked');
        });

        it('allows node count <= 2000 and blocks when node count > 2000', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            // 1999 keys + root object = 2000 nodes
            const okObj = {};
            for (let i = 0; i < 1999; i++) {
                okObj[`k_${i}`] = i;
            }
            const resOk = harness.decide({
                agentId: 'operator-agent',
                toolName: 'write',
                params: okObj,
            });
            assert.strictEqual(resOk.allow, true, 'Node count 2000 should be allowed');

            // 2001 keys => exceeds 2000 nodes
            const overObj = {};
            for (let i = 0; i < 2001; i++) {
                overObj[`k_${i}`] = i;
            }
            const resOver = harness.decide({
                agentId: 'operator-agent',
                toolName: 'write',
                params: overObj,
            });
            assert.strictEqual(resOver.allow, false);
            assert.ok(resOver.reason && resOver.reason.includes('params_nodes_exceeded'));
        });

        it('recursively parses JSON string inside JSON string inside JSON string', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            // 3 levels of JSON strings containing a blocked restart service
            const level3 = JSON.stringify({ domain: 'homeassistant', service: 'restart' });
            const level2 = JSON.stringify({ payload: level3 });
            const level1 = JSON.stringify({ envelope: level2 });

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: { data: level1 },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('homeassistant.restart'));
        });

        it('fails closed when parameter contains malformed JSON starting with {', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
            });

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'write',
                params: {
                    badJson: '{ "key": invalid_json_syntax }',
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('params_invalid'));
        });

        it('blocks nested call_mcp_tool inside Arguments JSON string', () => {
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
                    Arguments: JSON.stringify({
                        subAction: {
                            ServerName: 'test-server',
                            ToolName: 'exec',
                        },
                    }),
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('nested_call_mcp_tool'));
        });

        it('blocks arrays of service calls where only one element is dangerous', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const res = harness.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: {
                    calls: [
                        { domain: 'light', service: 'turn_on' },
                        { domain: 'switch', service: 'turn_off' },
                        { domain: 'climate', service: 'set_temperature' },
                        { domain: 'homeassistant', service: 'restart' }, // dangerous
                        { domain: 'media_player', service: 'pause' },
                    ],
                },
            });

            assert.strictEqual(res.allow, false);
            assert.ok(res.reason && res.reason.includes('homeassistant.restart'));
        });
    });

    describe('4. Home Assistant plugin vs Core without plugin', () => {
        it('core without HA plugin does NOT block homeassistant.stop, reload_core, or hassio', () => {
            const harnessNoHa = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [],
            });

            // homeassistant.stop
            const resStop = harnessNoHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: { domain: 'homeassistant', service: 'stop' },
            });
            assert.strictEqual(resStop.allow, true);
            assert.strictEqual(resStop.reason, 'OK');

            // homeassistant.reload_core
            const resReload = harnessNoHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: { domain: 'homeassistant', service: 'reload_core' },
            });
            assert.strictEqual(resReload.allow, true);
            assert.strictEqual(resReload.reason, 'OK');

            // hassio domain
            const resHassio = harnessNoHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: { domain: 'hassio', service: 'addon_stop' },
            });
            assert.strictEqual(resHassio.allow, true);
            assert.strictEqual(resHassio.reason, 'OK');

            // ha_call_event
            const resEvt = harnessNoHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_event',
                params: { event_type: 'homeassistant_stop' },
            });
            assert.strictEqual(resEvt.allow, true);
            assert.strictEqual(resEvt.reason, 'OK');
        });

        it('harness with HA plugin blocks homeassistant.stop, reload_core, and hassio actions', () => {
            const harnessWithHa = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const resStop = harnessWithHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: { domain: 'homeassistant', service: 'stop' },
            });
            assert.strictEqual(resStop.allow, false);
            assert.ok(resStop.reason.includes('homeassistant.restart'));

            const resReload = harnessWithHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: { domain: 'homeassistant', service: 'reload_core' },
            });
            assert.strictEqual(resReload.allow, false);
            assert.ok(resReload.reason.includes('homeassistant.restart'));

            const resHassio = harnessWithHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_service',
                params: { domain: 'hassio', service: 'host_reboot' },
            });
            assert.strictEqual(resHassio.allow, false);
            assert.ok(resHassio.reason.includes('ha_domain_blocked:hassio'));

            const resEvt = harnessWithHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:call_event',
                params: { event_type: 'homeassistant_stop' },
            });
            assert.strictEqual(resEvt.allow, false);
            assert.ok(resEvt.reason.includes('ha_event_blocked'));
        });

        it('harness with HA plugin blocks dangerous operations in ha_bulk_control', () => {
            const harnessWithHa = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const res = harnessWithHa.decide({
                agentId: 'operator-agent',
                toolName: 'ha:bulk_control',
                params: {
                    operations: JSON.stringify([
                        { domain: 'hassio', service: 'addon_restart' },
                    ]),
                },
            });
            assert.strictEqual(res.allow, false);
            assert.ok(res.reason.includes('ha_domain_blocked:hassio'));
        });

        it('bypasses HA domain guard when role has bypassDomainGuards: ["home-assistant"]', () => {
            const harness = createHarness({
                roles: {
                    roles: {
                        customOps: {
                            exec: 'sandbox',
                            allow: ['*'],
                            mcpServers: ['*'],
                            bypassDomainGuards: ['home-assistant'],
                        },
                    },
                },
                assignments: {
                    agents: { 'custom-agent': 'customOps' },
                },
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const res = harness.decide({
                agentId: 'custom-agent',
                toolName: 'ha:call_service',
                params: { domain: 'homeassistant', service: 'restart' },
            });
            assert.strictEqual(res.allow, true);
            assert.strictEqual(res.reason, 'OK');
        });

        it('correctly maps and guards server aliases ha, ha-mcp, homeassistant', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: assignmentsFile,
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            for (const srv of ['ha', 'ha-mcp', 'homeassistant']) {
                const res = harness.decide({
                    agentId: 'operator-agent',
                    toolName: 'call_mcp_tool',
                    params: {
                        ServerName: srv,
                        ToolName: 'ha_call_service',
                        Arguments: { domain: 'homeassistant', service: 'restart' },
                    },
                });
                assert.strictEqual(res.allow, false, `Expected server ${srv} to block restart`);
                assert.ok(res.reason.includes('homeassistant.restart'));
            }
        });
    });

    describe('5. Object form in assignments', () => {
        it('resolveAgent and resolveRole agree on role and resolveAgent extracts adapter metadata', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: {
                    default: 'none',
                    agents: {
                        'standard-agent': 'operator',
                        'adapter-full': {
                            role: 'operator',
                            adapter: 'cc-proxy',
                            adapterConfig: { endpoint: 'http://localhost:8080', timeout: 3000 },
                        },
                        'adapter-no-config': {
                            role: 'operator',
                            adapter: 'raw-proxy',
                        },
                        'adapter-no-adapter': {
                            role: 'operator',
                        },
                    },
                },
                toolNames: toolNamesFile,
            });

            // standard
            assert.strictEqual(harness.resolveRole('standard-agent'), 'operator');
            assert.deepStrictEqual(harness.resolveAgent('standard-agent'), {
                role: 'operator',
                adapter: null,
                adapterConfig: null,
            });

            // adapter-full
            assert.strictEqual(harness.resolveRole('adapter-full'), 'operator');
            assert.deepStrictEqual(harness.resolveAgent('adapter-full'), {
                role: 'operator',
                adapter: 'cc-proxy',
                adapterConfig: { endpoint: 'http://localhost:8080', timeout: 3000 },
            });

            // adapter-no-config
            assert.strictEqual(harness.resolveRole('adapter-no-config'), 'operator');
            assert.deepStrictEqual(harness.resolveAgent('adapter-no-config'), {
                role: 'operator',
                adapter: 'raw-proxy',
                adapterConfig: null,
            });

            // adapter-no-adapter
            assert.strictEqual(harness.resolveRole('adapter-no-adapter'), 'operator');
            assert.deepStrictEqual(harness.resolveAgent('adapter-no-adapter'), {
                role: 'operator',
                adapter: null,
                adapterConfig: null,
            });
        });

        it('adapter metadata does not alter authorization decisions', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: {
                    default: 'none',
                    agents: {
                        'plain-operator': 'operator',
                        'adapter-operator': {
                            role: 'operator',
                            adapter: 'cc-proxy',
                            adapterConfig: { strict: true },
                        },
                    },
                },
                toolNames: toolNamesFile,
                domainGuards: [haDomainGuard],
            });

            const testRequests = [
                { toolName: 'read', params: { path: '/tmp/test.txt' } },
                { toolName: 'exec', params: { command: 'ls -la' } },
                { toolName: 'ha:call_service', params: { domain: 'homeassistant', service: 'restart' } },
                { toolName: 'write', params: { path: '/root/.ssh/id_rsa' } },
                { toolName: 'nonexistent_tool', params: {} },
            ];

            for (const req of testRequests) {
                const resPlain = harness.decide({ agentId: 'plain-operator', ...req });
                const resAdapter = harness.decide({ agentId: 'adapter-operator', ...req });

                assert.strictEqual(resPlain.allow, resAdapter.allow, `allow mismatch for ${req.toolName}`);
                assert.strictEqual(resPlain.role, resAdapter.role, `role mismatch for ${req.toolName}`);
                assert.strictEqual(resPlain.exec, resAdapter.exec, `exec mismatch for ${req.toolName}`);
                assert.deepStrictEqual(resPlain.guards, resAdapter.guards, `guards mismatch for ${req.toolName}`);
            }
        });

        it('safely handles non-standard adapter and adapterConfig property types', () => {
            const harness = createHarness({
                roles: rolesFile,
                assignments: {
                    default: 'none',
                    agents: {
                        'bad-adapter-num': { role: 'operator', adapter: 12345 },
                        'bad-config-arr': { role: 'operator', adapter: 'test', adapterConfig: ['bad'] },
                        'bad-config-str': { role: 'operator', adapter: 'test', adapterConfig: 'bad' },
                    },
                },
                toolNames: toolNamesFile,
            });

            assert.deepStrictEqual(harness.resolveAgent('bad-adapter-num'), {
                role: 'operator',
                adapter: null,
                adapterConfig: null,
            });

            assert.deepStrictEqual(harness.resolveAgent('bad-config-arr'), {
                role: 'operator',
                adapter: 'test',
                adapterConfig: null,
            });

            assert.deepStrictEqual(harness.resolveAgent('bad-config-str'), {
                role: 'operator',
                adapter: 'test',
                adapterConfig: null,
            });
        });
    });
});
