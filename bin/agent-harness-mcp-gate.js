#!/usr/bin/env node
'use strict';

const { parseCommonArgs, createAuditLogger, loadHarnessFromOpts } = require('../src/enforcers/bin-common');
const { createMcpGate } = require('../src/enforcers/mcp');

function main() {
    const { opts, restArgs } = parseCommonArgs(process.argv, {
        server: process.env.AGENT_HARNESS_SERVER_NAME || null,
    });

    const upstreamCommand = restArgs[0] || null;
    const upstreamArgs = restArgs.slice(1);

    if (!opts.server || !opts.agent || !upstreamCommand) {
        process.stderr.write(
            'Usage: agent-harness-mcp-gate --server <name> --agent <id> [options] -- <command> [args...]\n' +
            'Error: Missing required argument (--server, --agent, or upstream command after "--")\n'
        );
        process.exit(2);
    }

    const onDecision = createAuditLogger(opts.auditLog);
    let harness = null;
    let harnessError = null;

    try {
        harness = loadHarnessFromOpts(opts);
    } catch (err) {
        harnessError = err;
    }

    const isAudit = opts.mode === 'audit';
    if (harnessError !== null) {
        if (!isAudit) {
            process.stderr.write(`enforcer_error: harness load failed: ${harnessError.message}\n`);
            process.exit(1);
        } else {
            if (typeof onDecision === 'function') {
                try {
                    onDecision({
                        ts: Date.now(),
                        agentId: opts.agent || null,
                        toolName: null,
                        allow: true,
                        reason: `enforcer_error: harness load failed: ${harnessError.message}`,
                        mode: 'audit',
                        enforcer: 'mcp',
                        wouldBlock: true,
                        paramsSha256: null,
                        paramsBytes: 0,
                    });
                } catch (_) {}
            }
        }
    }

    const gate = createMcpGate({
        harness,
        agentId: opts.agent,
        serverName: opts.server,
        mode: opts.mode,
        onDecision,
        upstream: {
            command: upstreamCommand,
            args: upstreamArgs,
        },
    });

    gate.start().then((code) => {
        process.exit(code);
    });
}

if (require.main === module) {
    main();
}

module.exports = { main };
