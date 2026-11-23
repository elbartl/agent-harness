#!/usr/bin/env node
'use strict';

const { parseCommonArgs, createAuditLogger, loadHarnessFromOpts } = require('../src/enforcers/bin-common');
const { createCliEnforcer } = require('../src/enforcers/cli');

function parseArgs(argv) {
    const { opts } = parseCommonArgs(argv, { format: null });
    return opts;
}

function main() {
    const opts = parseArgs(process.argv);
    const onDecision = createAuditLogger(opts.auditLog);

    let harness;
    try {
        harness = loadHarnessFromOpts(opts);
    } catch (err) {
        harness = null;
    }

    const enforcer = createCliEnforcer(harness, {
        format: opts.format,
        agentId: opts.agent,
        mode: opts.mode,
        onDecision,
    });

    function exitDeny(reason) {
        const isAudit = opts.mode === 'audit';
        if (typeof onDecision === 'function') {
            try {
                onDecision({
                    ts: Date.now(),
                    agentId: opts.agent || null,
                    toolName: null,
                    allow: isAudit,
                    reason,
                    mode: opts.mode,
                    enforcer: `cli:${opts.format || 'unknown'}`,
                    wouldBlock: true,
                    paramsSha256: null,
                    paramsBytes: 0,
                });
            } catch (_) {}
        }

        if (isAudit) {
            if (opts.format === 'agy') {
                process.stdout.write(JSON.stringify({ decision: 'allow' }) + '\n');
            }
            process.exit(0);
        }

        if (opts.format === 'agy') {
            process.stdout.write(JSON.stringify({ decision: 'deny', reason }) + '\n');
            process.exit(0);
        } else {
            process.stderr.write(reason + '\n');
            process.exit(2);
        }
    }

    const MAX_BYTES = 1024 * 1024; // 1 MiB
    let totalBytes = 0;
    const chunks = [];
    let handled = false;

    const timer = setTimeout(() => {
        if (handled) return;
        handled = true;
        process.stdin.destroy();
        exitDeny('enforcer_error: stdin read timeout exceeded (5s cap)');
    }, opts.timeoutMs || 5000);

    process.stdin.on('data', (chunk) => {
        if (handled) return;
        totalBytes += chunk.length;
        if (totalBytes > MAX_BYTES) {
            handled = true;
            clearTimeout(timer);
            process.stdin.destroy();
            exitDeny('enforcer_error: stdin size cap exceeded (max 1 MiB)');
            return;
        }
        chunks.push(chunk);
    });

    process.stdin.on('end', () => {
        if (handled) return;
        handled = true;
        clearTimeout(timer);
        const raw = Buffer.concat(chunks).toString('utf8');
        const result = enforcer.handle(raw);
        if (result.stdout) {
            process.stdout.write(result.stdout.endsWith('\n') ? result.stdout : result.stdout + '\n');
        }
        if (result.stderr) {
            process.stderr.write(result.stderr.endsWith('\n') ? result.stderr : result.stderr + '\n');
        }
        process.exit(result.exitCode);
    });

    process.stdin.on('error', (err) => {
        if (handled) return;
        handled = true;
        clearTimeout(timer);
        exitDeny(`enforcer_error: stdin read error: ${err.message}`);
    });
}

if (require.main === module) {
    main();
}

module.exports = { parseArgs };
