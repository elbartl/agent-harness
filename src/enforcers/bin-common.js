'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createHarness } = require('../core/decide');

function parseCommonArgs(argv, extraDefaults = {}) {
    const opts = {
        agent: process.env.AGENT_HARNESS_AGENT_ID || null,
        mode: process.env.AGENT_HARNESS_MODE || 'enforce',
        roles: process.env.AGENT_HARNESS_ROLES_FILE || null,
        assignments: process.env.AGENT_HARNESS_ASSIGNMENTS_FILE || null,
        toolNames: process.env.AGENT_HARNESS_TOOL_NAMES_FILE || null,
        guards: [],
        auditLog: null,
        timeoutMs: process.env.AGENT_HARNESS_TIMEOUT_MS ? parseInt(process.env.AGENT_HARNESS_TIMEOUT_MS, 10) : 5000,
        ...extraDefaults,
    };

    let i = 2;
    for (; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === '--') {
            i++;
            break;
        }
        if (arg === '--agent' && i + 1 < argv.length) {
            opts.agent = argv[++i];
        } else if (arg.startsWith('--agent=')) {
            opts.agent = arg.slice(8);
        } else if (arg === '--server' && i + 1 < argv.length) {
            opts.server = argv[++i];
        } else if (arg.startsWith('--server=')) {
            opts.server = arg.slice(9);
        } else if (arg === '--format' && i + 1 < argv.length) {
            opts.format = argv[++i];
        } else if (arg.startsWith('--format=')) {
            opts.format = arg.slice(9);
        } else if (arg === '--mode' && i + 1 < argv.length) {
            opts.mode = argv[++i];
        } else if (arg.startsWith('--mode=')) {
            opts.mode = arg.slice(7);
        } else if (arg === '--roles' && i + 1 < argv.length) {
            opts.roles = argv[++i];
        } else if (arg.startsWith('--roles=')) {
            opts.roles = arg.slice(8);
        } else if (arg === '--assignments' && i + 1 < argv.length) {
            opts.assignments = argv[++i];
        } else if (arg.startsWith('--assignments=')) {
            opts.assignments = arg.slice(14);
        } else if (arg === '--tool-names' && i + 1 < argv.length) {
            opts.toolNames = argv[++i];
        } else if (arg.startsWith('--tool-names=')) {
            opts.toolNames = arg.slice(13);
        } else if (arg === '--guard' && i + 1 < argv.length) {
            opts.guards.push(argv[++i]);
        } else if (arg.startsWith('--guard=')) {
            opts.guards.push(arg.slice(8));
        } else if (arg === '--audit-log' && i + 1 < argv.length) {
            opts.auditLog = argv[++i];
        } else if (arg.startsWith('--audit-log=')) {
            opts.auditLog = arg.slice(12);
        } else if (arg === '--timeout' && i + 1 < argv.length) {
            opts.timeoutMs = parseInt(argv[++i], 10);
        } else if (arg.startsWith('--timeout=')) {
            opts.timeoutMs = parseInt(arg.slice(10), 10);
        }
    }

    const restArgs = argv.slice(i);
    return { opts, restArgs };
}

function createAuditLogger(auditLogPath) {
    if (!auditLogPath) return null;
    const resolvedPath = path.resolve(process.cwd(), auditLogPath);
    return function onDecision(record) {
        try {
            const line = JSON.stringify(record) + '\n';
            fs.appendFileSync(resolvedPath, line, { mode: 0o600, flag: 'a' });
            try {
                fs.chmodSync(resolvedPath, 0o600);
            } catch (_) {}
        } catch (_) {}
    };
}

function loadHarnessFromOpts(opts) {
    const domainGuards = [];
    if (Array.isArray(opts.guards)) {
        for (const gPath of opts.guards) {
            const resolved = path.resolve(process.cwd(), gPath);
            const mod = require(resolved);
            domainGuards.push(mod.default || mod);
        }
    }

    return createHarness({
        roles: opts.roles ? path.resolve(process.cwd(), opts.roles) : undefined,
        assignments: opts.assignments ? path.resolve(process.cwd(), opts.assignments) : undefined,
        toolNames: opts.toolNames ? path.resolve(process.cwd(), opts.toolNames) : undefined,
        domainGuards,
    });
}

module.exports = {
    parseCommonArgs,
    createAuditLogger,
    loadHarnessFromOpts,
};
