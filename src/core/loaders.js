'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function expandHome(p) {
    if (typeof p !== 'string') return p;
    return (p.startsWith('~/') || p === '~') ? path.join(os.homedir(), p.slice(1)) : p;
}

function fullGrantValid(grantFilePath = null, opts = {}) {
    try {
        const file = expandHome(grantFilePath || (opts && opts.grantFile) || process.env.AGENT_HARNESS_GRANT_FILE || null);
        if (!file) return false;
        const st = fs.statSync(file);
        if (!st.isFile()) return false;
        const currentUid = typeof opts.uid === 'number' ? opts.uid : (typeof process.getuid === 'function' ? process.getuid() : 0);
        if (st.uid !== 0 && st.uid !== currentUid) return false;
        if (st.mode & 0o022) return false;
        const content = fs.readFileSync(file, 'utf8').trim();
        if (!/^\d{1,12}$/.test(content)) return false;
        const exp = parseInt(content, 10);
        const nowSec = typeof opts.now === 'number' ? opts.now : Math.floor(Date.now() / 1000);
        return Number.isFinite(exp) && exp > nowSec;
    } catch (_) {
        return false;
    }
}

function loadAssignments(opts = {}) {
    if (opts && opts.assignments && typeof opts.assignments === 'object') {
        if (!opts.assignments.agents || typeof opts.assignments.agents !== 'object') {
            throw new Error('Invalid assignments object structure: missing agents field');
        }
        return opts.assignments;
    }
    const envFile = (opts.env && opts.env.AGENT_HARNESS_ASSIGNMENTS_FILE) || process.env.AGENT_HARNESS_ASSIGNMENTS_FILE;
    const pathCandidate = (typeof opts.assignments === 'string' ? opts.assignments : null) || opts.assignmentsFile || envFile;
    const file = expandHome(pathCandidate);
    if (!file) {
        throw new Error('Missing assignments file path');
    }
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || typeof parsed.agents !== 'object') {
        throw new Error(`Invalid assignments file structure: ${file}`);
    }
    return parsed;
}

function loadRoles(opts = {}) {
    if (opts && opts.roles && typeof opts.roles === 'object') {
        if (!opts.roles.roles || typeof opts.roles.roles !== 'object') {
            throw new Error('Invalid roles object structure: missing roles field');
        }
        return opts.roles;
    }
    const envFile = (opts.env && opts.env.AGENT_HARNESS_ROLES_FILE) || process.env.AGENT_HARNESS_ROLES_FILE;
    const pathCandidate = (typeof opts.roles === 'string' ? opts.roles : null) || opts.rolesFile || envFile;
    const file = expandHome(pathCandidate);
    if (!file) {
        throw new Error('Missing roles file path');
    }
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || typeof parsed.roles !== 'object') {
        throw new Error(`Invalid roles file structure: ${file}`);
    }
    return parsed;
}

function loadToolNames(opts = {}) {
    if (opts && opts.toolNames && typeof opts.toolNames === 'object') {
        return opts.toolNames;
    }
    const envFile = (opts.env && opts.env.AGENT_HARNESS_TOOL_NAMES_FILE) || process.env.AGENT_HARNESS_TOOL_NAMES_FILE;
    const pathCandidate = (typeof opts.toolNames === 'string' ? opts.toolNames : null) || opts.toolNamesFile || envFile;
    const file = expandHome(pathCandidate);
    if (!file || !fs.existsSync(file)) return { tools: {}, mcpPrefixes: {} };
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!parsed || typeof parsed !== 'object') {
        throw new Error(`Invalid tool-names file structure: ${file}`);
    }
    return parsed;
}

function resolveRoleFile(role, fileKey, roleDef, opts = {}) {
    if (opts[fileKey]) return expandHome(opts[fileKey]);
    if (opts.files && opts.files[role] && opts.files[role][fileKey]) return expandHome(opts.files[role][fileKey]);
    const defaultPath = roleDef[fileKey];
    if (opts.files && defaultPath && opts.files[defaultPath]) return expandHome(opts.files[defaultPath]);
    const envKey = roleDef[fileKey + 'Env'];
    if (envKey && process.env[envKey]) return expandHome(process.env[envKey]);
    return defaultPath ? expandHome(defaultPath) : null;
}

function loadListFile(filePath, type = 'file', opts = {}) {
    if (!filePath) return [];
    const expanded = expandHome(filePath);

    if (opts && opts.fileContents && opts.fileContents[expanded]) {
        const val = opts.fileContents[expanded];
        if (Array.isArray(val)) return val;
        if (val && typeof val === 'object') {
            if (Array.isArray(val.allow)) return val.allow;
            if (Array.isArray(val.deny)) return val.deny;
            if (Array.isArray(val.builtin) || Array.isArray(val.mcp)) return [...(val.builtin || []), ...(val.mcp || [])];
        }
    }

    let parsed;
    try {
        parsed = JSON.parse(fs.readFileSync(expanded, 'utf8'));
    } catch (err) {
        const error = new Error(`${type}_unreadable: Cannot read file ${expanded}: ${err.message}`);
        error.code = `${type}_unreadable`;
        throw error;
    }

    if (Array.isArray(parsed)) return parsed;
    if (parsed && typeof parsed === 'object') {
        if (Array.isArray(parsed.allow)) return parsed.allow;
        if (Array.isArray(parsed.deny)) return parsed.deny;
        if (Array.isArray(parsed.builtin) || Array.isArray(parsed.mcp)) return [...(parsed.builtin || []), ...(parsed.mcp || [])];
    }

    const error = new Error(`${type}_unreadable: Missing valid array in file ${expanded}`);
    error.code = `${type}_unreadable`;
    throw error;
}

function resolveEffectiveRole(initialRole, rolesData, opts = {}) {
    let currentRole = initialRole;
    const visited = new Set();
    let hops = 0;

    while (hops <= 3) {
        if (!currentRole || typeof currentRole !== 'string') return { ok: false, error: 'Invalid role' };
        if (visited.has(currentRole)) return { ok: false, error: `Cycle detected in fallbackRole for role ${currentRole}` };
        visited.add(currentRole);

        if (!rolesData || !rolesData.roles || !Object.prototype.hasOwnProperty.call(rolesData.roles, currentRole)) {
            return { ok: false, error: `Fallback role ${currentRole} does not exist`, missingRole: currentRole };
        }

        const roleDef = rolesData.roles[currentRole];
        if (!roleDef || typeof roleDef !== 'object') return { ok: false, error: `Invalid definition for role ${currentRole}` };

        if (roleDef.requiresGrant) {
            const grantFile = opts.grantFile || process.env.AGENT_HARNESS_GRANT_FILE || null;
            if (fullGrantValid(grantFile, opts)) return { ok: true, role: currentRole, roleDef };
            const nextRole = roleDef.fallbackRole;
            if (!nextRole || typeof nextRole !== 'string') return { ok: false, error: `Missing fallbackRole for role ${currentRole} requiring grant` };
            currentRole = nextRole;
            hops++;
            continue;
        }

        return { ok: true, role: currentRole, roleDef };
    }

    return { ok: false, error: 'Exceeded limit of 3 fallbackRole resolutions' };
}

function resolveRole(agentId, opts = {}) {
    const assignments = loadAssignments(opts);
    if (!assignments || !assignments.agents || typeof agentId !== 'string') {
        return 'none';
    }

    const trimmedId = agentId.trim();
    let rawRole = 'none';

    if (Object.prototype.hasOwnProperty.call(assignments.agents, trimmedId)) {
        const entry = assignments.agents[trimmedId];
        if (typeof entry === 'string') {
            rawRole = entry;
        } else if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
            rawRole = typeof entry.role === 'string' ? entry.role : 'none';
        } else {
            rawRole = 'none';
        }
    } else {
        rawRole = typeof assignments.default === 'string' ? assignments.default : 'none';
    }

    let rolesData;
    try {
        rolesData = loadRoles(opts);
    } catch (_) {
        return rawRole;
    }

    if (!rolesData || !rolesData.roles || !Object.prototype.hasOwnProperty.call(rolesData.roles, rawRole)) {
        return rawRole;
    }

    const eff = resolveEffectiveRole(rawRole, rolesData, opts);
    return eff.ok ? eff.role : rawRole;
}

function resolveAgent(agentId, opts = {}) {
    const assignments = loadAssignments(opts);
    if (!assignments || !assignments.agents || typeof agentId !== 'string') {
        return { role: 'none', adapter: null, adapterConfig: null };
    }

    const trimmedId = agentId.trim();
    if (!Object.prototype.hasOwnProperty.call(assignments.agents, trimmedId)) {
        const role = resolveRole(trimmedId, opts);
        return { role, adapter: null, adapterConfig: null };
    }

    const entry = assignments.agents[trimmedId];
    if (typeof entry === 'string') {
        const role = resolveRole(trimmedId, opts);
        return { role, adapter: null, adapterConfig: null };
    }

    if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
        if (typeof entry.role !== 'string') {
            return { role: 'none', adapter: null, adapterConfig: null };
        }
        const role = resolveRole(trimmedId, opts);
        const adapter = typeof entry.adapter === 'string' ? entry.adapter : null;
        const adapterConfig = (entry.adapterConfig && typeof entry.adapterConfig === 'object' && !Array.isArray(entry.adapterConfig))
            ? entry.adapterConfig
            : null;
        return { role, adapter, adapterConfig };
    }

    return { role: 'none', adapter: null, adapterConfig: null };
}

module.exports = {
    expandHome,
    fullGrantValid,
    loadAssignments,
    loadRoles,
    loadToolNames,
    resolveRoleFile,
    loadListFile,
    resolveEffectiveRole,
    resolveRole,
    resolveAgent,
};
