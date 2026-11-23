'use strict';

const path = require('node:path');
const { normalizeForMatch, hasBidiChars, hasInvisibleChars } = require('./normalize');
const { formatMessage } = require('./messages');
const { canonicalize, canonicalTool } = require('./canonicalize');
const { deepInspectParams, hasNestedMcpCall } = require('./deepInspectParams');
const {
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
} = require('./loaders');

const PATH_KEYS = ['path', 'file_path', 'file', 'filePath', 'notebook_path', 'filepath', 'filename'];

function isMcpToolName(name) {
    if (!name || typeof name !== 'string') return false;
    return name.startsWith('mcp__') || name.includes('__') || name.startsWith('mcp:');
}

function getToolCategory(name, toolTable = {}, options = {}) {
    if (!name || typeof name !== 'string') return 'unknown';
    const trimmed = name.trim();
    const t = toolTable || {};
    const domainGuards = options.domainGuards || [];

    if (t.tools && Object.prototype.hasOwnProperty.call(t.tools, trimmed) && t.tools[trimmed].category) {
        return t.tools[trimmed].category;
    }

    if (!isMcpToolName(trimmed) && t.tools) {
        const lowerTrimmed = trimmed.toLowerCase();
        for (const [k, v] of Object.entries(t.tools)) {
            if (k.toLowerCase() === lowerTrimmed && v && v.category) return v.category;
        }
    }

    const canonRes = canonicalize(null, trimmed, toolTable, options);
    const canon = canonRes.ok ? canonRes.canonical : trimmed;

    if (t.tools && Object.prototype.hasOwnProperty.call(t.tools, canon) && t.tools[canon].category) {
        return t.tools[canon].category;
    }

    for (const g of domainGuards) {
        if (typeof g.getToolCategory === 'function') {
            const cat = g.getToolCategory(trimmed, canon, toolTable);
            if (cat) return cat;
        }
    }

    const lowerCanon = canon.toLowerCase();
    if (lowerCanon.startsWith('openclaw:')) {
        const bare = lowerCanon.slice('openclaw:'.length);
        if (['gateway', 'plugins', 'message', 'cron'].includes(bare)) return bare;
        return 'openclaw';
    }

    if (canon.startsWith('mcp:')) {
        const parts = canon.slice(4).split(':');
        const srv = parts[0] || '';
        const toolPart = (parts[1] || '').toLowerCase();
        if (toolPart.includes('exec') || toolPart.includes('command') || toolPart.includes('shell')) return 'exec';
        if (toolPart.includes('read') || toolPart.includes('tree') || toolPart.includes('grep') || toolPart.includes('diff')) return 'read';
        if (toolPart.includes('write') || toolPart.includes('edit')) return 'write';
        return `mcp:${srv}`;
    }

    const lower = trimmed.toLowerCase();
    if (['exec', 'process', 'bash'].includes(lower) || lower.includes('exec')) return 'exec';
    if (['write', 'edit', 'apply_patch', 'notebookedit', 'notebook_edit'].includes(lower)) return 'write';
    if (['read', 'glob', 'grep'].includes(lower)) return 'read';
    if (['web_fetch', 'webfetch', 'web_search', 'websearch'].includes(lower)) return 'web';
    if (['gateway', 'plugins', 'message', 'cron'].includes(lower)) return lower;
    if (['sessions_spawn', 'sessions_send'].includes(lower)) return 'openclaw';

    return 'unknown';
}

function isExecTool(name, toolTable = {}, options = {}) {
    if (getToolCategory(name, toolTable, options) === 'exec') return true;
    const canon = canonicalTool(name, toolTable, options).toLowerCase();
    return canon === 'exec' || canon === 'process' || canon === 'bash' || canon.endsWith(':dev_exec') || canon.endsWith(':host_exec');
}

function isWriteTool(name, toolTable = {}, options = {}) {
    if (getToolCategory(name, toolTable, options) === 'write') return true;
    const canon = canonicalTool(name, toolTable, options).toLowerCase();
    return canon === 'write' || canon === 'edit' || canon === 'apply_patch' || canon === 'notebook_edit' || canon === 'notebookedit';
}

function isReadTool(name, toolTable = {}, options = {}) {
    if (getToolCategory(name, toolTable, options) === 'read') return true;
    const canon = canonicalTool(name, toolTable, options).toLowerCase();
    return canon === 'read' || canon === 'glob' || canon === 'grep' ||
        canon.endsWith(':code_read') || canon.endsWith(':code_tree') ||
        canon.endsWith(':code_diff') || canon.endsWith(':code_grep');
}

function isCategoryOpenclaw(normTool, canonTool, toolTable = {}, options = {}) {
    if (normTool.toLowerCase().startsWith('openclaw:') || canonTool.toLowerCase().startsWith('openclaw:')) return true;
    const cat = getToolCategory(normTool, toolTable, options);
    return ['openclaw', 'gateway', 'plugins', 'message', 'cron'].includes(cat);
}

function matchTool(toolName, entry, toolTable = {}, options = {}) {
    if (!toolName || !entry) return false;
    if (entry === '*') return true;
    const rawTool = toolName.trim();
    const rawEntry = entry.trim();
    if (rawTool === rawEntry) return true;

    const domainGuards = options.domainGuards || [];
    for (const g of domainGuards) {
        if (typeof g.matchTool === 'function') {
            const m = g.matchTool(rawTool, rawEntry, toolTable);
            if (m) return true;
        }
    }

    const toolIsMcp = isMcpToolName(rawTool);
    const entryIsMcp = isMcpToolName(rawEntry);

    if (!toolIsMcp && !entryIsMcp) {
        if (rawTool.toLowerCase() === rawEntry.toLowerCase()) return true;
        const canonTool = canonicalTool(rawTool, toolTable, options).toLowerCase();
        const canonEntry = canonicalTool(rawEntry, toolTable, options).toLowerCase();
        if (canonTool === canonEntry || canonTool === rawEntry.toLowerCase() || rawTool.toLowerCase() === canonEntry) return true;
    }

    const canonTool = canonicalTool(rawTool, toolTable, options);
    const canonEntry = canonicalTool(rawEntry, toolTable, options);
    if (canonTool === canonEntry || canonTool === rawEntry || rawTool === canonEntry) return true;

    if (canonEntry.endsWith('*') && canonTool.startsWith(canonEntry.slice(0, -1))) return true;
    if (rawEntry.endsWith('*') && (rawTool.startsWith(rawEntry.slice(0, -1)) || canonTool.startsWith(rawEntry.slice(0, -1)))) return true;

    if (rawEntry.startsWith('mcp__') && !rawEntry.slice(5).includes('__')) {
        const srv = rawEntry.slice(5);
        const srvNorm = srv.replace(/_/g, '-');
        if (rawTool.startsWith(`mcp__${srv}__`) || rawTool.startsWith(`${srv}__`)) return true;
        if (canonTool.startsWith('mcp:')) {
            const toolSrv = canonTool.slice(4).split(':')[0];
            if (toolSrv.replace(/_/g, '-') === srvNorm) return true;
        }
    }

    if (canonEntry.startsWith('mcp:') && canonTool.startsWith('mcp:')) {
        const entryParts = canonEntry.slice(4).split(':');
        const toolParts = canonTool.slice(4).split(':');
        if (entryParts.length >= 1 && toolParts.length >= 2) {
            if (entryParts[0].replace(/_/g, '-') === toolParts[0].replace(/_/g, '-')) {
                if (entryParts[1] === '*' || entryParts[1] === toolParts[1]) return true;
            }
        }
    }

    return false;
}

function matchesDisallowPattern(toolName, params, pattern, toolTable = {}, options = {}) {
    if (!pattern) return false;
    const rawTool = toolName.trim();
    const canonTool = canonicalTool(rawTool, toolTable, options);

    if (rawTool === pattern || canonTool === pattern) return true;
    if (pattern.endsWith('(*)')) {
        const base = pattern.slice(0, -3).trim();
        if (rawTool === base || canonTool === base || rawTool.startsWith(base)) return true;
    }

    let fileGlob = null;
    const m = pattern.match(/^([A-Za-z0-9_]+)\((.+)\)$/);
    if (m) {
        const baseTool = m[1].toLowerCase();
        if (rawTool.toLowerCase() === baseTool || canonTool.toLowerCase() === baseTool) {
            fileGlob = m[2];
        }
    } else if (pattern.startsWith('**/') || pattern.includes('/') || pattern.includes('*')) {
        fileGlob = pattern;
    }

    if (fileGlob) {
        if (!params || typeof params !== 'object') return false;
        const candidatePaths = [];

        for (const k of PATH_KEYS) {
            if (typeof params[k] === 'string' && params[k].trim()) candidatePaths.push(params[k].trim());
        }

        for (const rawPath of candidatePaths) {
            const normalized = path.posix.normalize(rawPath.replace(/\\/g, '/'));
            const segments = normalized.split('/').filter(Boolean);
            const filename = segments.length > 0 ? segments[segments.length - 1] : normalized;

            const normSegments = segments.map(s => normalizeForMatch(s));
            const normFilename = normalizeForMatch(filename);

            if (fileGlob === '**/secrets.yaml' && (filename === 'secrets.yaml' || normFilename === 'secrets.yaml')) return true;
            if (fileGlob === '**/.env' && (filename === '.env' || normFilename === '.env')) return true;
            if (fileGlob === '**/.env.*' && (filename.startsWith('.env.') || normFilename.startsWith('.env.'))) return true;
            if (fileGlob === '**/*.pem' && (filename.endsWith('.pem') || normFilename.endsWith('.pem'))) return true;
            if (fileGlob === '**/*.key' && (filename.endsWith('.key') || normFilename.endsWith('.key'))) return true;
            if ((fileGlob === '**/.ssh/**' || fileGlob === '**/.ssh/*') && (segments.includes('.ssh') || filename === '.ssh' || normSegments.includes('.ssh') || normFilename === '.ssh')) return true;
            if (fileGlob.includes('.ssh') && (segments.includes('.ssh') || filename === '.ssh' || normSegments.includes('.ssh') || normFilename === '.ssh')) return true;
        }
    }

    return false;
}

function getEffectiveTools(role, opts = {}) {
    const rolesData = loadRoles(opts);
    if (!rolesData.roles || !Object.prototype.hasOwnProperty.call(rolesData.roles, role)) {
        throw new Error(`Unknown role: ${role}`);
    }
    const roleDef = rolesData.roles[role];

    const allowed = Array.isArray(roleDef.allow) ? [...roleDef.allow] : [];
    const allowFilePath = resolveRoleFile(role, 'allowFile', roleDef, opts);
    if (allowFilePath) allowed.push(...loadListFile(allowFilePath, 'allow_file', opts));

    if (roleDef.openclaw && Array.isArray(roleDef.openclaw.allow)) {
        for (const oc of roleDef.openclaw.allow) allowed.push(oc === '*' ? 'openclaw:*' : `openclaw:${oc}`);
    }

    const denied = Array.isArray(roleDef.deny) ? [...roleDef.deny] : [];
    const denyFilePath = resolveRoleFile(role, 'denyFile', roleDef, opts);
    if (denyFilePath) denied.push(...loadListFile(denyFilePath, 'deny_file', opts));

    return {
        role,
        requiresGrant: Boolean(roleDef.requiresGrant),
        fallbackRole: roleDef.fallbackRole || null,
        exec: roleDef.exec || 'none',
        files: roleDef.files || 'sandbox',
        categories: Array.isArray(roleDef.categories) ? roleDef.categories : [],
        mcpServers: Array.isArray(roleDef.mcpServers) ? roleDef.mcpServers : [],
        allowed,
        denied,
        disallowPatterns: Array.isArray(roleDef.disallowPatterns) ? [...roleDef.disallowPatterns] : [],
        openclaw: roleDef.openclaw || { allow: [] },
    };
}

function decide(request, opts = {}, harnessConfig = {}) {
    let role = null;
    const mergedOpts = { ...harnessConfig, ...opts };
    const messages = mergedOpts.messages || {};
    const domainGuards = Array.isArray(mergedOpts.domainGuards) ? mergedOpts.domainGuards : [];

    try {
        if (!request || typeof request !== 'object') {
            return {
                allow: false,
                reason: formatMessage('request_invalid', {}, messages),
                role: null,
                exec: 'none',
                guards: [],
            };
        }

        const { toolName, agentId } = request;

        if (!agentId || typeof agentId !== 'string' || !agentId.trim()) {
            return {
                allow: false,
                reason: formatMessage('no_agent', {}, messages),
                role: null,
                exec: 'none',
                guards: [],
            };
        }

        let normalizedParams = request.params;
        if (typeof normalizedParams === 'string') {
            try {
                normalizedParams = JSON.parse(normalizedParams);
            } catch (_) {
                return {
                    allow: false,
                    reason: formatMessage('params_invalid', {}, messages),
                    role: null,
                    exec: 'none',
                    guards: [],
                };
            }
        }

        if (!toolName || typeof toolName !== 'string') {
            return {
                allow: false,
                reason: formatMessage('tool_name_invalid', {}, messages),
                role: null,
                exec: 'none',
                guards: [],
            };
        }

        if (hasBidiChars(toolName)) {
            return {
                allow: false,
                reason: formatMessage('tool_name_suspicious', { name: 'toolName contains bidi characters' }, messages),
                role: null,
                exec: 'none',
                guards: [],
            };
        }

        if (hasInvisibleChars(toolName)) {
            return {
                allow: false,
                reason: formatMessage('tool_name_suspicious', { name: 'Tool name contains forbidden invisible characters' }, messages),
                role: null,
                exec: 'none',
                guards: [],
            };
        }

        const trimmedTool = toolName.trim();
        if (!trimmedTool) {
            return {
                allow: false,
                reason: formatMessage('tool_name_invalid', {}, messages),
                role: null,
                exec: 'none',
                guards: [],
            };
        }

        if (trimmedTool.includes('../') || trimmedTool.includes('/..')) {
            return {
                allow: false,
                reason: formatMessage('path_traversal', {}, messages),
                role: null,
                exec: 'none',
                guards: [],
            };
        }

        // Bidi check on path keys in params
        if (normalizedParams && typeof normalizedParams === 'object') {
            for (const pk of PATH_KEYS) {
                if (typeof normalizedParams[pk] === 'string' && hasBidiChars(normalizedParams[pk])) {
                    return {
                        allow: false,
                        reason: formatMessage('path_suspicious', {}, messages),
                        role: null,
                        exec: 'none',
                        guards: [],
                    };
                }
            }
        }

        const calculatedRole = resolveRole(agentId.trim(), mergedOpts);
        if (!calculatedRole || typeof calculatedRole !== 'string') {
            return {
                allow: false,
                reason: formatMessage('role_resolution_failed', {}, messages),
                role: null,
                exec: 'none',
                guards: [],
            };
        }

        if (request.role !== undefined && request.role !== null) {
            if (typeof request.role !== 'string' || request.role.trim() !== calculatedRole) {
                return {
                    allow: false,
                    reason: formatMessage('role_mismatch', {}, messages),
                    role: calculatedRole,
                    exec: 'none',
                    guards: [],
                };
            }
        }

        role = calculatedRole;

        const toolTable = loadToolNames(mergedOpts);
        const rolesData = loadRoles(mergedOpts);
        if (!rolesData.roles || !Object.prototype.hasOwnProperty.call(rolesData.roles, role)) {
            return {
                allow: false,
                reason: formatMessage('unknown_role', { role }, messages),
                role,
                exec: 'none',
                guards: [],
            };
        }

        const effRole = resolveEffectiveRole(role, rolesData, mergedOpts);
        if (!effRole.ok) {
            return {
                allow: false,
                reason: effRole.error,
                role,
                exec: 'none',
                guards: [],
            };
        }

        role = effRole.role;
        const roleDef = effRole.roleDef;
        const roleExec = roleDef.exec || 'none';
        const roleFiles = roleDef.files || 'sandbox';

        let normTool = trimmedTool;
        let effectiveParams = normalizedParams;
        let effectiveServer = null;
        let effectiveToolName = trimmedTool;

        const canonOpts = { ...mergedOpts, domainGuards, messages };

        if (trimmedTool === 'call_mcp_tool') {
            if (!normalizedParams || typeof normalizedParams !== 'object' || Array.isArray(normalizedParams)) {
                return {
                    allow: false,
                    reason: formatMessage('params_invalid', {}, messages),
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }

            const { ServerName, ToolName } = normalizedParams;
            if (!ServerName || typeof ServerName !== 'string' || !ServerName.trim() ||
                !ToolName || typeof ToolName !== 'string' || !ToolName.trim()) {
                return {
                    allow: false,
                    reason: formatMessage('call_mcp_missing_target', {}, messages),
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }

            const trimmedServer = ServerName.trim();
            const trimmedSubTool = ToolName.trim();
            if (trimmedSubTool === 'call_mcp_tool') {
                return {
                    allow: false,
                    reason: formatMessage('nested_call_mcp_tool', {}, messages),
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }

            let innerArgs = normalizedParams.Arguments;
            if (typeof innerArgs === 'string') {
                try {
                    innerArgs = JSON.parse(innerArgs);
                } catch (_) {
                    return {
                        allow: false,
                        reason: formatMessage('params_invalid', {}, messages),
                        role,
                        exec: roleExec,
                        guards: [],
                    };
                }
            }

            const hasNestedInParams = Object.entries(normalizedParams).some(([k, v]) => {
                if (k === 'ServerName' || k === 'ToolName' || k === 'Arguments') return false;
                return k === 'toolName' || k === 'serverName' || hasNestedMcpCall(v);
            });
            if (hasNestedInParams || hasNestedMcpCall(innerArgs)) {
                return {
                    allow: false,
                    reason: formatMessage('nested_call_mcp_tool', {}, messages),
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }

            const canonRes = canonicalize(trimmedServer, trimmedSubTool, toolTable, canonOpts);
            if (!canonRes.ok) {
                return {
                    allow: false,
                    reason: canonRes.error,
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }

            normTool = canonRes.canonical;
            effectiveServer = canonRes.server;
            effectiveToolName = canonRes.tool;
            effectiveParams = innerArgs;
        } else {
            const canonRes = canonicalize(null, trimmedTool, toolTable, canonOpts);
            if (!canonRes.ok) {
                return {
                    allow: false,
                    reason: canonRes.error,
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }
            normTool = canonRes.canonical;
            effectiveServer = canonRes.server;
            effectiveToolName = canonRes.tool;
        }

        if (normTool.endsWith(':*') || normTool === 'openclaw:*') {
            return {
                allow: false,
                reason: formatMessage('tool_name_server_only', { tool: trimmedTool }, messages),
                role,
                exec: 'none',
                guards: [],
            };
        }

        const toolIsExec = isExecTool(normTool, toolTable, canonOpts);
        if (toolIsExec && roleExec === 'none') {
            return {
                allow: false,
                reason: formatMessage('exec_disabled', { tool: trimmedTool, role }, messages),
                role,
                exec: 'none',
                guards: [],
            };
        }

        // Domain guards: tool-level inspection
        for (const guard of domainGuards) {
            if (typeof guard.inspectTool === 'function') {
                const tRes = guard.inspectTool(normTool, effectiveToolName, effectiveParams, roleDef, {
                    toolTable,
                    messages,
                    role,
                    effectiveServer,
                });
                if (tRes && tRes.blocked) {
                    return {
                        allow: false,
                        reason: tRes.reason,
                        role,
                        exec: roleExec,
                        guards: [],
                    };
                }
            }
        }

        // Deep parameter inspection (nested objects, JSON strings, domain guards)
        const paramsToCheck = (effectiveParams !== normalizedParams) ? [effectiveParams, normalizedParams] : [effectiveParams];
        for (const p of paramsToCheck) {
            if (p !== undefined && p !== null) {
                const pRes = deepInspectParams(p, {
                    domainGuards,
                    toolTable,
                    messages,
                    ctx: { role, roleDef, toolName: normTool, effectiveToolName, effectiveServer },
                });
                if (pRes && pRes.blocked) {
                    return {
                        allow: false,
                        reason: pRes.reason,
                        role,
                        exec: roleExec,
                        guards: [],
                    };
                }
            }
        }

        // Verify MCP servers access
        let isMcp = normTool.startsWith('mcp:');
        let mcpServer = null;
        if (isMcp) {
            mcpServer = effectiveServer || (normTool.startsWith('mcp:') ? normTool.slice(4).split(':')[0] : null);
        } else {
            for (const g of domainGuards) {
                if (typeof g.matchServer === 'function' && ((effectiveServer && g.matchServer(effectiveServer)) || (Array.isArray(g.prefixes) && g.prefixes.some(p => normTool.startsWith(`${p}:`))))) {
                    isMcp = true;
                    mcpServer = g.effectiveServerName || effectiveServer || g.canonicalServer;
                    break;
                }
            }
        }

        if (isMcp) {
            const roleMcpServers = Array.isArray(roleDef.mcpServers) ? roleDef.mcpServers : null;
            if (!roleMcpServers) {
                return {
                    allow: false,
                    reason: formatMessage('mcp_server_not_configured', { role }, messages),
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }

            if (!roleMcpServers.includes('*')) {
                if (!mcpServer) {
                    return {
                        allow: false,
                        reason: formatMessage('mcp_server_unknown', { tool: trimmedTool }, messages),
                        role,
                        exec: roleExec,
                        guards: [],
                    };
                }
                const normTarget = mcpServer.replace(/_/g, '-');
                const isServerAllowed = roleMcpServers.some(s => {
                    if (s === mcpServer || s.replace(/_/g, '-') === normTarget) return true;
                    for (const g of domainGuards) {
                        if (typeof g.matchServer === 'function' && g.matchServer(mcpServer) && g.matchServer(s)) {
                            return true;
                        }
                    }
                    return false;
                });
                if (!isServerAllowed) {
                    return {
                        allow: false,
                        reason: formatMessage('mcp_server_forbidden', { server: mcpServer, role }, messages),
                        role,
                        exec: roleExec,
                        guards: [],
                    };
                }
            }
        }

        const effTools = getEffectiveTools(role, mergedOpts);
        const allowedTools = effTools.allowed;
        const deniedTools = effTools.denied;

        const canonToolForOc = canonicalTool(normTool, toolTable, canonOpts);
        const toolIsOpenclaw = isCategoryOpenclaw(normTool, canonToolForOc, toolTable, canonOpts);
        if (toolIsOpenclaw) {
            const ocAllow = roleDef.openclaw && Array.isArray(roleDef.openclaw.allow) ? roleDef.openclaw.allow : [];
            const subName = normTool.startsWith('openclaw:')
                ? normTool.slice('openclaw:'.length)
                : (canonToolForOc.startsWith('openclaw:') ? canonToolForOc.slice('openclaw:'.length) : trimmedTool.toLowerCase());

            const isOcAllowed = ocAllow.includes('*') || ocAllow.includes(subName) || ocAllow.includes(trimmedTool.toLowerCase());
            if (!isOcAllowed) {
                return {
                    allow: false,
                    reason: formatMessage('platform_tool_forbidden', { tool: trimmedTool, role }, messages),
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }
        }

        for (const d of deniedTools) {
            if (matchTool(normTool, d, toolTable, canonOpts)) {
                return {
                    allow: false,
                    reason: formatMessage('tool_denied', { tool: trimmedTool, role }, messages),
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }
        }

        const disallowPatterns = Array.isArray(roleDef.disallowPatterns) ? roleDef.disallowPatterns : [];
        for (const pat of disallowPatterns) {
            if (matchesDisallowPattern(normTool, effectiveParams, pat, toolTable, canonOpts)) {
                return {
                    allow: false,
                    reason: formatMessage('disallow_pattern_matched', { tool: trimmedTool, role }, messages),
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }
        }

        if (!allowedTools.includes('*')) {
            let isAllowed = false;
            if (toolIsOpenclaw) {
                isAllowed = true;
            } else {
                for (const a of allowedTools) {
                    if (matchTool(normTool, a, toolTable, canonOpts)) {
                        isAllowed = true;
                        break;
                    }
                }
            }
            if (!isAllowed) {
                return {
                    allow: false,
                    reason: formatMessage('tool_not_allowed', { tool: trimmedTool, role }, messages),
                    role,
                    exec: roleExec,
                    guards: [],
                };
            }
        }

        const guards = [];
        if (toolIsExec && roleExec === 'sandbox') guards.push('sandbox_shell');
        if (isWriteTool(normTool, toolTable, canonOpts) && roleFiles !== 'unrestricted') guards.push('write_guard');
        if (isReadTool(normTool, toolTable, canonOpts) && roleFiles !== 'unrestricted') guards.push('read_guard');

        for (const g of domainGuards) {
            if (typeof g.getGuards === 'function') {
                const extraGuards = g.getGuards(normTool, effectiveToolName, roleDef, {
                    toolTable,
                    role,
                    matchTool: (t, e) => matchTool(t, e, toolTable, canonOpts),
                });
                if (Array.isArray(extraGuards)) {
                    guards.push(...extraGuards);
                }
            }
        }

        return {
            allow: true,
            reason: 'OK',
            role,
            exec: roleExec,
            guards: [...new Set(guards)],
        };
    } catch (err) {
        return {
            allow: false,
            reason: formatMessage('internal_error', { error: err.message }, messages),
            role: typeof role === 'string' ? role : null,
            exec: 'none',
            guards: [],
        };
    }
}

function createHarness(config = {}) {
    const harness = {
        roles: config.roles,
        assignments: config.assignments,
        toolNames: config.toolNames,
        domainGuards: Array.isArray(config.domainGuards) ? config.domainGuards : [],
        messages: config.messages || {},
        grantFile: config.grantFile,
        env: config.env || process.env,

        decide(request, callOpts = {}) {
            return decide(request, { ...config, ...callOpts }, harness);
        },

        resolveRole(agentId, callOpts = {}) {
            return resolveRole(agentId, { ...config, ...callOpts });
        },

        resolveAgent(agentId, callOpts = {}) {
            return resolveAgent(agentId, { ...config, ...callOpts });
        },
    };
    return harness;
}

module.exports = {
    decide,
    createHarness,
    getEffectiveTools,
    resolveRole,
    resolveAgent,
    fullGrantValid,
    canonicalTool,
    canonicalize,
    getToolCategory,
    loadRoles,
    loadAssignments,
    loadToolNames,
    isExecTool,
    isWriteTool,
    isReadTool,
    matchTool,
    matchesDisallowPattern,
};
