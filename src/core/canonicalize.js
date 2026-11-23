'use strict';

const { hasBidiChars, hasInvisibleChars } = require('./normalize');
const { formatMessage } = require('./messages');

function isSuspiciousName(str) {
    if (!str || typeof str !== 'string') return true;
    if (str.startsWith('__') || str.endsWith('__') || str.includes('___')) return true;
    return !/^[A-Za-z0-9_.:-]+$/.test(str);
}

function normalizeServerName(srv, serverAliases = {}) {
    if (!srv || typeof srv !== 'string') return '';
    const s = srv.toLowerCase().trim().replace(/_/g, '-');
    if (serverAliases && Object.prototype.hasOwnProperty.call(serverAliases, s)) {
        return serverAliases[s];
    }
    return s;
}

function canonicalize(providedServer, toolName, toolTable = {}, options = {}) {
    const messages = options.messages || {};
    const domainGuards = options.domainGuards || [];

    // Collect serverAliases and custom prefixes from domainGuards and toolTable
    const serverAliases = { ...(toolTable.serverAliases || {}) };
    const customPrefixes = [...(toolTable.prefixes || [])];

    for (const g of domainGuards) {
        if (g.serverAliases && typeof g.serverAliases === 'object') {
            Object.assign(serverAliases, g.serverAliases);
        }
        if (Array.isArray(g.prefixes)) {
            customPrefixes.push(...g.prefixes);
        }
    }

    if (!toolName || typeof toolName !== 'string') {
        return {
            ok: false,
            code: 'tool_name_invalid',
            error: formatMessage('tool_name_invalid', {}, messages),
        };
    }

    if (hasBidiChars(toolName)) {
        return {
            ok: false,
            code: 'tool_name_suspicious',
            error: formatMessage('tool_name_suspicious', { name: 'toolName contains bidi control characters' }, messages),
        };
    }

    if (hasInvisibleChars(toolName)) {
        return {
            ok: false,
            code: 'tool_name_suspicious',
            error: formatMessage('tool_name_suspicious', { name: 'toolName contains invisible characters' }, messages),
        };
    }

    const trimmedTool = toolName.trim();
    if (!trimmedTool) {
        return {
            ok: false,
            code: 'tool_name_invalid',
            error: formatMessage('tool_name_invalid', {}, messages),
        };
    }

    if (trimmedTool.includes('../') || trimmedTool.includes('/..')) {
        return {
            ok: false,
            code: 'path_traversal',
            error: formatMessage('path_traversal', {}, messages),
        };
    }

    let curServer = null;
    if (providedServer !== null && providedServer !== undefined) {
        if (typeof providedServer !== 'string') {
            return {
                ok: false,
                code: 'server_name_invalid',
                error: formatMessage('server_name_invalid', {}, messages),
            };
        }
        if (hasBidiChars(providedServer)) {
            return {
                ok: false,
                code: 'tool_name_suspicious',
                error: formatMessage('tool_name_suspicious', { name: 'ServerName contains bidi control characters' }, messages),
            };
        }
        if (hasInvisibleChars(providedServer)) {
            return {
                ok: false,
                code: 'tool_name_suspicious',
                error: formatMessage('tool_name_suspicious', { name: 'ServerName contains invisible characters' }, messages),
            };
        }
        const sTrim = providedServer.trim();
        if (!sTrim) {
            return {
                ok: false,
                code: 'server_name_invalid',
                error: formatMessage('server_name_invalid', {}, messages),
            };
        }
        if (sTrim.includes('../') || sTrim.includes('/..')) {
            return {
                ok: false,
                code: 'path_traversal',
                error: formatMessage('path_traversal', {}, messages),
            };
        }
        if (isSuspiciousName(sTrim)) {
            return {
                ok: false,
                code: 'tool_name_suspicious',
                error: formatMessage('tool_name_suspicious', { name: sTrim }, messages),
            };
        }
        curServer = sTrim;
    }

    if (trimmedTool.startsWith('__') || trimmedTool.endsWith('__') || trimmedTool.includes('___')) {
        return {
            ok: false,
            code: 'tool_name_invalid',
            error: formatMessage('mcp_tool_name_invalid', { tool: trimmedTool }, messages),
        };
    }

    let curTool = trimmedTool;
    let iterations = 0;

    while (true) {
        let matched = false;
        let prefixServer = null;
        let nextTool = null;

        // 1. Check custom prefixes from domainGuards or toolTable (e.g. "ha:")
        for (const p of customPrefixes) {
            const prefixColon = `${p}:`;
            if (curTool.startsWith(prefixColon)) {
                matched = true;
                prefixServer = p;
                nextTool = curTool.slice(prefixColon.length);
                break;
            }
        }

        // 2. Generic MCP prefixes
        if (!matched) {
            if (curTool.startsWith('mcp:')) {
                matched = true;
                const rem = curTool.slice(4);
                const idx = rem.indexOf(':');
                if (idx !== -1) {
                    prefixServer = rem.slice(0, idx);
                    nextTool = rem.slice(idx + 1);
                } else {
                    prefixServer = rem;
                    nextTool = '';
                }
            } else if (curTool.startsWith('mcp__')) {
                matched = true;
                const rem = curTool.slice(5);
                const idx = rem.indexOf('__');
                if (idx !== -1) {
                    prefixServer = rem.slice(0, idx);
                    nextTool = rem.slice(idx + 2);
                } else {
                    prefixServer = rem;
                    nextTool = '';
                }
            } else if (curTool.includes('__')) {
                matched = true;
                const idx = curTool.indexOf('__');
                prefixServer = curTool.slice(0, idx);
                nextTool = curTool.slice(idx + 2);
            }
        }

        if (!matched) break;

        iterations++;
        if (iterations > 5) {
            return {
                ok: false,
                code: 'too_many_iterations',
                error: formatMessage('too_many_iterations', {}, messages),
            };
        }

        if (prefixServer === '' || (prefixServer && isSuspiciousName(prefixServer))) {
            return {
                ok: false,
                code: 'server_name_invalid',
                error: formatMessage('server_prefix_invalid', { prefixServer }, messages),
            };
        }

        if (curServer !== null) {
            const srv1 = normalizeServerName(curServer, serverAliases);
            const srv2 = normalizeServerName(prefixServer, serverAliases);
            if (srv1 !== srv2) {
                return {
                    ok: false,
                    code: 'server_mismatch',
                    error: formatMessage('server_mismatch', { prefixServer, curServer }, messages),
                };
            }
        }

        curServer = prefixServer;
        curTool = nextTool;
    }

    if (curTool === '') {
        let canonicalServerOnly = '';
        if (curServer) {
            let handled = false;
            for (const g of domainGuards) {
                if (typeof g.matchServer === 'function' && g.matchServer(curServer)) {
                    canonicalServerOnly = `${g.canonicalServer || curServer}:*`;
                    handled = true;
                    break;
                }
            }
            if (!handled) {
                const srvNorm = normalizeServerName(curServer, serverAliases);
                canonicalServerOnly = `mcp:${srvNorm || curServer}:*`;
            }
        }
        return { ok: true, server: curServer, tool: '', canonical: canonicalServerOnly };
    }

    if (isSuspiciousName(curTool)) {
        return {
            ok: false,
            code: 'tool_name_suspicious',
            error: formatMessage('tool_name_suspicious', { name: curTool }, messages),
        };
    }

    let canonical = curTool;
    let effectiveServer = curServer;

    if (effectiveServer !== null) {
        let guardCanonical = false;
        for (const g of domainGuards) {
            if (typeof g.matchServer === 'function' && g.matchServer(effectiveServer)) {
                if (typeof g.formatCanonical === 'function') {
                    canonical = g.formatCanonical(effectiveServer, curTool);
                    effectiveServer = g.effectiveServerName || effectiveServer;
                } else {
                    const prefix = g.canonicalPrefix || (g.canonicalServer ? `${g.canonicalServer}:` : 'mcp:');
                    effectiveServer = g.effectiveServerName || effectiveServer;
                    canonical = `${prefix}${curTool}`;
                }
                guardCanonical = true;
                break;
            }
        }

        if (!guardCanonical) {
            canonical = `mcp:${effectiveServer}:${curTool}`;
        }
    } else {
        let guardHandled = false;
        for (const g of domainGuards) {
            if (typeof g.resolveToolCanonical === 'function') {
                const res = g.resolveToolCanonical(curTool);
                if (res) {
                    effectiveServer = res.server;
                    canonical = res.canonical;
                    guardHandled = true;
                    break;
                }
            }
        }

        if (!guardHandled) {
            const t = toolTable || {};
            if (t.tools && Object.prototype.hasOwnProperty.call(t.tools, curTool) && t.tools[curTool].canonical) {
                canonical = t.tools[curTool].canonical;
            } else if (t.tools) {
                const lower = curTool.toLowerCase();
                for (const [k, v] of Object.entries(t.tools)) {
                    if (k.toLowerCase() === lower && v && v.canonical) {
                        canonical = v.canonical;
                        break;
                    }
                }
            }

            if (canonical.startsWith('mcp:')) {
                effectiveServer = canonical.slice(4).split(':')[0];
            } else {
                for (const g of domainGuards) {
                    if (g.prefixes && Array.isArray(g.prefixes)) {
                        for (const p of g.prefixes) {
                            if (canonical.startsWith(`${p}:`)) {
                                effectiveServer = g.effectiveServerName || p;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    return { ok: true, server: effectiveServer, tool: curTool, canonical };
}

function canonicalTool(name, toolTable, options = {}) {
    if (!name || typeof name !== 'string') return '';
    const res = canonicalize(null, name, toolTable, options);
    return res.ok ? res.canonical : name.trim();
}

module.exports = {
    isSuspiciousName,
    normalizeServerName,
    canonicalize,
    canonicalTool,
};
