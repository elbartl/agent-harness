'use strict';

const { hasBidiChars } = require('./normalize');
const { formatMessage } = require('./messages');

const PATH_KEYS = new Set([
    'path',
    'file_path',
    'file',
    'filePath',
    'notebook_path',
    'filepath',
    'filename',
]);

function hasNestedMcpCall(val, depth = 0) {
    if (!val || depth > 8) return false;
    if (typeof val === 'string') {
        const trimmed = val.trim();
        if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
            try {
                return hasNestedMcpCall(JSON.parse(trimmed), depth + 1);
            } catch (_) {
                return false;
            }
        }
        return false;
    }
    if (Array.isArray(val)) {
        for (const item of val) {
            if (hasNestedMcpCall(item, depth + 1)) return true;
        }
        return false;
    }
    if (typeof val === 'object') {
        for (const key of ['ServerName', 'ToolName', 'toolName', 'serverName']) {
            if (Object.prototype.hasOwnProperty.call(val, key)) return true;
        }
        for (const k of Object.keys(val)) {
            if (hasNestedMcpCall(val[k], depth + 1)) return true;
        }
    }
    return false;
}

function deepInspectParams(rootParams, options = {}) {
    let nodeCount = 0;
    const domainGuards = options.domainGuards || [];
    const toolTable = options.toolTable || {};
    const messages = options.messages || {};

    function walk(val, depth, currentCtx = {}) {
        if (depth > 8) {
            return {
                blocked: true,
                code: 'params_depth_exceeded',
                reason: formatMessage('params_depth_exceeded', {}, messages),
            };
        }
        if (val === null || val === undefined) return { blocked: false };

        nodeCount++;
        if (nodeCount > 2000) {
            return {
                blocked: true,
                code: 'params_nodes_exceeded',
                reason: formatMessage('params_nodes_exceeded', {}, messages),
            };
        }

        if (typeof val === 'string') {
            const trimmed = val.trim();
            if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
                let parsed;
                try {
                    parsed = JSON.parse(trimmed);
                } catch (_) {
                    return {
                        blocked: true,
                        code: 'params_invalid',
                        reason: formatMessage('params_invalid', {}, messages),
                    };
                }
                return walk(parsed, depth + 1, currentCtx);
            }
            return { blocked: false };
        }

        if (Array.isArray(val)) {
            for (const item of val) {
                const r = walk(item, depth + 1, currentCtx);
                if (r.blocked) return r;
            }
            return { blocked: false };
        }

        if (typeof val === 'object') {
            const rawKeys = Object.keys(val);

            // Bidi check on path-like keys
            for (const k of rawKeys) {
                if (PATH_KEYS.has(k) && typeof val[k] === 'string') {
                    if (hasBidiChars(val[k])) {
                        return {
                            blocked: true,
                            code: 'path_suspicious',
                            reason: formatMessage('path_suspicious', {}, messages),
                        };
                    }
                }
            }

            // Execute domainGuards inspection on this object node
            let nextCtx = { ...currentCtx };
            for (const guard of domainGuards) {
                if (typeof guard.inspect === 'function') {
                    const guardRes = guard.inspect(val, {
                        ...nextCtx,
                        depth,
                        toolTable,
                        messages,
                        walk: (subVal, subCtx = {}) => walk(subVal, depth + 1, { ...nextCtx, ...subCtx }),
                    });
                    if (guardRes && guardRes.blocked) {
                        return guardRes;
                    }
                    if (guardRes && guardRes.contextUpdate) {
                        nextCtx = { ...nextCtx, ...guardRes.contextUpdate };
                    }
                }
            }

            // Recurse into all object keys
            for (const k of rawKeys) {
                if (nextCtx.skipKeys && nextCtx.skipKeys.has(k)) continue;
                const r = walk(val[k], depth + 1, nextCtx);
                if (r.blocked) return r;
            }
            return { blocked: false };
        }

        return { blocked: false };
    }

    return walk(rootParams, 0, options.ctx || {});
}

module.exports = {
    hasNestedMcpCall,
    deepInspectParams,
};
