'use strict';

const childProcess = require('node:child_process');
const os = require('node:os');
const { runDecision } = require('./common');

const MAX_LINE_BYTES = 4 * 1024 * 1024; // 4 MiB line cap

// Role-level deny codes:
// When filtering tools in tools/list responses from upstream, decide() is evaluated
// with empty params ({}).
//
// Fail-closed tools/list filtering rule:
// In enforce mode, a tool is DROPPED from tools/list if:
// 1. Tool name is missing, non-string, empty, or contains leading/trailing whitespace.
// 2. decide() throws or returns an invalid/non-object/non-boolean result.
// 3. The decision reason is missing, unparsable, or has code 'enforcer_error' or 'domain_guard_error'.
// 4. The denial reason code matches any role-level deny code in ROLE_LEVEL_DENY_CODES.
// Tools are KEPT only when decide() allows the call, or when the denial code is strictly
// parameter-dependent (e.g. param_forbidden, path_not_allowed, params_invalid).
// In audit mode, tools/list responses are never filtered.
//
// Role-level codes treated as dropping tools from tools/list:
// - no_agent: Missing or unresolvable agent ID
// - role_mismatch: Role mismatch
// - unknown_role: Agent role is unknown
// - role_resolution_failed: Role resolution failed
// - fallback_cycle / fallback_missing / fallback_invalid / fallback_no_grant / fallback_hops_exceeded: Grant fallback failures
// - tool_name_invalid: Tool name format is invalid
// - mcp_tool_name_invalid: MCP tool name format is invalid
// - server_prefix_invalid: Invalid server prefix
// - tool_name_suspicious: Tool name contains suspicious characters (bidi, invisible, homoglyphs)
// - tool_name_server_only: Tool name refers to a server rather than a tool
// - path_traversal: Path traversal attempt in tool/server name
// - server_name_invalid: Invalid server name
// - server_mismatch: Server name mismatch
// - too_many_iterations: Prefix stripping cycle
// - exec_disabled: Exec tools are forbidden for the role (exec: none)
// - mcp_server_not_configured: Role does not have MCP servers configured
// - mcp_server_unknown: MCP server unknown
// - mcp_server_forbidden: MCP server is not allowed for the role
// - platform_tool_forbidden: Platform tool forbidden for the role
// - tool_denied: Tool is explicitly blocked on the deny list for the role
// - tool_not_allowed: Tool is not on the allowed list for the role
// - disallow_pattern_matched: Disallowed by unconditional pattern
// - enforcer_error: Harness evaluation threw or returned invalid result (fail-closed)
// - domain_guard_error: Domain guard inspection failure (fail-closed)
const ROLE_LEVEL_DENY_CODES = new Set([
    'no_agent',
    'role_mismatch',
    'unknown_role',
    'role_resolution_failed',
    'fallback_cycle',
    'fallback_missing',
    'fallback_invalid',
    'fallback_no_grant',
    'fallback_hops_exceeded',
    'tool_name_invalid',
    'mcp_tool_name_invalid',
    'server_prefix_invalid',
    'tool_name_suspicious',
    'tool_name_server_only',
    'path_traversal',
    'server_name_invalid',
    'server_mismatch',
    'too_many_iterations',
    'exec_disabled',
    'mcp_server_not_configured',
    'mcp_server_unknown',
    'mcp_server_forbidden',
    'platform_tool_forbidden',
    'tool_denied',
    'tool_not_allowed',
    'disallow_pattern_matched',
    'enforcer_error',
    'domain_guard_error',
]);

function createLineSplitter({ maxBytes, onLine, onOversize }) {
    let buf = Buffer.alloc(0);
    let isOversize = false;
    let oversizePrefix = '';

    function push(chunk) {
        if (!chunk || chunk.length === 0) return;
        buf = Buffer.concat([buf, chunk]);
        while (true) {
            const newlineIdx = buf.indexOf(0x0a); // \n
            if (newlineIdx === -1) {
                if (buf.length > maxBytes) {
                    if (!isOversize) {
                        isOversize = true;
                        oversizePrefix = buf.subarray(0, 65536).toString('utf8');
                    }
                    buf = Buffer.alloc(0);
                }
                break;
            }

            const lineBuf = buf.subarray(0, newlineIdx);
            buf = buf.subarray(newlineIdx + 1);

            if (isOversize) {
                onOversize(oversizePrefix);
                isOversize = false;
                oversizePrefix = '';
            } else if (lineBuf.length > maxBytes) {
                const prefix = lineBuf.subarray(0, 65536).toString('utf8');
                onOversize(prefix);
            } else {
                let lineStr = lineBuf.toString('utf8');
                if (lineStr.endsWith('\r')) {
                    lineStr = lineStr.slice(0, -1);
                }
                if (lineStr.trim().length > 0) {
                    onLine(lineStr);
                }
            }
        }
    }

    return { push };
}

function extractIdFromPrefix(prefix) {
    if (!prefix || typeof prefix !== 'string') return undefined;
    const match = prefix.match(/"id"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|null)/);
    if (!match) return undefined;
    try {
        return JSON.parse(match[1]);
    } catch (_) {
        return undefined;
    }
}

function createMcpGate(options = {}) {
    const harness = options.harness;
    const agentId = options.agentId;
    const serverName = options.serverName;
    const mode = options.mode === 'audit' ? 'audit' : 'enforce';
    const onDecision = options.onDecision;
    const upstream = options.upstream || {};
    const input = options.stdin || options.input || process.stdin;
    const output = options.stdout || options.output || process.stdout;
    const upstreamStderr = options.stderr || options.upstream?.stderr || 'inherit';
    const onExit = typeof options.onExit === 'function' ? options.onExit : (code) => process.exit(code);
    const now = options.now;

    const isAudit = mode === 'audit';
    let passThroughOnly = false;

    let exitPromiseResolve;
    const exitPromise = new Promise((resolve) => {
        exitPromiseResolve = resolve;
    });

    let hasExited = false;
    function handleExit(code, signal) {
        if (hasExited) return;
        hasExited = true;
        if (killTimer) clearTimeout(killTimer);
        // Upstream exit: signal maps to 128 + signal number, or 1 if signal number is unavailable
        const exitCode = code !== null
            ? code
            : (signal && os.constants?.signals?.[signal]
                ? 128 + os.constants.signals[signal]
                : 1);
        exitPromiseResolve(exitCode);
        onExit(exitCode, signal);
    }

    // Validate harness, agentId, and serverName
    const hasConfigError =
        !agentId || typeof agentId !== 'string' || !agentId.trim() ||
        !serverName || typeof serverName !== 'string' || !serverName.trim() ||
        !harness || typeof harness.decide !== 'function';

    if (hasConfigError) {
        const errorDetail = !agentId
            ? 'Missing agentId'
            : (!serverName
                ? 'Missing serverName'
                : 'Invalid harness instance with decide() method');

        if (!isAudit) {
            handleExit(1, null);
            return {
                child: null,
                start: () => exitPromise,
                terminate: () => {},
            };
        } else {
            passThroughOnly = true;
            if (typeof onDecision === 'function') {
                try {
                    onDecision({
                        ts: typeof now === 'function' ? now() : (now !== undefined ? now : Date.now()),
                        agentId: typeof agentId === 'string' ? agentId : null,
                        toolName: null,
                        allow: true,
                        reason: `enforcer_error: ${errorDetail}`,
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

    if (!upstream || !upstream.command) {
        throw new Error('upstream.command is required for createMcpGate');
    }

    // Spawn upstream process with argv-style execution (never a shell)
    const child = childProcess.spawn(upstream.command, upstream.args || [], {
        shell: false,
        env: upstream.env || process.env,
        cwd: upstream.cwd || process.cwd(),
        stdio: ['pipe', 'pipe', upstreamStderr],
    });

    child.stdin.on('error', () => {});
    if (output && typeof output.on === 'function') {
        output.on('error', () => {});
    }

    let upstreamTerminated = false;
    let killTimer = null;

    function terminateUpstream() {
        if (upstreamTerminated) return;
        upstreamTerminated = true;

        try {
            child.stdin.end();
        } catch (_) {}

        try {
            child.kill('SIGTERM');
        } catch (_) {}

        const killDelay = typeof options.killTimeoutMs === 'number' ? options.killTimeoutMs : 3000;
        killTimer = setTimeout(() => {
            try {
                if (child.exitCode === null) {
                    child.kill('SIGKILL');
                }
            } catch (_) {}
        }, killDelay);
        if (killTimer.unref) killTimer.unref();
    }

    input.on('end', terminateUpstream);
    input.on('close', terminateUpstream);

    child.on('exit', (code, signal) => {
        handleExit(code, signal);
    });

    child.on('error', () => {
        handleExit(1, null);
    });

    // Tracking pending tools/list requests by JSON-RPC ID
    const pendingToolsListRequests = new Set();

    // Batch merging state:
    // Tracks pending mixed batches forwarded to upstream.
    // Each pending batch holds the expected upstream response IDs and the gate responses.
    const pendingBatches = [];

    // Helper: evaluate single request object against harness policy
    function evaluateSingleRequest(req) {
        if (!req || typeof req !== 'object' || Array.isArray(req)) {
            return { allowed: true, forward: req };
        }

        if (req.method === 'tools/list' && req.id !== undefined) {
            pendingToolsListRequests.add(req.id);
            return { allowed: true, forward: req };
        }

        if (req.method !== 'tools/call') {
            return { allowed: true, forward: req };
        }

        // Canonical tool name format: "mcp__${serverName}__${targetToolName}", which matches
        // the format used by the CLI enforcer for MCP tools and is canonicalized by
        // the harness core canonicalizer into "mcp:${serverName}:${targetToolName}".
        // Exact name matching: no trimming. Empty names, non-string names, or names with
        // leading/trailing whitespace are treated as invalid names and denied in enforce mode.
        const rawToolName = (req.params && typeof req.params.name === 'string')
            ? req.params.name
            : null;
        const toolArgs = (req.params && req.params.arguments !== undefined)
            ? req.params.arguments
            : {};

        const isValidName = typeof rawToolName === 'string' &&
            rawToolName.length > 0 &&
            rawToolName.trim() === rawToolName;

        if (!isValidName) {
            const reason = 'tool_name_invalid: Tool name is missing or invalid in tools/call';
            const dec = runDecision(
                {
                    decide: () => ({
                        allow: false,
                        reason,
                        role: null,
                        exec: 'none',
                        guards: [],
                    }),
                },
                {
                    agentId,
                    toolName: typeof rawToolName === 'string' ? `mcp__${serverName}__${rawToolName}` : null,
                    params: toolArgs,
                },
                {
                    mode,
                    onDecision,
                    now,
                    enforcer: 'mcp',
                }
            );
            if (dec.allow) {
                return { allowed: true, forward: req };
            }
            return {
                allowed: false,
                reason: dec.reason,
                id: req.id,
            };
        }

        const harnessToolName = `mcp__${serverName}__${rawToolName}`;

        const decision = runDecision(harness, {
            agentId,
            toolName: harnessToolName,
            params: toolArgs,
        }, {
            mode,
            onDecision,
            now,
            enforcer: 'mcp',
        });

        if (decision.allow) {
            return { allowed: true, forward: req };
        }

        return {
            allowed: false,
            reason: decision.reason,
            id: req.id,
        };
    }

    // Helper: filter tools/list responses from upstream
    function filterToolsListResponse(resp) {
        if (!resp || typeof resp !== 'object' || !resp.result || !Array.isArray(resp.result.tools)) {
            return resp;
        }

        if (mode === 'audit') {
            // Audit mode: do not filter tools/list
            return resp;
        }

        // Enforce mode: filter tools the role can never call.
        // We evaluate runDecision with empty params without logging an onDecision record,
        // so tools/list filtering does not flood the audit log.
        // Fail-closed tools/list filtering:
        // 1. Tool name must be a non-empty string without leading/trailing whitespace.
        // 2. decide() throwing or returning an invalid result drops the tool.
        // 3. Reason codes enforcer_error, domain_guard_error, unparsable reason, or
        //    any role-level deny code drop the tool.
        // 4. Parameter-dependent deny codes (e.g. param_forbidden, path_not_allowed) keep the tool.
        const filteredTools = resp.result.tools.filter((tool) => {
            if (!tool || typeof tool !== 'object' || typeof tool.name !== 'string') return false;
            const toolName = tool.name;
            if (!toolName || toolName.trim() !== toolName) {
                // Empty or leading/trailing whitespace => invalid name, drop in enforce mode
                return false;
            }

            const toolHarnessName = `mcp__${serverName}__${toolName}`;
            let dec;
            try {
                dec = runDecision(harness, {
                    agentId,
                    toolName: toolHarnessName,
                    params: {},
                }, {
                    mode: 'enforce',
                    enforcer: 'mcp-list',
                });
            } catch (_) {
                return false;
            }

            if (!dec || typeof dec !== 'object' || dec.allow !== true) {
                // Otherwise, it was denied or returned invalid result
                const code = (dec && typeof dec.reason === 'string')
                    ? dec.reason.split(':')[0].trim()
                    : '';

                if (!code || code === 'enforcer_error' || code === 'domain_guard_error' || ROLE_LEVEL_DENY_CODES.has(code)) {
                    return false;
                }
                return true;
            }

            return true;
        });

        return {
            ...resp,
            result: {
                ...resp.result,
                tools: filteredTools,
            },
        };
    }

    // Client -> Upstream line handler
    function handleClientLine(lineStr) {
        if (passThroughOnly) {
            child.stdin.write(lineStr + '\n');
            return;
        }

        let msg;
        try {
            msg = JSON.parse(lineStr);
        } catch (_) {
            // Invalid JSON from client => -32700 parse error, not forwarded
            output.write(JSON.stringify({
                jsonrpc: '2.0',
                id: null,
                error: {
                    code: -32700,
                    message: 'Parse error: Invalid JSON',
                },
            }) + '\n');
            return;
        }

        if (!msg || typeof msg !== 'object') {
            output.write(JSON.stringify({
                jsonrpc: '2.0',
                id: null,
                error: {
                    code: -32600,
                    message: 'Invalid Request: payload must be an object or array',
                },
            }) + '\n');
            return;
        }

        // Batch handling:
        // 1. Each tools/call element in the batch array is decided separately.
        // 2. Denied items are answered by the gate with JSON-RPC error results.
        // 3. If all items denied: gate returns the array of gate responses immediately.
        // 4. If all items allowed: original batch line is forwarded byte-identically.
        // 5. If mixed: allowed items are forwarded to upstream as a sub-batch; gate responses
        //    are merged with the upstream response batch when received.
        if (Array.isArray(msg)) {
            if (msg.length === 0) {
                output.write(JSON.stringify({
                    jsonrpc: '2.0',
                    id: null,
                    error: {
                        code: -32600,
                        message: 'Invalid Request: batch must not be empty',
                    },
                }) + '\n');
                return;
            }

            const allowedItems = [];
            const gateResponses = [];

            for (const item of msg) {
                const evalRes = evaluateSingleRequest(item);
                if (evalRes.allowed) {
                    allowedItems.push(evalRes.forward);
                } else {
                    if (evalRes.id !== undefined) {
                        gateResponses.push({
                            jsonrpc: '2.0',
                            id: evalRes.id,
                            result: {
                                content: [{ type: 'text', text: evalRes.reason }],
                                isError: true,
                            },
                        });
                    }
                }
            }

            if (allowedItems.length === 0) {
                if (gateResponses.length > 0) {
                    output.write(JSON.stringify(gateResponses) + '\n');
                }
                return;
            }

            if (gateResponses.length === 0) {
                child.stdin.write(lineStr + '\n');
                return;
            }

            // Mixed batch
            const expectedIds = new Set();
            for (const item of allowedItems) {
                if (item && item.id !== undefined) {
                    expectedIds.add(item.id);
                }
            }

            if (expectedIds.size === 0) {
                if (gateResponses.length > 0) {
                    output.write(JSON.stringify(gateResponses) + '\n');
                }
                child.stdin.write(JSON.stringify(allowedItems) + '\n');
                return;
            }

            pendingBatches.push({
                expectedIds,
                gateResponses,
                collectedUpstreamResponses: [],
            });

            child.stdin.write(JSON.stringify(allowedItems) + '\n');
            return;
        }

        // Single message
        const evalRes = evaluateSingleRequest(msg);
        if (evalRes.allowed) {
            // Byte-identical line forwarding for allowed requests and other methods
            child.stdin.write(lineStr + '\n');
        } else {
            if (msg.id !== undefined) {
                output.write(JSON.stringify({
                    jsonrpc: '2.0',
                    id: msg.id,
                    result: {
                        content: [{ type: 'text', text: evalRes.reason }],
                        isError: true,
                    },
                }) + '\n');
            }
        }
    }

    // Client line oversize handler
    function handleClientOversize(prefix) {
        const parsedId = extractIdFromPrefix(prefix);
        if (parsedId !== undefined) {
            output.write(JSON.stringify({
                jsonrpc: '2.0',
                id: parsedId,
                error: {
                    code: -32600,
                    message: 'Request exceeded maximum size limit (4 MiB)',
                },
            }) + '\n');
        }
        // Notifications without ID are dropped silently
    }

    const clientSplitter = createLineSplitter({
        maxBytes: MAX_LINE_BYTES,
        onLine: handleClientLine,
        onOversize: handleClientOversize,
    });

    input.on('data', (chunk) => {
        clientSplitter.push(chunk);
    });

    // Upstream -> Client line handler
    function handleUpstreamLine(lineStr) {
        let resp;
        try {
            resp = JSON.parse(lineStr);
        } catch (_) {
            output.write(lineStr + '\n');
            return;
        }

        if (Array.isArray(resp)) {
            // Batch response from upstream
            for (let i = 0; i < resp.length; i++) {
                const item = resp[i];
                if (item && item.id !== undefined && pendingToolsListRequests.has(item.id)) {
                    pendingToolsListRequests.delete(item.id);
                    resp[i] = filterToolsListResponse(item);
                }
            }

            const matchedIdx = pendingBatches.findIndex((pb) =>
                resp.some((r) => r && r.id !== undefined && pb.expectedIds.has(r.id))
            );

            if (matchedIdx !== -1) {
                const pb = pendingBatches[matchedIdx];
                pendingBatches.splice(matchedIdx, 1);
                const combined = [...pb.gateResponses, ...resp];
                output.write(JSON.stringify(combined) + '\n');
                return;
            }

            output.write(JSON.stringify(resp) + '\n');
            return;
        }

        if (resp && typeof resp === 'object') {
            if (resp.id !== undefined && pendingToolsListRequests.has(resp.id)) {
                pendingToolsListRequests.delete(resp.id);
                resp = filterToolsListResponse(resp);
                output.write(JSON.stringify(resp) + '\n');
                return;
            }

            const matchedIdx = pendingBatches.findIndex((pb) => pb.expectedIds.has(resp.id));
            if (matchedIdx !== -1) {
                const pb = pendingBatches[matchedIdx];
                pb.expectedIds.delete(resp.id);
                pb.collectedUpstreamResponses.push(resp);

                if (pb.expectedIds.size === 0) {
                    pendingBatches.splice(matchedIdx, 1);
                    const combined = [...pb.gateResponses, ...pb.collectedUpstreamResponses];
                    output.write(JSON.stringify(combined) + '\n');
                }
                return;
            }

            // Normal response or notification: byte-identical forwarding
            output.write(lineStr + '\n');
            return;
        }

        output.write(lineStr + '\n');
    }

    const upstreamSplitter = createLineSplitter({
        maxBytes: MAX_LINE_BYTES,
        onLine: handleUpstreamLine,
        onOversize: () => {},
    });

    child.stdout.on('data', (chunk) => {
        upstreamSplitter.push(chunk);
    });

    return {
        child,
        start: () => exitPromise,
        terminate: terminateUpstream,
    };
}

module.exports = {
    createMcpGate,
    ROLE_LEVEL_DENY_CODES,
};
