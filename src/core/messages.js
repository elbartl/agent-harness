'use strict';

const DEFAULT_MESSAGES_EN = {
    'no_agent': 'Required agentId identifier (role is resolved exclusively from agentId)',
    'role_mismatch': 'Provided role request.role does not match agent role from assignments',
    'unknown_role': 'Unknown role: {role}',
    'role_resolution_failed': 'Could not resolve agent role',
    'fallback_cycle': 'Cycle detected in fallbackRole for role {role}',
    'fallback_missing': 'Fallback role {role} does not exist',
    'fallback_invalid': 'Invalid definition for role {role}',
    'fallback_no_grant': 'No fallbackRole defined for role {role} requiring grant',
    'fallback_hops_exceeded': 'Exceeded limit of 3 fallbackRole resolutions',

    'tool_name_invalid': 'Missing or invalid tool name (toolName)',
    'mcp_tool_name_invalid': 'Invalid MCP tool name: {tool}',
    'server_prefix_invalid': "Invalid server name in prefix: '{prefixServer}'",
    'tool_name_suspicious': 'Suspicious tool or server name: {name}',
    'tool_name_server_only': "Tool name '{tool}' refers to a server, not a specific tool",
    'path_traversal': 'Path traversal is not allowed in tool or server name',
    'server_name_invalid': 'Missing or invalid ServerName',
    'server_mismatch': "Server name from ToolName ('{prefixServer}') does not match ServerName ('{curServer}')",
    'too_many_iterations': 'Exceeded limit of 5 prefix stripping iterations',
    'path_suspicious': 'Path contains forbidden bidi characters',

    'request_invalid': 'Missing or invalid request object',
    'call_mcp_missing_target': 'Missing or invalid ServerName or ToolName in call_mcp_tool',
    'params_invalid': 'Invalid parameters format (fail-closed)',
    'params_depth_exceeded': 'Parameters depth limit exceeded (max 8)',
    'params_nodes_exceeded': 'Parameters node count limit exceeded (max 2000)',
    'nested_call_mcp_tool': 'Nested call_mcp_tool invocation is forbidden',

    'exec_disabled': 'Execution tool {tool} is forbidden in role {role} (exec: none mode)',
    'mcp_server_not_configured': 'Role {role} does not have access configured for MCP servers',
    'mcp_server_unknown': 'Could not determine MCP server for tool {tool}',
    'mcp_server_forbidden': "MCP server '{server}' is not allowed for role {role}",
    'platform_tool_forbidden': 'Tool {tool} is allowed exclusively in full role (missing in permissions for role {role})',
    'tool_denied': 'Tool {tool} is blocked on deny list of role {role}',
    'disallow_pattern_matched': 'Tool {tool} is blocked by disallowPatterns rule in role {role}',
    'tool_not_allowed': 'Tool {tool} is not on the allowed list for role {role}',
    'allow_file_unreadable': 'Could not read allow file {file}: {error}',
    'deny_file_unreadable': 'Could not read deny file {file}: {error}',
    'internal_error': 'Internal permissions verification error (fail-closed): {error}',
    'enforcer_error': 'Enforcer internal error: {error}',
};

function formatMessage(code, params = {}, customMessages = {}) {
    let template = customMessages[code] || DEFAULT_MESSAGES_EN[code] || code;
    let text = typeof template === 'function' ? template(params) : template;
    if (typeof text === 'string') {
        for (const [k, v] of Object.entries(params)) {
            text = text.replaceAll(`{${k}}`, String(v ?? ''));
        }
        if (text.startsWith(`${code}:`)) {
            return text;
        }
        return `${code}: ${text}`;
    }
    return `${code}: ${String(text)}`;
}

module.exports = {
    DEFAULT_MESSAGES_EN,
    formatMessage,
};
