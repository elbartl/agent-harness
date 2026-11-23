# agent-harness

Universal, deterministic policy enforcement and authorization harness for AI agents and Model Context Protocol (MCP) tools.

## Overview

`agent-harness` provides a decoupled, fail-closed authorization layer that evaluates whether an agent is permitted to execute a given tool call with specific parameters.

Key features:
- **Strict Fail-Closed Architecture:** Any parsing error, missing configuration file, unknown role, traversal attempt, or cycle resolution results in an immediate denial.
- **Pure Evaluation & Separation of Concerns:** Core engine is completely decoupled from application-specific business logic, private paths, and external service definitions.
- **Deep Parameter Inspection:** Traverses parameter payloads up to depth 8 and 2000 nodes, parsing stringified JSON and blocking nested tool invocations.
- **Homoglyph & Unicode Normalization:** `normalizeForMatch()` handles NFKC normalization, invisible characters, and Cyrillic/Greek homoglyphs strictly for matching against policies, never modifying payload content.
- **Bidi Control Character Rejection:** Rejects bidirectional overrides (U+202A–U+202E, U+2066–U+2069) in tool names, server names, and path fields.
- **Pluggable Domain Guards:** Extensible domain-specific guard interface (`domainGuards`) for inspecting tool invocations without contaminating the core engine.
- **Adapter Metadata Support:** `assignments.json` supports both string role definitions and object definitions with adapter metadata (`{ role, adapter, adapterConfig }`).
- **Zero Runtime Dependencies:** Built solely on standard Node.js (>= 20).

---

## Installation

```bash
npm install github:elbartl/agent-harness
```

---

## Architecture & Core Concepts

### 1. Configuration Model

The harness relies on three core configuration artifacts:

1. **`roles.json`**: Defines roles (`exec`, `files`, `allow`, `deny`, `disallowPatterns`, `mcpServers`, `categories`, `requiresGrant`, `fallbackRole`).
2. **`assignments.json`**: Maps agent identifiers (`agentId`) to assigned roles. Supports string format (`"main": "ops"`) and object format (`"main": { "role": "ops", "adapter": "cc-proxy", "adapterConfig": {} }`).
3. **`tool-names.json`**: Maps tool aliases to canonical tool names and categories.

### 2. Contract & API

The package exports `createHarness`, `decide`, `resolveRole`, `resolveAgent`, `canonicalize`, `normalizeForMatch`, and `deepInspectParams`.

#### `createHarness(config)`
```javascript
const harness = createHarness({
  roles: './roles.json',          // Path string or roles object
  assignments: './assignments.json', // Path string or assignments object
  toolNames: './tool-names.json', // Path string or tool-names object
  domainGuards: [haDomainGuard],  // Array of domain guard plugins
  messages: {                     // Optional localized messages dictionary
    'unknown_role': 'Role {role} is not defined'
  },
  grantFile: '/path/to/grant',    // Optional grant file path
  env: process.env                // Optional environment variables
});
```

#### `harness.decide(request, options)`
Input:
```javascript
{
  agentId: 'worker-1',      // Required agent identifier
  toolName: 'exec',         // Tool name being called
  params: { ... },          // Parameters object or JSON string
  role: 'ops',              // Optional assertion role (must match resolved role)
}
```

Output:
```javascript
{
  allow: true | false,
  reason: 'OK' | '<code: <message>>',
  role: 'ops' | null,
  exec: 'none' | 'sandbox' | 'host',
  guards: ['sandbox_shell', 'write_guard', ...]
}
```

#### `harness.resolveRole(agentId, options)`
Resolves the effective role string (e.g. `'ops'`, `'ro'`, `'none'`).

#### `harness.resolveAgent(agentId, options)`
Resolves agent definition including adapter metadata:
```javascript
{
  role: 'ops',
  adapter: 'cc-proxy' | null,
  adapterConfig: { ... } | null
}
```
If an agent is unassigned or configured with an unknown format, `role` defaults to `'none'` (fail-closed) and `adapter` / `adapterConfig` return `null`.

---

## Domain Guards Interface

Domain guards extend the harness with domain-specific rules (e.g. Home Assistant service protection) without baking service-specific constants or paths into the core engine.

```javascript
const myGuard = {
  name: 'my-service',
  canonicalServer: 'mysrv',
  effectiveServerName: 'mysrv',
  
  // Checks if a given MCP server name belongs to this domain
  matchServer(serverName) {
    return serverName === 'my-mcp' || serverName === 'myservice';
  },

  // Prefix and server alias mappings for canonicalization
  serverAliases: { 'my-mcp': 'mysrv', 'myservice': 'mysrv' },
  prefixes: ['mysrv'],

  // Deep inspection callback for parameter nodes (called on every traversed object node)
  inspect(node, ctx) {
    if (node && node.action === 'drop_database') {
      return {
        blocked: true,
        code: 'db_drop_forbidden',
        reason: 'db_drop_forbidden: Dropping database is strictly prohibited'
      };
    }
    return null; // continue inspection
  },

  // Tool inspection callback
  inspectTool(normTool, effectiveToolName, effectiveParams, roleDef, ctx) {
    return null;
  },

  // Execution guards returned in decide() result
  getGuards(normTool, effectiveToolName, roleDef, ctx) {
    return [];
  }
};
```

### Home Assistant Domain Guard Example (`examples/home-assistant`)

The Home Assistant plugin (`ha-domain-guard.js`) demonstrates:
- **Server Canonicalization:** Maps `ha-mcp`, `homeassistant`, and `ha` servers to canonical `ha` via `serverAliases` and `matchServer`.
- **Sensitive Service Protection:** Inspects all parameter payloads for blocked service actions (`homeassistant.restart`, `homeassistant.stop`, `homeassistant.reload_core`, and the entire `hassio` domain).
- **Domain Guard Bypass:** Supported either via the generic role property `bypassDomainGuards: ["home-assistant"]` or the domain-specific flag `allowHaRestart: true` in `roles.json`.
- **Guard Attachment:** Automatically attaches the `ha_guard` parameter guard for state-modifying tools (`ha_call_service`, `ha_bulk_control`, `ha_call_event`) in operational roles.

---

## Error Codes and Message Customization

All reasons follow the standard `<code: <message>>` format. Built-in error codes include:

| Code | Description |
| :--- | :--- |
| `no_agent` | Missing or invalid `agentId` |
| `role_mismatch` | `request.role` assertion does not match resolved role |
| `unknown_role` | Role is not defined in `roles.json` |
| `params_invalid` | Malformed parameters (e.g. invalid JSON string) |
| `params_depth_exceeded`| Parameter depth exceeds 8 levels |
| `params_nodes_exceeded`| Parameter node count exceeds 2000 |
| `tool_name_suspicious` | Tool or server name contains invalid/invisible/bidi characters |
| `path_suspicious` | Path contains bidi control characters |
| `nested_call_mcp_tool` | Disallowed nested MCP call inside parameters |
| `too_many_iterations` | Prefix stripping exceeded 5 iterations |
| `server_mismatch` | ServerName mismatch with prefix in ToolName |
| `exec_disabled` | Execution tool called in `exec: none` role |
| `tool_denied` | Tool matched deny list |
| `disallow_pattern_matched` | Parameter path matched disallowPatterns |
| `tool_not_allowed` | Tool not present in allow list |

Messages can be localized or customized via `createHarness({ messages })` or passed to `decide(request, { messages })`.

---

## Example Usage

```javascript
const { createHarness } = require('agent-harness');
const haDomainGuard = require('agent-harness/examples/home-assistant/ha-domain-guard');

const harness = createHarness({
  roles: './roles.json',
  assignments: './assignments.json',
  toolNames: './tool-names.json',
  domainGuards: [haDomainGuard],
  messages: {
    'no_agent': 'Agent identifier is mandatory',
  }
});

const result = harness.decide({
  agentId: 'main',
  toolName: 'exec',
  params: { command: 'ls' }
});

console.log(result);
// { allow: true, reason: 'OK', role: 'ops', exec: 'sandbox', guards: ['sandbox_shell'] }
```

---

## Enforcers

`agent-harness` provides three generic, production-ready enforcers that connect the `decide()` authorization engine to actual tool execution surfaces:

1. **CLI Pre-Tool Hook (`createCliEnforcer`, `bin/agent-harness-hook`)**:
   - Supports `claude-code` (`PreToolUse` protocol: stdin JSON with `tool_name` / `tool_input`; denial produces exit code 2 and stderr message, allow produces exit code 0).
   - Supports `agy` (`toolCall: { name, args }`; denial produces exit code 0 with stdout `{"decision":"deny","reason":"..."}`, allow produces `{"decision":"allow"}`).
   - Handles inner tool call resolution for `call_mcp_tool` (evaluating `ServerName`, `ToolName`, and `Arguments`).
   - Guarded stdin reader with a 1 MiB payload size cap and 5-second execution timeout.
2. **MCP Stdio Gate (`createMcpGate`, `bin/agent-harness-mcp-gate`)**:
   - Transparent stdio JSON-RPC 2.0 proxy placed between an MCP client and any upstream MCP server process.
   - Spawns upstream commands using `child_process.spawn(command, args, { shell: false })` (never invokes a shell).
   - Intercepts `tools/call` requests: decides authorization using tool name `mcp__<serverName>__<params.name>` and `params.arguments`. On denial in enforce mode, returns JSON-RPC `{ result: { content: [{ type: 'text', text: reason }], isError: true }, id }` directly to the client without forwarding the request upstream.
   - Filters upstream `tools/list` responses in enforce mode, dropping tools the agent role can never call.
   - Handles JSON-RPC batch arrays by deciding elements independently, forwarding allowed subsets, and merging responses.
   - Upstream process supervision: terminates upstream with `SIGTERM` when client stdin disconnects, escalating to `SIGKILL` after 3 seconds if unresponsive.
3. **API Tool Call Hook (`createToolCallHook`)**:
   - Synchronous host policy hook `(event, ctx) => undefined | { block: true, blockReason }`.
   - Plugs directly into runtime `before_tool_call` hooks. Pure, synchronous, and never mutates parameters.

---

### Enforce vs. Audit Modes

Every enforcer operates in one of two modes:
- **`enforce`**: Disallowed tool calls and policy errors are blocked immediately (non-zero CLI exit code, JSON-RPC error response, or hook block).
- **`audit`**: Shadow/canary mode. Policy decisions are evaluated and logged via `onDecision`, but tool calls are never blocked (`allow: true`, with `wouldBlock: true` set on violations). Requests pass through to upstream unmodified.

---

### Audit Record Format

Audit logs capture authorization telemetry without leaking sensitive parameter values:
```json
{
  "ts": 1732310000000,
  "agentId": "worker-1",
  "toolName": "mcp__my-server__read_data",
  "allow": true,
  "reason": "OK",
  "mode": "enforce",
  "enforcer": "mcp",
  "wouldBlock": false,
  "paramsSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "paramsBytes": 2
}
```

- **Zero Parameter Leaks:** Raw parameter values are never stored. `paramsSha256` contains the SHA-256 digest of canonical JSON parameters, and `paramsBytes` stores the canonical UTF-8 byte length.
- **Strict File Permissions:** Audit log files created by CLI binaries are restricted to file mode `0600`.
- **Fault-Tolerant:** Exceptions thrown by `onDecision` callbacks are swallowed and never alter authorization decisions.

---

### Fail-Closed Behavior Table

| Scenario | Enforcer | Enforce Mode Behavior | Audit Mode Behavior |
| :--- | :--- | :--- | :--- |
| Unparsable stdin / JSON | CLI Hook | Deny (exit 2 or deny JSON) | Allow, log `enforcer_error` with `wouldBlock: true` |
| Missing tool name | CLI / MCP / API | Deny (`tool_name_invalid`) | Allow, log `wouldBlock: true` |
| Missing agent ID | CLI / MCP / API | Deny (`no_agent` / `enforcer_error`) | Allow, log `wouldBlock: true` |
| Unknown hook format | CLI Hook | Deny (`enforcer_error`) | Allow, log `wouldBlock: true` |
| Stdin input > 1 MiB | CLI Hook | Deny (`enforcer_error: Stdin input size limit exceeded`) | Deny (`enforcer_error: Stdin input size limit exceeded`) |
| Stdin timeout (> 5 s) | CLI Hook | Deny (`enforcer_error: Stdin read timeout`) | Deny (`enforcer_error: Stdin read timeout`) |
| `harness.decide()` throws | All Enforcers | Deny (`enforcer_error`) | Allow, log `wouldBlock: true` |
| Invalid harness result | All Enforcers | Deny (`enforcer_error`) | Allow, log `wouldBlock: true` |
| MCP client line > 4 MiB | MCP Gate | Return `-32600` if ID parsed, or drop | Return `-32600` or drop |
| Invalid JSON from client | MCP Gate | Return `-32700` Parse error, not forwarded | Return `-32700` Parse error |
| `tools/list` decide error | MCP Gate | Drop tool from list (`enforcer_error` / `domain_guard_error`) | Keep tool in list |

---

### MCP Tool Name Mapping & `tools/list` Filtering

- **Tool Name Mapping:** MCP tool calls are authorized under `mcp__<serverName>__<params.name>` with parameters from `params.arguments` (default `{}`). Exact string matching is enforced without trimming. Empty names, non-string names, or names with leading/trailing whitespace are rejected as invalid.
- **`tools/list` Filtering:** In `enforce` mode, each upstream tool is evaluated via `decide()` with empty parameters `{}`:
  - **Dropped:** If `decide()` throws, returns an invalid result, yields reason `enforcer_error` or `domain_guard_error`, or fails with any role-level code (`ROLE_LEVEL_DENY_CODES` including `tool_not_allowed`, `tool_denied`, `mcp_server_forbidden`, `exec_disabled`, `role_mismatch`).
  - **Kept:** If the tool is permitted, or if the denial code is strictly parameter-dependent (e.g. `param_forbidden`, `path_not_allowed`, `params_invalid`).
  - In `audit` mode, upstream `tools/list` responses are never filtered.

---

### CLI Binaries

#### 1. `agent-harness-hook`
```bash
agent-harness-hook \
  --format claude-code \
  --agent worker-1 \
  --mode enforce \
  --roles /path/to/roles.json \
  --assignments /path/to/assignments.json \
  --tool-names /path/to/tool-names.json \
  --guard ./guards/my-guard.js \
  --audit-log ./audit.log
```

#### 2. `agent-harness-mcp-gate`
```bash
agent-harness-mcp-gate \
  --server filesystem \
  --agent worker-1 \
  --mode enforce \
  --roles /path/to/roles.json \
  --assignments /path/to/assignments.json \
  --tool-names /path/to/tool-names.json \
  --guard ./guards/my-guard.js \
  --audit-log ./mcp-audit.log \
  -- /usr/bin/npx -y @modelcontextprotocol/server-filesystem /tmp
```

---

## Deployment Wiring (OpenClaw)

This deployment integrates `agent-harness` across three distinct enforcement surfaces in audit mode (telemetry only, never blocking):

### 1. OpenClaw Policy Plugin (`plugins/agent-harness-policy`)
- **Hook**: Registers a `before_tool_call` hook evaluating tool calls through `createToolCallHook`.
- **Policy File Resolution**: For `roles.json`, `assignments.json`, and `tool-names.json`, resolution order per file is:
  1. Environment overrides: `OC_ROLES_FILE`, `OC_ASSIGNMENTS_FILE`, `OC_TOOL_NAMES_FILE`.
  2. Plugin configuration: `policyDir` (must be an absolute directory path).
  3. Default fallback: `<repo>/permissions/` relative to the original module path.
- **Fail-Closed Diagnostics**: If `policyDir` is relative, or if any policy file does not exist, an error is logged (`api.logger.error`/`warn`) with the missing paths. Missing files never result in a silent allow.
- **Telemetry**: Writes decisions to `~/.openclaw/logs/agent-harness-audit.jsonl` (or configured `auditLog`).

### 2. CLI PreToolUse Hook (`claude_proxy.js`)
- **Placement**: Attached LAST in `PreToolUse` hook list within `--settings` after existing operational guards (`Bash`, `Write|Edit`, `Read|Grep`, `ha_guard`).
- **Scope**: Applied to all roles (`full`, `ro`, `ops`, `cfg`, `web`, `dev`, `ncro`, `ncops`) with matcher `.*` (covering all native tools and `mcp__*`).
- **Execution & Safety**: Runs `bin/agent-harness-hook.js --format claude-code --mode audit`. In audit mode, the hook always exits `0` and never emits a `deny`/`ask` decision; errors/timeouts never block tool execution.
- **Agent Identity**: Resolved via `resolveAgentId`: checks `PAPERCLIP_AGENT_ID` (env) > `x-openclaw-agent-id` (header) > `data.agentId` / `metadata.agentId` (body). Validated against `/^[A-Za-z0-9:_.-]{1,64}$/`. Fallback format is `cc:<role>` (e.g. `cc:ops`, `cc:ro`).
- **Telemetry**: Logs to `~/.openclaw/logs/agent-harness-audit-cli.jsonl`.
- **Sandboxed Roles (`ops`, `cfg`)**: Requires root-owned binary at `/usr/local/lib/openclaw-guard/agent-harness-hook.js` (`0755`, owner root). If missing, logs a single warning and skips the harness hook without failing the session. Root-owned installation commands:
  ```bash
  sudo install -m 0755 -o root -g root <repo>/packages/agent-harness/bin/agent-harness-hook.js /usr/local/lib/openclaw-guard/agent-harness-hook.js
  sudo mkdir -p /usr/local/lib/openclaw-guard/packages/agent-harness
  sudo cp -r <repo>/packages/agent-harness/* /usr/local/lib/openclaw-guard/packages/agent-harness/
  sudo chown -R root:root /usr/local/lib/openclaw-guard/packages/agent-harness
  sudo chmod -R 0755 /usr/local/lib/openclaw-guard/packages/agent-harness
  ```
- **Kill Switch**: `AGENT_HARNESS_CLI=off` disables CLI hook generation entirely.

### 3. Stdio MCP Gate (`claude_proxy.js`)
- **Scope**: Wraps stdio MCP servers in generated `--mcp-config` files (`devMcpConfig`, `webMcpConfig`, `roMcpConfig`, `ncroMcpConfig`, `ncopsMcpConfig`, `fullMcpConfig`).
- **Wrapping**: Prepends `node bin/agent-harness-mcp-gate.js --server <name> --agent <id> --mode audit ... --` before original command and args. Preserves `env` and `cwd` unchanged.
- **Config Storage**: Generates per-agent config files `mcp-<role>-harness-<agentId>.json` with mode `0600` via atomic temporary file rename.
- **HTTP/SSE Servers**: Untouched and passed through as-is; server names are logged once per process.
- **Telemetry**: Logs to `~/.openclaw/logs/agent-harness-audit-mcp.jsonl`.
- **Sandboxed Roles (`ops`, `cfg`)**: Requires root-owned binary `/usr/local/lib/openclaw-guard/agent-harness-mcp-gate.js`. If missing, logs one warning and falls back to unwrapped configs.
- **Kill Switch**: `AGENT_HARNESS_MCP=off` disables MCP server wrapping and returns unwrapped configs.

### 4. Switching to Enforce Later
- **Prerequisite**: Review audit logs (`agent-harness-audit.jsonl`, `agent-harness-audit-cli.jsonl`, `agent-harness-audit-mcp.jsonl`) for entries with `"wouldBlock": true`. Adjust `roles.json` / `assignments.json` until zero unintended blocks and zero `internal_error` entries occur.
- **Caller Authentication Requirement**: Before switching to enforce mode, the proxy must authenticate the caller (e.g. via a loopback token from the Gateway) or take agent identity only from the trusted environment, because `x-openclaw-agent-id` headers and request body `agentId` fields can be spoofed by an unauthenticated direct HTTP client.
- **Enforcement Knobs**:
  1. *Plugin*: Set `"mode": "enforce"` in plugin configuration (or `OC_HARNESS_MODE=enforce`).
  2. *CLI Hook*: Set `--mode enforce` in `claude_proxy.js` CLI hook builder arguments.
  3. *MCP Gate*: Set `--mode enforce` in `claude_proxy.js` `wrapMcpServers` arguments.
- **Recommended Rollout Order**:
  1. Flip OpenClaw Plugin to `enforce`. Verify Gateway tool execution.
  2. Flip CLI PreToolUse hook to `enforce`. Verify backend Claude executions block disallowed tools with exit `2`.
  3. Flip MCP Gate to `enforce`. Verify `tools/list` filters unauthorized tools and `tools/call` rejects unauthorized invocations.
- **Verification**: Check logs for `"mode": "enforce"`. Ensure allowed tools succeed and unauthorized tools produce explicit denial records without internal errors.

### 5. Test Suites
- `tools/test_claude_proxy_harness.js`: Verifies CLI hook configuration, role coverage, ordering, kill switch, and sandbox fallback.
- `tools/test_claude_proxy_mcp_gate.js`: Verifies MCP server wrapping, argument preservation, HTTP passthrough, kill switch, and permissions.
- `tools/test_agent_harness_e2e.js`: End-to-end audit mode verification for CLI hook and MCP gate with mock upstream processes.
- `packages/agent-harness/test/`: Core authorization engine unit tests (policies, homoglyphs, bidi, domain guards, enforcers).
- `plugins/agent-harness-policy/agent-harness-policy.test.mjs`: Policy path resolution, plugin configuration, and hook dispatch tests.

---

## License

MIT License. Copyright (c) 2026 Agent Harness Authors.
