# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-22

### Added
- Generic enforcers connecting the policy harness to real tool execution surfaces:
  - CLI pre-tool hook (`createCliEnforcer`, `bin/agent-harness-hook`) supporting `claude-code` and `agy` formats with size and timeout guards.
  - MCP stdio JSON-RPC gate (`createMcpGate`, `bin/agent-harness-mcp-gate`) with fail-closed `tools/call` blocking and `tools/list` role-level filtering.
  - API tool call hook (`createToolCallHook`) compatible with agent `before_tool_call` contracts.
- Dual execution modes: `enforce` (blocking) and `audit` (logging/shadow mode with `wouldBlock: true`).
- Secure audit logging with canonical JSON parameter hashing (SHA-256) and payload byte length; parameter values are never stored.
- Process lifecycle management in MCP gate with upstream `SIGTERM` and 3-second `SIGKILL` escalation on client disconnect.
- Standalone CLI binaries `agent-harness-hook` and `agent-harness-mcp-gate` in package `bin`.

## [0.1.0] - 2026-11-22

### Added
- Initial release of `agent-harness`.
- Deterministic, fail-closed authorization engine (`decide`, `resolveRole`, `resolveAgent`).
- Pluggable `domainGuards` interface for deep parameter inspection and domain-specific rules.
- Unicode and homoglyph normalization (`normalizeForMatch`) for match evaluation without rewriting inputs.
- Bidirectional text (bidi) override rejection for tool and server names and paths.
- Configurable error message catalog with custom message overrides.
- Home Assistant example domain guard in `examples/home-assistant/`.
- JSON schemas for roles and assignments configuration.
