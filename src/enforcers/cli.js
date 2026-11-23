'use strict';

const { runDecision, computeParamsHash } = require('./common');
const { formatMessage } = require('../core/messages');

function createCliEnforcer(harness, options = {}) {
    const format = options.format;
    const configuredAgentId = options.agentId;
    const mode = options.mode === 'audit' ? 'audit' : 'enforce';
    const onDecision = options.onDecision;
    const now = options.now;
    const enforcerName = `cli:${format || 'unknown'}`;

    function failClosed(reason, agentId, toolName, params) {
        const { paramsSha256, paramsBytes } = computeParamsHash(params);
        const ts = typeof now === 'function' ? now() : (now !== undefined ? now : Date.now());
        const wouldBlock = true;
        const allow = mode === 'audit';

        const record = {
            ts,
            agentId: typeof agentId === 'string' ? agentId : null,
            toolName: typeof toolName === 'string' ? toolName : null,
            allow,
            reason,
            mode,
            enforcer: enforcerName,
            wouldBlock,
            paramsSha256,
            paramsBytes,
        };

        if (typeof onDecision === 'function') {
            try {
                onDecision(record);
            } catch (_) {}
        }

        if (mode === 'audit') {
            if (format === 'agy') {
                return {
                    exitCode: 0,
                    stdout: JSON.stringify({ decision: 'allow' }),
                    stderr: '',
                };
            }
            return {
                exitCode: 0,
                stdout: '',
                stderr: '',
            };
        }

        if (format === 'agy') {
            return {
                exitCode: 0,
                stdout: JSON.stringify({ decision: 'deny', reason }),
                stderr: '',
            };
        }

        // claude-code or unknown format
        return {
            exitCode: 2,
            stdout: '',
            stderr: reason,
        };
    }

    return {
        handle(eventInput) {
            // 1. Check format
            if (format !== 'claude-code' && format !== 'agy') {
                return failClosed(
                    `enforcer_error: Unknown CLI enforcer format: ${format}`,
                    configuredAgentId,
                    null,
                    undefined
                );
            }

            // 2. Parse eventInput
            let ev = eventInput;
            if (typeof eventInput === 'string') {
                try {
                    ev = JSON.parse(eventInput);
                } catch (e) {
                    return failClosed(
                        `enforcer_error: Unparsable event JSON: ${e.message}`,
                        configuredAgentId,
                        null,
                        undefined
                    );
                }
            }

            if (!ev || typeof ev !== 'object' || Array.isArray(ev)) {
                return failClosed(
                    formatMessage('request_invalid', {}, harness?.messages),
                    configuredAgentId,
                    null,
                    undefined
                );
            }

            // 3. Format-specific handling
            if (format === 'claude-code') {
                const rawToolName = ev.tool_name;
                if (!rawToolName || typeof rawToolName !== 'string' || !rawToolName.trim()) {
                    return failClosed(
                        formatMessage('tool_name_invalid', {}, harness?.messages),
                        configuredAgentId,
                        null,
                        ev.tool_input
                    );
                }

                const effectiveAgentId = (typeof configuredAgentId === 'string' && configuredAgentId.trim())
                    ? configuredAgentId.trim()
                    : ((typeof ev.agentId === 'string' && ev.agentId.trim())
                        ? ev.agentId.trim()
                        : ((typeof ev.agent === 'string' && ev.agent.trim()) ? ev.agent.trim() : null));

                if (!effectiveAgentId) {
                    return failClosed(
                        formatMessage('no_agent', {}, harness?.messages),
                        null,
                        rawToolName.trim(),
                        ev.tool_input
                    );
                }

                let toolInput = ev.tool_input;
                if (typeof toolInput === 'string') {
                    try {
                        toolInput = JSON.parse(toolInput);
                    } catch (_) {
                        return failClosed(
                            formatMessage('params_invalid', {}, harness?.messages),
                            effectiveAgentId,
                            rawToolName.trim(),
                            ev.tool_input
                        );
                    }
                }

                if (!toolInput || typeof toolInput !== 'object' || Array.isArray(toolInput)) {
                    return failClosed(
                        formatMessage('params_invalid', {}, harness?.messages),
                        effectiveAgentId,
                        rawToolName.trim(),
                        toolInput
                    );
                }

                const request = {
                    agentId: effectiveAgentId,
                    toolName: rawToolName.trim(),
                    params: toolInput,
                };

                const decision = runDecision(harness, request, {
                    mode,
                    onDecision,
                    now,
                    enforcer: enforcerName,
                });

                if (decision.allow) {
                    return {
                        exitCode: 0,
                        stdout: '',
                        stderr: '',
                    };
                }

                return {
                    exitCode: 2,
                    stdout: '',
                    stderr: decision.reason,
                };
            }

            if (format === 'agy') {
                let toolCall = null;
                if (ev.toolCall && typeof ev.toolCall === 'object' && !Array.isArray(ev.toolCall)) {
                    toolCall = ev.toolCall;
                } else if (typeof ev.name === 'string') {
                    toolCall = ev;
                }

                if (!toolCall) {
                    return failClosed(
                        formatMessage('tool_name_invalid', {}, harness?.messages),
                        configuredAgentId,
                        null,
                        undefined
                    );
                }

                const rawToolName = toolCall.name;
                if (!rawToolName || typeof rawToolName !== 'string' || !rawToolName.trim()) {
                    return failClosed(
                        formatMessage('tool_name_invalid', {}, harness?.messages),
                        configuredAgentId,
                        null,
                        undefined
                    );
                }

                const effectiveAgentId = (typeof configuredAgentId === 'string' && configuredAgentId.trim())
                    ? configuredAgentId.trim()
                    : ((typeof ev.agentId === 'string' && ev.agentId.trim())
                        ? ev.agentId.trim()
                        : ((typeof ev.agent === 'string' && ev.agent.trim()) ? ev.agent.trim() : null));

                if (!effectiveAgentId) {
                    return failClosed(
                        formatMessage('no_agent', {}, harness?.messages),
                        null,
                        rawToolName.trim(),
                        toolCall.args
                    );
                }

                let toolArgs = toolCall.args !== undefined ? toolCall.args : (toolCall.arguments !== undefined ? toolCall.arguments : {});
                if (typeof toolArgs === 'string') {
                    try {
                        toolArgs = JSON.parse(toolArgs);
                    } catch (_) {
                        return failClosed(
                            formatMessage('params_invalid', {}, harness?.messages),
                            effectiveAgentId,
                            rawToolName.trim(),
                            toolCall.args
                        );
                    }
                }

                if (!toolArgs || typeof toolArgs !== 'object' || Array.isArray(toolArgs)) {
                    return failClosed(
                        formatMessage('params_invalid', {}, harness?.messages),
                        effectiveAgentId,
                        rawToolName.trim(),
                        toolArgs
                    );
                }

                const request = {
                    agentId: effectiveAgentId,
                    toolName: rawToolName.trim(),
                    params: toolArgs,
                };

                const decision = runDecision(harness, request, {
                    mode,
                    onDecision,
                    now,
                    enforcer: enforcerName,
                });

                if (decision.allow) {
                    return {
                        exitCode: 0,
                        stdout: JSON.stringify({ decision: 'allow' }),
                        stderr: '',
                    };
                }

                return {
                    exitCode: 0,
                    stdout: JSON.stringify({ decision: 'deny', reason: decision.reason }),
                    stderr: '',
                };
            }

            return failClosed(`enforcer_error: Unknown format ${format}`, configuredAgentId, null, undefined);
        },
    };
}

module.exports = {
    createCliEnforcer,
};
