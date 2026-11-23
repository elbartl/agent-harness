'use strict';

const { runDecision, computeParamsHash } = require('./common');
const { formatMessage } = require('../core/messages');

function createToolCallHook(harness, options = {}) {
    const mode = options.mode === 'audit' ? 'audit' : 'enforce';
    const agentIdFrom = typeof options.agentIdFrom === 'function'
        ? options.agentIdFrom
        : ((event, ctx) => (ctx && typeof ctx.agentId === 'string' ? ctx.agentId : null));
    const toolNameMap = typeof options.toolNameMap === 'function' ? options.toolNameMap : null;
    const onDecision = options.onDecision;
    const now = options.now;

    return function beforeToolCall(event, ctx) {
        const effectiveAgentId = agentIdFrom(event, ctx);
        const rawToolName = toolNameMap ? toolNameMap(event, ctx) : (event && event.toolName);
        const params = event ? event.params : undefined;

        if (!effectiveAgentId || typeof effectiveAgentId !== 'string' || !effectiveAgentId.trim()) {
            const reason = formatMessage('no_agent', {}, harness?.messages);
            const { paramsSha256, paramsBytes } = computeParamsHash(params);
            const ts = typeof now === 'function' ? now() : (now !== undefined ? now : Date.now());
            const wouldBlock = true;
            const allow = mode === 'audit';

            if (typeof onDecision === 'function') {
                try {
                    onDecision({
                        ts,
                        agentId: null,
                        toolName: typeof rawToolName === 'string' ? rawToolName : null,
                        allow,
                        reason,
                        mode,
                        enforcer: 'api',
                        wouldBlock,
                        paramsSha256,
                        paramsBytes,
                    });
                } catch (_) {}
            }

            if (mode === 'audit') {
                return undefined;
            }
            return { block: true, blockReason: reason };
        }

        const request = {
            agentId: effectiveAgentId.trim(),
            toolName: typeof rawToolName === 'string' ? rawToolName : '',
            params,
        };

        const decision = runDecision(harness, request, {
            mode,
            onDecision,
            now,
            enforcer: 'api',
        });

        if (decision.allow) {
            return undefined;
        }

        return {
            block: true,
            blockReason: decision.reason,
        };
    };
}

module.exports = {
    createToolCallHook,
};
