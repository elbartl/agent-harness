'use strict';

const crypto = require('node:crypto');
const { formatMessage } = require('../core/messages');

function canonicalJson(val, seen = new Set()) {
    if (val === undefined) return '';
    if (val === null || typeof val !== 'object') {
        return JSON.stringify(val);
    }
    if (seen.has(val)) {
        return '"[Circular]"';
    }
    seen.add(val);
    try {
        if (Array.isArray(val)) {
            return '[' + val.map((item) => canonicalJson(item, seen)).join(',') + ']';
        }
        const keys = Object.keys(val).filter((k) => val[k] !== undefined).sort();
        return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(val[k], seen)).join(',') + '}';
    } finally {
        seen.delete(val);
    }
}

function computeParamsHash(params) {
    if (params === undefined) {
        const emptySha = crypto.createHash('sha256').update('').digest('hex');
        return {
            paramsSha256: emptySha,
            paramsBytes: 0,
        };
    }
    let val = params;
    if (typeof val === 'string') {
        try {
            val = JSON.parse(val);
        } catch (_) {
            // Keep string as-is
        }
    }
    try {
        const canon = canonicalJson(val);
        const paramsBytes = Buffer.byteLength(canon, 'utf8');
        const paramsSha256 = crypto.createHash('sha256').update(canon, 'utf8').digest('hex');
        return { paramsSha256, paramsBytes };
    } catch (_) {
        const emptySha = crypto.createHash('sha256').update('').digest('hex');
        return { paramsSha256: emptySha, paramsBytes: 0 };
    }
}

function runDecision(harness, request, options = {}) {
    const opts = options || {};
    const mode = opts.mode === 'audit' ? 'audit' : 'enforce';
    const enforcer = typeof opts.enforcer === 'string' ? opts.enforcer : 'unknown';
    const nowFn = typeof opts.now === 'function' ? opts.now : () => (opts.now !== undefined ? opts.now : Date.now());
    const ts = nowFn();

    const { paramsSha256, paramsBytes } = computeParamsHash(request ? request.params : undefined);

    let rawResult;

    try {
        if (!harness || typeof harness.decide !== 'function') {
            throw new Error('Harness instance with decide() method is required');
        }
        rawResult = harness.decide(request);
        if (!rawResult || typeof rawResult !== 'object' || typeof rawResult.allow !== 'boolean') {
            throw new Error('Harness decide() returned an invalid result');
        }
    } catch (err) {
        const msg = harness && harness.messages ? harness.messages : {};
        const errMsg = formatMessage('enforcer_error', { error: err.message }, msg);
        rawResult = {
            allow: false,
            reason: errMsg,
            role: null,
            exec: 'none',
            guards: [],
        };
    }

    const wouldBlock = !rawResult.allow;
    const finalAllow = mode === 'audit' ? true : rawResult.allow;
    const finalReason = rawResult.reason;

    const record = {
        ts,
        agentId: (request && typeof request.agentId === 'string') ? request.agentId : null,
        toolName: (request && typeof request.toolName === 'string') ? request.toolName : null,
        allow: finalAllow,
        reason: finalReason,
        mode,
        enforcer,
        wouldBlock,
        paramsSha256,
        paramsBytes,
    };

    if (typeof opts.onDecision === 'function') {
        try {
            opts.onDecision(record);
        } catch (_) {
            // Exceptions thrown by onDecision are swallowed and never change the decision
        }
    }

    return {
        ...rawResult,
        allow: finalAllow,
        reason: finalReason,
        mode,
        wouldBlock,
    };
}

module.exports = {
    canonicalJson,
    computeParamsHash,
    runDecision,
};
