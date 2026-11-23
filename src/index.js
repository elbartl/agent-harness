'use strict';

const decideCore = require('./core/decide');
const loaders = require('./core/loaders');
const canonicalizeCore = require('./core/canonicalize');
const normalizeCore = require('./core/normalize');
const deepInspect = require('./core/deepInspectParams');
const messagesCore = require('./core/messages');

const { runDecision, computeParamsHash, canonicalJson } = require('./enforcers/common');
const { createCliEnforcer } = require('./enforcers/cli');
const { createToolCallHook } = require('./enforcers/api');
const { createMcpGate, ROLE_LEVEL_DENY_CODES } = require('./enforcers/mcp');

const enforcers = {
    runDecision,
    computeParamsHash,
    canonicalJson,
    createCliEnforcer,
    createToolCallHook,
    createMcpGate,
    ROLE_LEVEL_DENY_CODES,
};

module.exports = {
    ...decideCore,
    ...loaders,
    ...canonicalizeCore,
    ...normalizeCore,
    ...deepInspect,
    ...messagesCore,
    runDecision,
    computeParamsHash,
    canonicalJson,
    createCliEnforcer,
    createToolCallHook,
    createMcpGate,
    ROLE_LEVEL_DENY_CODES,
    enforcers,
};
