'use strict';

const { normalizeForMatch } = require('../../src/core/normalize');

const BLOCKED_HA_ACTIONS = new Set([
    'homeassistant.restart',
    'homeassistant.stop',
    'homeassistant.reload_core',
    'hassio.host_reboot',
    'hassio.host_shutdown',
]);

const BARE_HASSIO_ACTIONS = new Set([
    'addon_stop',
    'addon_restart',
    'addon_uninstall',
    'addon_update',
    'host_reboot',
    'host_shutdown',
    'supervisor_update',
    'backup_full',
    'backup_partial',
    'restore_full',
    'restore_partial',
]);

const BARE_HA_ACTIONS = new Set([
    'restart',
    'stop',
    'reload_core',
    ...BARE_HASSIO_ACTIONS,
]);

const BLOCKED_HA_TOOLS = new Set([
    'ha_restart',
    'ha_stop',
    'ha_reload_core',
    'ha:ha_restart',
    'ha:ha_stop',
    'ha:ha_reload_core',
    'ha:restart',
    'ha:stop',
    'ha:reload_core',
    'restart',
    'stop',
    'reload_core',
    'mcp__ha-mcp__ha_restart',
    'mcp__ha-mcp__ha_stop',
    'mcp__ha-mcp__ha_reload_core',
    'mcp__homeassistant__ha_restart',
    'mcp__homeassistant__ha_stop',
    'mcp__homeassistant__ha_reload_core',
]);

for (const act of BARE_HASSIO_ACTIONS) {
    BLOCKED_HA_TOOLS.add(act);
    BLOCKED_HA_TOOLS.add(`ha_${act}`);
    BLOCKED_HA_TOOLS.add(`ha:${act}`);
    BLOCKED_HA_TOOLS.add(`ha:ha_${act}`);
    BLOCKED_HA_TOOLS.add(`mcp__ha-mcp__${act}`);
    BLOCKED_HA_TOOLS.add(`mcp__ha-mcp__ha_${act}`);
    BLOCKED_HA_TOOLS.add(`mcp__homeassistant__${act}`);
    BLOCKED_HA_TOOLS.add(`mcp__homeassistant__ha_${act}`);
}

function matchServer(server) {
    if (!server || typeof server !== 'string') return false;
    const s = server.toLowerCase().trim().replace(/_/g, '-');
    return s === 'ha' || s === 'ha-mcp' || s === 'homeassistant';
}

function shouldBypass(roleDef) {
    if (!roleDef) return false;
    if (roleDef.allowHaRestart === true) return true;
    if (Array.isArray(roleDef.bypassDomainGuards) && roleDef.bypassDomainGuards.includes('home-assistant')) return true;
    return false;
}

function isBlockedHaTool(name, toolTable = {}) {
    if (!name || typeof name !== 'string') return false;
    const lower = name.toLowerCase().trim();
    const norm = normalizeForMatch(name);
    if (BLOCKED_HA_TOOLS.has(lower) || BLOCKED_HA_TOOLS.has(norm)) return true;

    // Check canonical resolution
    let curTool = lower;
    if (curTool.startsWith('ha:')) curTool = curTool.slice(3);
    else if (curTool.startsWith('mcp__ha-mcp__')) curTool = curTool.slice(13);
    else if (curTool.startsWith('mcp__homeassistant__')) curTool = curTool.slice(20);
    else if (curTool.startsWith('mcp:ha-mcp:')) curTool = curTool.slice(11);
    else if (curTool.startsWith('mcp:homeassistant:')) curTool = curTool.slice(18);

    let normTool = norm;
    if (normTool.startsWith('ha:')) normTool = normTool.slice(3);
    else if (normTool.startsWith('mcp__ha-mcp__')) normTool = normTool.slice(13);
    else if (normTool.startsWith('mcp__homeassistant__')) normTool = normTool.slice(20);
    else if (normTool.startsWith('mcp:ha-mcp:')) normTool = normTool.slice(11);
    else if (normTool.startsWith('mcp:homeassistant:')) normTool = normTool.slice(18);

    if (BLOCKED_HA_TOOLS.has(curTool) || BLOCKED_HA_TOOLS.has(normTool)) return true;
    if (BLOCKED_HA_TOOLS.has(`ha:${curTool}`) || BLOCKED_HA_TOOLS.has(`ha:${normTool}`)) return true;
    return false;
}

function normalizeStringOrArray(val) {
    if (val === undefined || val === null) return { ok: true, values: [] };
    if (typeof val === 'string') return { ok: true, values: [val.toLowerCase().trim()] };
    if (Array.isArray(val)) {
        const result = [];
        for (const item of val) {
            if (typeof item !== 'string') return { ok: false, error: 'ha_params_invalid: Invalid HA parameters blocked (fail-closed)' };
            result.push(item.toLowerCase().trim());
        }
        return { ok: true, values: result };
    }
    return { ok: false, error: 'ha_params_invalid: Invalid HA parameters blocked (fail-closed)' };
}

function getMsg(code, defaultText, ctx = {}) {
    const messages = ctx.messages || {};
    if (messages && messages[code]) {
        return messages[code];
    }
    return defaultText;
}

const haDomainGuard = {
    name: 'home-assistant',
    canonicalServer: 'ha',
    effectiveServerName: 'ha-mcp',
    prefixes: ['ha'],
    serverAliases: {
        'ha': 'ha',
        'ha-mcp': 'ha',
        'homeassistant': 'ha',
    },
    blockedTools: BLOCKED_HA_TOOLS,

    matchServer,

    resolveToolCanonical(toolName) {
        if (typeof toolName === 'string' && toolName.startsWith('ha_')) {
            return { server: 'ha-mcp', canonical: `ha:${toolName}` };
        }
        return null;
    },

    formatCanonical(server, tool) {
        return `ha:${tool}`;
    },

    getToolCategory(toolName, canonTool) {
        if (typeof canonTool === 'string' && canonTool.startsWith('ha:')) {
            const lowerCanon = canonTool.toLowerCase();
            if (lowerCanon.includes('config_') || lowerCanon.includes('config')) return 'ha_config';
            if (lowerCanon.includes('call_service') || lowerCanon.includes('bulk_control') || lowerCanon.includes('call_event')) return 'ha_control';
            return 'ha_read';
        }
        return null;
    },

    matchTool(normTool, entry) {
        if (typeof normTool === 'string' && typeof entry === 'string' &&
            normTool.startsWith('ha:') && entry.startsWith('ha:')) {
            const tName = normTool.slice(3);
            const eName = entry.slice(3);
            if (eName === '*') return true;
            const normT = tName.startsWith('ha_') ? tName.slice(3) : tName;
            const normE = eName.startsWith('ha_') ? eName.slice(3) : eName;
            if (normT === normE) return true;
        }
        return false;
    },

    inspectTool(normTool, effectiveToolName, effectiveParams, roleDef, ctx = {}) {
        if (shouldBypass(roleDef)) return null;

        const isHa = (typeof normTool === 'string' && normTool.startsWith('ha:')) ||
            (ctx.effectiveServer === 'ha-mcp') ||
            (typeof effectiveToolName === 'string' && effectiveToolName.startsWith('ha_'));

        if (isHa && effectiveParams !== undefined && effectiveParams !== null) {
            if (typeof effectiveParams !== 'object' || Array.isArray(effectiveParams)) {
                return {
                    blocked: true,
                    code: 'ha_params_invalid',
                    reason: getMsg('ha_params_invalid_type', 'ha_params_invalid: HA tool parameters blocked (cannot be a number, top-level array, or primitive type; fail-closed)', ctx),
                };
            }
        }

        if (isBlockedHaTool(normTool, ctx.toolTable) || (effectiveToolName && isBlockedHaTool(effectiveToolName, ctx.toolTable))) {
            const isHassio = (normTool && (normTool.includes('hassio') || [...BARE_HASSIO_ACTIONS].some(a => normTool.includes(a)))) ||
                (effectiveToolName && (effectiveToolName.includes('hassio') || [...BARE_HASSIO_ACTIONS].some(a => effectiveToolName.includes(a))));
            const code = isHassio ? 'ha_domain_blocked:hassio' : 'ha_restart_blocked';
            const defaultReason = isHassio
                ? 'ha_domain_blocked:hassio: Services from hassio domain are blocked.'
                : 'homeassistant.restart is blocked.';
            return {
                blocked: true,
                code,
                reason: getMsg(code, defaultReason, ctx),
            };
        }

        return null;
    },

    inspect(node, ctx = {}) {
        if (shouldBypass(ctx.roleDef)) return null;
        if (!node || typeof node !== 'object') return null;

        const rawKeys = Object.keys(node);

        // Check operations JSON string (e.g. in ha_bulk_control)
        const opKey = rawKeys.find(k => k.toLowerCase().trim() === 'operations');
        if (opKey && typeof node[opKey] === 'string') {
            let opParsed;
            try {
                opParsed = JSON.parse(node[opKey].trim());
            } catch (_) {
                return {
                    blocked: true,
                    code: 'ha_params_invalid',
                    reason: getMsg('ha_params_invalid_operations', 'ha_params_invalid: Invalid JSON in operations blocked (fail-closed)', ctx),
                };
            }
            if (typeof ctx.walk === 'function') {
                const r = ctx.walk(opParsed, { currentDomain: ctx.currentDomain });
                if (r.blocked) return r;
            }
        }

        const domainVals = [];
        const serviceVals = [];
        const actionVals = [];

        for (const k of rawKeys) {
            const lowerK = k.toLowerCase().trim();
            const normK = normalizeForMatch(k);
            if (lowerK === 'domain' || normK === 'domain') {
                const norm = normalizeStringOrArray(node[k]);
                if (!norm.ok) return { blocked: true, code: 'ha_params_invalid', reason: norm.error };
                domainVals.push(...norm.values);
            } else if (lowerK === 'service' || normK === 'service') {
                const norm = normalizeStringOrArray(node[k]);
                if (!norm.ok) return { blocked: true, code: 'ha_params_invalid', reason: norm.error };
                serviceVals.push(...norm.values);
            } else if (lowerK === 'action' || normK === 'action') {
                const norm = normalizeStringOrArray(node[k]);
                if (!norm.ok) return { blocked: true, code: 'ha_params_invalid', reason: norm.error };
                actionVals.push(...norm.values);
            }
        }

        const domains = (domainVals.length > 0 ? domainVals : (ctx.currentDomain ? [ctx.currentDomain] : [''])).map(v => v.replace(/\s*\.\s*/g, '.'));
        const candidates = [...serviceVals, ...actionVals].map(v => v.replace(/\s*\.\s*/g, '.'));

        // 1. Block entire hassio domain:
        if (domains.some(d => d === 'hassio' || normalizeForMatch(d) === 'hassio')) {
            return {
                blocked: true,
                code: 'ha_domain_blocked:hassio',
                reason: getMsg('ha_domain_blocked:hassio', 'ha_domain_blocked:hassio: Services from hassio domain are blocked.', ctx),
            };
        }

        // 2. Block actions with hassio. prefix or bare hassio:
        for (const s of candidates) {
            const normS = normalizeForMatch(s);
            const sDomain = s.includes('.') ? s.split('.')[0] : '';
            const normSDomain = normS.includes('.') ? normS.split('.')[0] : '';
            if (s.startsWith('hassio.') || normS.startsWith('hassio.') ||
                sDomain === 'hassio' || normSDomain === 'hassio' ||
                BARE_HASSIO_ACTIONS.has(s) || BARE_HASSIO_ACTIONS.has(normS)) {
                return {
                    blocked: true,
                    code: 'ha_domain_blocked:hassio',
                    reason: getMsg('ha_domain_blocked:hassio', 'ha_domain_blocked:hassio: Services from hassio domain are blocked.', ctx),
                };
            }
        }

        // 3. Check homeassistant restart/stop/reload_core & BLOCKED_HA_ACTIONS:
        for (const dom of domains) {
            const normDom = normalizeForMatch(dom);
            for (const s of candidates) {
                const normS = normalizeForMatch(s);
                if (s === 'homeassistant.restart' || s === 'homeassistant.stop' || s === 'homeassistant.reload_core' ||
                    normS === 'homeassistant.restart' || normS === 'homeassistant.stop' || normS === 'homeassistant.reload_core' ||
                    (dom && (BLOCKED_HA_ACTIONS.has(`${dom}.${s}`) || BLOCKED_HA_ACTIONS.has(`${dom}.${normS}`))) ||
                    (normDom && (BLOCKED_HA_ACTIONS.has(`${normDom}.${s}`) || BLOCKED_HA_ACTIONS.has(`${normDom}.${normS}`))) ||
                    ((dom === 'homeassistant' || normDom === 'homeassistant') &&
                        (s === 'restart' || s === 'stop' || s === 'reload_core' ||
                         normS === 'restart' || normS === 'stop' || normS === 'reload_core'))) {
                    return {
                        blocked: true,
                        code: 'ha_restart_blocked',
                        reason: getMsg('ha_restart_blocked', 'homeassistant.restart is blocked.', ctx),
                    };
                }
            }
        }

        // Determine effective domain for nested nodes
        let effectiveDomain = ctx.currentDomain ? normalizeForMatch(ctx.currentDomain) : ctx.currentDomain;
        const foundDom = domainVals.find(d => {
            const nd = normalizeForMatch(d);
            return nd === 'homeassistant' || nd === 'hassio';
        });
        if (foundDom) {
            effectiveDomain = normalizeForMatch(foundDom);
        } else {
            const foundCandidate = candidates.find(c => {
                const nc = normalizeForMatch(c);
                return nc.startsWith('homeassistant.') || nc.startsWith('hassio.');
            });
            if (foundCandidate) {
                effectiveDomain = normalizeForMatch(foundCandidate).split('.')[0];
            } else if (domainVals.length > 0 && domainVals[0]) {
                effectiveDomain = normalizeForMatch(domainVals[0]);
            }
        }

        // Inspection of toolName and name keys
        for (const k of rawKeys) {
            const lowerK = k.toLowerCase().trim();
            if (lowerK === 'toolname' || lowerK === 'tool') {
                const rawName = node[k];
                if (typeof rawName === 'string' && rawName.trim()) {
                    const trimmed = rawName.trim();
                    if (isBlockedHaTool(trimmed, ctx.toolTable)) {
                        return {
                            blocked: true,
                            code: 'ha_restart_blocked',
                            reason: getMsg('ha_restart_blocked', 'homeassistant.restart is blocked.', ctx),
                        };
                    }
                }
            } else if (lowerK === 'name') {
                const rawName = node[k];
                if (typeof rawName === 'string' && rawName.trim()) {
                    const trimmed = rawName.trim();
                    const lowerName = trimmed.toLowerCase();
                    const normName = normalizeForMatch(trimmed);

                    if ((isBlockedHaTool(trimmed, ctx.toolTable) || isBlockedHaTool(normName, ctx.toolTable)) &&
                        !BARE_HA_ACTIONS.has(lowerName) && !BARE_HA_ACTIONS.has(normName)) {
                        return {
                            blocked: true,
                            code: 'ha_restart_blocked',
                            reason: getMsg('ha_restart_blocked', 'homeassistant.restart is blocked.', ctx),
                        };
                    }

                    if (BARE_HA_ACTIONS.has(lowerName) || BARE_HA_ACTIONS.has(normName)) {
                        const matchedAction = BARE_HA_ACTIONS.has(lowerName) ? lowerName : normName;
                        if (effectiveDomain === 'homeassistant' || effectiveDomain === 'hassio' || BARE_HASSIO_ACTIONS.has(matchedAction)) {
                            const isHassioAction = (effectiveDomain === 'hassio' || BARE_HASSIO_ACTIONS.has(matchedAction));
                            const code = isHassioAction ? 'ha_domain_blocked:hassio' : 'ha_restart_blocked';
                            const defReason = isHassioAction
                                ? 'ha_domain_blocked:hassio: Services from hassio domain are blocked.'
                                : 'homeassistant.restart is blocked.';
                            return {
                                blocked: true,
                                code,
                                reason: getMsg(code, defReason, ctx),
                            };
                        }
                    }
                }
            }
        }

        // Check event_type
        const evtKey = rawKeys.find(k => {
            const lk = k.toLowerCase().trim();
            return lk === 'event_type' || normalizeForMatch(k) === 'event_type';
        });
        if (evtKey) {
            const normEvt = normalizeStringOrArray(node[evtKey]);
            if (!normEvt.ok) return { blocked: true, code: 'ha_params_invalid', reason: 'ha_params_invalid: Invalid HA event parameters blocked' };
            for (const et of normEvt.values) {
                const normEt = normalizeForMatch(et);
                if (normEt.includes('homeassistant_stop') || normEt.includes('homeassistant_restart') || normEt.includes('homeassistant_final_write') ||
                    et.includes('homeassistant_stop') || et.includes('homeassistant_restart') || et.includes('homeassistant_final_write')) {
                    return {
                        blocked: true,
                        code: 'ha_event_blocked',
                        reason: getMsg('ha_event_blocked', 'ha_event_blocked: Home Assistant stop or restart event is blocked', ctx),
                    };
                }
            }
        }

        const skipKeys = new Set();
        if (opKey && typeof node[opKey] === 'string') {
            skipKeys.add(opKey);
        }

        return {
            blocked: false,
            contextUpdate: {
                currentDomain: effectiveDomain,
                skipKeys,
            },
        };
    },

    getGuards(normTool, effectiveToolName, roleDef, ctx = {}) {
        let haGuardedList = [];
        if (roleDef && Array.isArray(roleDef.haGuardedTools)) {
            haGuardedList = roleDef.haGuardedTools;
        } else if (ctx.toolTable && Array.isArray(ctx.toolTable.haGuardedTools)) {
            haGuardedList = ctx.toolTable.haGuardedTools;
        }

        const matchFn = ctx.matchTool || ((t, e) => t === e);
        const isHaGuarded = haGuardedList.some(gt => matchFn(normTool, gt) || matchFn(effectiveToolName, gt));
        if (isHaGuarded && (ctx.role === 'ops' || ctx.role === 'cfg')) {
            return ['ha_guard'];
        }
        return [];
    },

    isHaRestartOrStop(toolName, params, toolTable = {}) {
        if (isBlockedHaTool(toolName, toolTable)) return true;
        if (!params) return false;
        const { deepInspectParams } = require('../../src/core/deepInspectParams');
        return Boolean(deepInspectParams(params, { domainGuards: [haDomainGuard], toolTable }).blocked);
    },
};

module.exports = haDomainGuard;
