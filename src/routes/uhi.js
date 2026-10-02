// UHI (Unified Health Interface) routes, merged in from the former clinux-uhi-gateway repo.
//
// Two trust boundaries share this prefix and must never be mixed:
//
//   Network-facing  /uhi/hspa/{search,select,init,confirm,status,cancel}
//                   /uhi/eua/{on_search,on_select,...,on_update,on_message}
//     Called by the NHA UHI gateway and other network participants. Authenticated ONLY by the
//     UHI message signature (Ed25519 over BLAKE2b-512, keys from the network registry, or from
//     config in local mode). No service key, no ClinuxFlow session.
//
//   Operator        /uhi/hspa/internal/*, /uhi/eua/internal/*
//     Driven by signed-in ClinuxFlow users. Service key + ClinuxFlow session + per-account rate
//     limit, like the ABDM routes. HSPA operator routes are further restricted to the clinics
//     in UHI_HSPA_OPERATOR_CLINIC_IDS (the HSPA identity is shared by the whole deployment).

import { Hono } from 'hono';
import { serviceKeyAuth } from '../lib/serviceAuth.js';
import { requireClinuxSession } from '../lib/userSession.js';
import { recordAbdmTransactions } from '../lib/transactionLog.js';
import { rateLimit } from '../lib/rateLimit.js';
import { EUA_INBOUND_ACTIONS, HSPA_INBOUND_ACTIONS, PUSH_ACTIONS } from '../uhi/protocol.js';
import { loadUhiConfig } from '../uhi/config.js';
import { RegistryLookupClient, createStaticKeyResolver, verifyUhiSignature } from '../uhi/client.js';
import { getRecordStore } from '../uhi/stores.js';
import { buildHspaInternalRoutes, buildHspaPublicRoutes } from '../uhi/hspa/routes.js';
import { buildEuaInternalRoutes, buildEuaPublicRoutes } from '../uhi/eua/routes.js';

// Test seam only: unit tests set env.UHI_FETCH_OVERRIDE to route outbound calls back into the
// app in-process. Never configured in wrangler.toml.
const fetchFor = (env) => env.UHI_FETCH_OVERRIDE ?? fetch;

// One registry client per signing identity per isolate, so its in-memory cache survives between
// requests (KV backs it across isolates).
const registryClients = new Map();

function keyResolver(c, config, identity) {
    if (config.mode === 'local') return createStaticKeyResolver(config.localPeers);
    const cacheKey = `${identity.subscriberId}|${config.registryBaseUrl}`;
    let client = registryClients.get(cacheKey);
    if (!client) {
        client = new RegistryLookupClient({
            baseUrl: config.registryBaseUrl,
            identity,
            domain: config.domain,
            country: config.country,
            city: config.city,
            kv: c.env.MASTER_DATA_CACHE,
            fetchImpl: fetchFor(c.env),
        });
        registryClients.set(cacheKey, client);
    }
    return client.resolvePublicKey;
}

function configFor(c) {
    let config = c.get('uhiConfig');
    if (!config) {
        config = loadUhiConfig(c.env, c.req.url);
        c.set('uhiConfig', config);
    }
    return config;
}

function hspaDeps(c) {
    const config = configFor(c);
    if (!config.hspa) return null;
    return { config, identity: config.hspa.identity, baseUrl: config.hspa.baseUrl, store: getRecordStore(c.env), fetchImpl: fetchFor(c.env) };
}

export function euaDeps(c) {
    const config = configFor(c);
    if (!config.eua) return null;
    return {
        config,
        identity: config.eua.identity,
        baseUrl: config.eua.baseUrl,
        localHspaUrl: config.eua.localHspaUrl,
        store: getRecordStore(c.env),
        fetchImpl: fetchFor(c.env),
    };
}

/** Resolves keys with whichever of this gateway's identities is receiving the call. */
function resolverFor(role) {
    return (c) => {
        const config = configFor(c);
        const identity = config[role]?.identity ?? config.hspa?.identity ?? config.eua?.identity;
        if (!identity) return async () => undefined;
        return keyResolver(c, config, identity);
    };
}

function requireHspaOperator() {
    return async (c, next) => {
        const allowed = String(c.env.UHI_HSPA_OPERATOR_CLINIC_IDS || '')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
        if (!allowed.includes(c.get('user').clinicId)) {
            return c.json({ error: 'Not permitted to operate this gateway’s HSPA' }, 403);
        }
        return next();
    };
}

export const uhiRoutes = new Hono();

const operatorGate = [
    serviceKeyAuth(),
    requireClinuxSession(),
    rateLimit({ bucket: 'uhi', limit: 120, windowSeconds: 60 }),
    recordAbdmTransactions('uhi'),
];
uhiRoutes.use('/hspa/internal/*', ...operatorGate, requireHspaOperator());
uhiRoutes.use('/eua/internal/*', ...operatorGate);

for (const action of HSPA_INBOUND_ACTIONS) {
    uhiRoutes.use(`/hspa/${action}`, verifyUhiSignature(resolverFor('hspa')));
}
for (const action of [...EUA_INBOUND_ACTIONS, ...PUSH_ACTIONS]) {
    uhiRoutes.use(`/eua/${action}`, verifyUhiSignature(resolverFor('eua')));
}

uhiRoutes.route('/hspa/internal', buildHspaInternalRoutes(hspaDeps));
uhiRoutes.route('/eua/internal', buildEuaInternalRoutes(euaDeps));
uhiRoutes.route('/hspa', buildHspaPublicRoutes(hspaDeps));
uhiRoutes.route('/eua', buildEuaPublicRoutes(euaDeps));
