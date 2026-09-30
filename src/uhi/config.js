// UHI configuration from Worker env vars.
//
//   UHI_GATEWAY_MODE        'local' (default) or 'sandbox'.
//                           local: EUA calls this Worker's own HSPA directly and keys come from
//                           config; sandbox: search goes through the NHA UHI gateway and keys are
//                           resolved from its network registry.
//   UHI_PUBLIC_BASE_URL     this Worker's public origin (e.g. https://abdm-gw.example.com). The
//                           HSPA advertises `${base}/uhi/hspa` as provider_uri and the EUA
//                           advertises `${base}/uhi/eua` as consumer_uri. Falls back to the
//                           request's own origin, which is right for local dev and tests.
//   UHI_DOMAIN / UHI_COUNTRY / UHI_CITY   network scope (defaults nic2004:85111 / IND / std:011)
//   UHI_REGISTRY_BASE_URL, UHI_GATEWAY_BASE_URL   default https://uhigatewaysandbox.abdm.gov.in
//   UHI_HSPA_SUBSCRIBER_ID, UHI_HSPA_PUB_KEY_ID, UHI_HSPA_PRIVATE_KEY_DER (secret)
//   UHI_EUA_SUBSCRIBER_ID,  UHI_EUA_PUB_KEY_ID,  UHI_EUA_PRIVATE_KEY_DER  (secret)
//   UHI_LOCAL_PEERS         local mode only, optional JSON array of extra trusted keys:
//                           [{ "subscriberId", "pubKeyId", "publicKeyDer" }]
//
// A role whose private key is not configured is disabled (its routes answer 503).

import { createPrivateKey, createPublicKey } from 'node:crypto';

const SANDBOX = 'https://uhigatewaysandbox.abdm.gov.in';

export function publicKeyFromPrivate(privateKeyDer) {
    const priv = createPrivateKey({ key: Buffer.from(privateKeyDer, 'base64'), format: 'der', type: 'pkcs8' });
    return createPublicKey(priv).export({ format: 'der', type: 'spki' }).toString('base64');
}

function role(env, prefix, defaultSubscriber) {
    const privateKeyDer = env[`UHI_${prefix}_PRIVATE_KEY_DER`] || '';
    if (!privateKeyDer) return null;
    return {
        subscriberId: env[`UHI_${prefix}_SUBSCRIBER_ID`] || defaultSubscriber,
        pubKeyId: env[`UHI_${prefix}_PUB_KEY_ID`] || 'k1',
        privateKeyDer,
    };
}

/** @param {Record<string, any>} env @param {string} requestUrl */
export function loadUhiConfig(env, requestUrl) {
    const mode = env.UHI_GATEWAY_MODE === 'sandbox' ? 'sandbox' : 'local';
    const base = (env.UHI_PUBLIC_BASE_URL || new URL(requestUrl).origin).replace(/\/+$/, '');
    const hspa = role(env, 'HSPA', 'hspa-local.example.com');
    const eua = role(env, 'EUA', 'eua-local.example.com');

    let localPeers = [];
    if (mode === 'local') {
        for (const identity of [hspa, eua]) {
            if (identity) {
                localPeers.push({
                    subscriberId: identity.subscriberId,
                    pubKeyId: identity.pubKeyId,
                    publicKeyDer: publicKeyFromPrivate(identity.privateKeyDer),
                });
            }
        }
        if (env.UHI_LOCAL_PEERS) {
            try {
                localPeers = localPeers.concat(JSON.parse(env.UHI_LOCAL_PEERS));
            } catch {
                console.warn('[uhi] UHI_LOCAL_PEERS is not valid JSON; ignoring it');
            }
        }
    }

    return {
        mode,
        domain: env.UHI_DOMAIN || 'nic2004:85111',
        country: env.UHI_COUNTRY || 'IND',
        city: env.UHI_CITY || 'std:011',
        registryBaseUrl: (env.UHI_REGISTRY_BASE_URL || SANDBOX).replace(/\/+$/, ''),
        gatewayBaseUrl: (env.UHI_GATEWAY_BASE_URL || SANDBOX).replace(/\/+$/, ''),
        hspa: hspa && { identity: hspa, baseUrl: `${base}/uhi/hspa` },
        eua: eua && { identity: eua, baseUrl: `${base}/uhi/eua`, localHspaUrl: env.UHI_LOCAL_HSPA_URL || `${base}/uhi/hspa` },
        localPeers,
    };
}
