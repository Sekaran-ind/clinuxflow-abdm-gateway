// Signed UHI HTTP client, network-registry key lookup, and inbound signature verification.
// Ported from clinux-uhi-gateway's packages/uhi-client (Express middleware → Hono).

import { buildAuthorizationHeader, verifyAuthorizationHeader } from './crypto.js';
import { ERROR_CODES, ResponseSchema, SubscriberDtoSchema, extractSigningPublicKey, nackResponse } from './protocol.js';

export class UhiRequestError extends Error {
    constructor(message, status, body) {
        super(message);
        this.name = 'UhiRequestError';
        this.status = status;
        this.body = body;
    }
}

/**
 * Signs and POSTs a UHI envelope. The body is serialized once so the digest matches the exact
 * bytes sent.
 * @param {string} url
 * @param {{ context: object, message: object, error?: object }} envelope
 * @param {{ subscriberId: string, pubKeyId: string, privateKeyDer: string }} identity
 * @param {{ ttlSeconds?: number, timeoutMs?: number, fetchImpl?: typeof fetch }} [options]
 */
export async function signedPost(url, envelope, identity, options = {}) {
    const body = JSON.stringify(envelope);
    const authorization = buildAuthorizationHeader({ ...identity, body, ttlSeconds: options.ttlSeconds });
    const fetchImpl = options.fetchImpl ?? fetch;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
    try {
        const res = await fetchImpl(url, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization },
            body,
            signal: controller.signal,
        });
        const text = await res.text();
        let parsed;
        try {
            parsed = text ? JSON.parse(text) : {};
        } catch {
            throw new UhiRequestError(`${url} returned non-JSON response (status ${res.status})`, res.status, text);
        }
        if (!res.ok) throw new UhiRequestError(`${url} responded with status ${res.status}`, res.status, parsed);
        return ResponseSchema.parse(parsed);
    } finally {
        clearTimeout(timeout);
    }
}

/** A resolver over a fixed list of known keys (local mode: no real network registry). */
export function createStaticKeyResolver(entries) {
    const byKey = new Map(entries.map((e) => [`${e.subscriberId}|${e.pubKeyId}`, e.publicKeyDer]));
    return async (subscriberId, pubKeyId) => byKey.get(`${subscriberId}|${pubKeyId}`);
}

/**
 * Resolves subscribers' signing public keys via POST {baseUrl}/api/v1/networkregistry/lookup.
 * Caches in memory (per isolate) and, when a KV namespace is given, in KV so every isolate
 * benefits, honouring the subscriber's `valid_until` where present.
 */
export class RegistryLookupClient {
    constructor(options) {
        this.options = options;
        this.cache = new Map();
        this.fetchImpl = options.fetchImpl ?? fetch;
        this.resolvePublicKey = this.resolvePublicKey.bind(this);
    }

    async resolvePublicKey(subscriberId, pubKeyId) {
        const cacheKey = `${subscriberId}|${pubKeyId}`;
        const cached = this.cache.get(cacheKey);
        if (cached && cached.expiresAtMs > Date.now()) return cached.publicKeyDer;

        const kvKey = `uhi:registry:${cacheKey}`;
        if (this.options.kv) {
            const hit = await this.options.kv.get(kvKey, 'json');
            if (hit && hit.expiresAtMs > Date.now()) {
                this.cache.set(cacheKey, hit);
                return hit.publicKeyDer;
            }
        }

        const body = JSON.stringify({
            subscriber_id: subscriberId,
            pub_key_id: pubKeyId,
            domain: this.options.domain,
            country: this.options.country,
            city: this.options.city,
        });
        const authorization = buildAuthorizationHeader({ ...this.options.identity, body });
        const res = await this.fetchImpl(`${this.options.baseUrl}/api/v1/networkregistry/lookup`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization },
            body,
        });
        if (res.status === 404) return undefined;
        if (!res.ok) throw new Error(`registry lookup for ${cacheKey} failed with status ${res.status}`);

        const subscriber = SubscriberDtoSchema.parse(await res.json());
        const publicKeyDer = extractSigningPublicKey(subscriber);
        if (!publicKeyDer) return undefined;

        const expiresAtMs = subscriber.valid_until
            ? Date.parse(subscriber.valid_until)
            : Date.now() + (this.options.cacheTtlMsFallback ?? 5 * 60_000);
        const entry = { publicKeyDer, expiresAtMs };
        this.cache.set(cacheKey, entry);
        const ttlSeconds = Math.floor((expiresAtMs - Date.now()) / 1000);
        // KV requires expirationTtl >= 60s; shorter-lived entries stay in the isolate cache only.
        if (this.options.kv && ttlSeconds >= 60) {
            await this.options.kv.put(kvKey, JSON.stringify(entry), { expirationTtl: ttlSeconds });
        }
        return publicKeyDer;
    }
}

const REASON_MESSAGE = {
    'malformed-header': 'MALFORMED AUTHORIZATION HEADER',
    'key-not-found': 'SUBSCRIBER PUBLIC KEY NOT FOUND',
    expired: 'SIGNATURE EXPIRED',
    'not-yet-valid': 'SIGNATURE NOT YET VALID',
    'signature-mismatch': 'INVALID SIGNATURE',
    'algorithm-mismatch': 'UNSUPPORTED SIGNING ALGORITHM',
};

/**
 * Hono middleware: verifies the inbound Authorization (or, on the Gateway's first search hop,
 * X-Gateway-Authorization) header against the exact raw body, then exposes the raw body and the
 * parsed JSON to handlers as c.get('uhiRawBody') / c.get('uhiBody'). This is the ONLY
 * authentication on the network-facing UHI routes: the NHA gateway and other participants never
 * hold a ClinuxFlow session or our service key.
 * @param {(c) => (subscriberId: string, pubKeyId: string) => Promise<string|undefined>} getResolver
 */
export function verifyUhiSignature(getResolver) {
    return async (c, next) => {
        const header = c.req.header('authorization') ?? c.req.header('x-gateway-authorization');
        const rawBody = await c.req.text();
        const path = new URL(c.req.url).pathname;

        if (!header) {
            return c.json(nackResponse({ type: '', code: ERROR_CODES.UNAUTHORISED, path, message: 'MISSING AUTHORIZATION HEADER' }), 401);
        }
        const result = await verifyAuthorizationHeader({ header, body: rawBody, resolvePublicKey: getResolver(c) });
        if (!result.valid) {
            return c.json(nackResponse({ type: '', code: ERROR_CODES.UNAUTHORISED, path, message: REASON_MESSAGE[result.reason] }), 401);
        }

        let body;
        try {
            body = JSON.parse(rawBody);
        } catch {
            return c.json(nackResponse({ type: '', code: 'UHI-BAD-REQUEST', path, message: 'BODY IS NOT JSON' }), 400);
        }
        c.set('uhiRawBody', rawBody);
        c.set('uhiBody', body);
        c.set('uhiSender', result.subscriberId);
        return next();
    };
}
