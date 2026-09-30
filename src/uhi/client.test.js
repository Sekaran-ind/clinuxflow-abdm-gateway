import { describe, expect, it } from 'vitest';
import { Hono } from 'hono';
import { generateKeyPair } from './crypto.js';
import { ackResponse } from './protocol.js';
import { RegistryLookupClient, createStaticKeyResolver, signedPost, verifyUhiSignature } from './client.js';
import { publicKeyFromPrivate } from './config.js';

/** A fetch that dispatches to a Hono app in-process. */
const appFetch = (app) => (url, init) => app.request(url, init);

describe('createStaticKeyResolver', () => {
    it('resolves configured keys only', async () => {
        const resolver = createStaticKeyResolver([{ subscriberId: 'a', pubKeyId: 'k1', publicKeyDer: 'PUBKEY' }]);
        expect(await resolver('a', 'k1')).toBe('PUBKEY');
        expect(await resolver('a', 'k2')).toBeUndefined();
        expect(await resolver('b', 'k1')).toBeUndefined();
    });
});

describe('publicKeyFromPrivate', () => {
    it('derives the matching SPKI public key', () => {
        const keys = generateKeyPair();
        expect(publicKeyFromPrivate(keys.privateKeyDer)).toBe(keys.publicKeyDer);
    });
});

describe('signedPost + verifyUhiSignature', () => {
    function buildApp(resolver) {
        const app = new Hono();
        app.post('/search', verifyUhiSignature(() => resolver), (c) => {
            expect(c.get('uhiBody').message.intent).toEqual({});
            expect(c.get('uhiSender')).toBe('eua-test.example.com');
            return c.json(ackResponse());
        });
        return app;
    }

    it('accepts a correctly signed request', async () => {
        const keys = generateKeyPair();
        const identity = { subscriberId: 'eua-test.example.com', pubKeyId: 'k1', privateKeyDer: keys.privateKeyDer };
        const app = buildApp(createStaticKeyResolver([{ subscriberId: identity.subscriberId, pubKeyId: 'k1', publicKeyDer: keys.publicKeyDer }]));
        const response = await signedPost('http://hspa.test/search', { context: { action: 'search' }, message: { intent: {} } }, identity, {
            fetchImpl: appFetch(app),
        });
        expect(response).toEqual({ message: { ack: { status: 'ACK' } } });
    });

    it('rejects a request signed by an unregistered key', async () => {
        const identity = { subscriberId: 'eua-test.example.com', pubKeyId: 'k1', privateKeyDer: generateKeyPair().privateKeyDer };
        const app = buildApp(createStaticKeyResolver([]));
        await expect(
            signedPost('http://hspa.test/search', { context: { action: 'search' }, message: { intent: {} } }, identity, { fetchImpl: appFetch(app) }),
        ).rejects.toThrow(/status 401/);
    });

    it('rejects an unsigned request with the UHI-1405 NACK body', async () => {
        const res = await buildApp(createStaticKeyResolver([])).request('/search', { method: 'POST', body: '{}' });
        expect(res.status).toBe(401);
        expect((await res.json()).error.code).toBe('UHI-1405');
    });
});

describe('RegistryLookupClient', () => {
    const identity = { subscriberId: 'eua-test.example.com', pubKeyId: 'k1', privateKeyDer: generateKeyPair().privateKeyDer };
    const options = (fetchImpl, extra = {}) => ({ baseUrl: 'https://registry.invalid', identity, domain: 'nic2004:85111', country: 'IND', city: 'std:011', fetchImpl, ...extra });
    const subscriber = (validUntilMs) =>
        new Response(JSON.stringify({ subscriber_id: 'hspa-nha', pub_key_id: 'k1', signing_public_key: 'HSPA-PUBKEY', valid_until: new Date(validUntilMs).toISOString() }), {
            status: 200,
        });

    it('caches a resolved key within its validity window', async () => {
        let calls = 0;
        const client = new RegistryLookupClient(options(async () => (calls++, subscriber(Date.now() + 60_000))));
        expect(await client.resolvePublicKey('hspa-nha', 'k1')).toBe('HSPA-PUBKEY');
        expect(await client.resolvePublicKey('hspa-nha', 'k1')).toBe('HSPA-PUBKEY');
        expect(calls).toBe(1);
    });

    it('signs the lookup request itself', async () => {
        let authorization;
        const client = new RegistryLookupClient(
            options(async (_url, init) => {
                authorization = JSON.parse(init.headers.authorization);
                return subscriber(Date.now() + 60_000);
            }),
        );
        await client.resolvePublicKey('hspa-nha', 'k1');
        expect(authorization.keyId).toBe('eua-test.example.com|k1|ed25519');
    });

    it('returns undefined on a 404 without throwing', async () => {
        const client = new RegistryLookupClient(options(async () => new Response('{}', { status: 404 })));
        expect(await client.resolvePublicKey('unknown', 'k1')).toBeUndefined();
    });

    it("re-fetches once the entry's valid_until has passed", async () => {
        let calls = 0;
        const client = new RegistryLookupClient(options(async () => (calls++, subscriber(Date.now() - 1000))));
        await client.resolvePublicKey('hspa-nha', 'k1');
        await client.resolvePublicKey('hspa-nha', 'k1');
        expect(calls).toBe(2);
    });

    it('shares the cache across isolates through KV', async () => {
        const kvData = new Map();
        const kv = { get: async (k) => (kvData.has(k) ? JSON.parse(kvData.get(k)) : null), put: async (k, v) => void kvData.set(k, v) };
        let calls = 0;
        const fetchImpl = async () => (calls++, subscriber(Date.now() + 10 * 60_000));
        await new RegistryLookupClient(options(fetchImpl, { kv })).resolvePublicKey('hspa-nha', 'k1');
        // a second client stands in for another isolate with an empty in-memory cache
        expect(await new RegistryLookupClient(options(fetchImpl, { kv })).resolvePublicKey('hspa-nha', 'k1')).toBe('HSPA-PUBKEY');
        expect(calls).toBe(1);
    });
});
