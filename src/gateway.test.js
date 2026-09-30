// Gateway-level tests through the real entrypoint (src/index.js): the ABDM session gate and
// OTP rate limits (finding S3), and the merged UHI surface end to end, with the EUA and HSPA
// roles of this one Worker talking to each other in local mode. Outbound UHI calls are routed
// back into the app in-process via the UHI_FETCH_OVERRIDE test seam.

import { describe, expect, it } from 'vitest';
import { sign } from 'hono/jwt';
import app from './index.js';
import { buildAuthorizationHeader, generateKeyPair } from './uhi/crypto.js';
import { buildContext } from './uhi/protocol.js';

const BASE = 'http://gw.test';
const JWT_SECRET = 'test-jwt-secret';
const SERVICE_KEY = 'test-service-key';

function makeEnv(overrides = {}) {
    const hspa = generateKeyPair();
    const eua = generateKeyPair();
    const env = {
        SERVICE_KEY,
        JWT_SECRET,
        UHI_GATEWAY_MODE: 'local',
        UHI_HSPA_SUBSCRIBER_ID: 'hspa.gw.test',
        UHI_HSPA_PUB_KEY_ID: 'k1',
        UHI_HSPA_PRIVATE_KEY_DER: hspa.privateKeyDer,
        UHI_EUA_SUBSCRIBER_ID: 'eua.gw.test',
        UHI_EUA_PUB_KEY_ID: 'k1',
        UHI_EUA_PRIVATE_KEY_DER: eua.privateKeyDer,
        UHI_HSPA_OPERATOR_CLINIC_IDS: 'clinic-a',
        ...overrides,
    };
    env.UHI_FETCH_OVERRIDE = (url, init) => app.request(url, init, env);
    return { env, keys: { hspa, eua } };
}

async function sessionToken(accountId, clinicId, secret = JWT_SECRET) {
    const now = Math.floor(Date.now() / 1000);
    return sign({ sub: accountId, clinicId, email: `${accountId}@example.com`, iat: now, exp: now + 3600 }, secret, 'HS256');
}

async function call(env, method, path, { body, token, serviceKey = SERVICE_KEY, headers = {} } = {}) {
    const res = await app.request(
        `${BASE}${path}`,
        {
            method,
            headers: {
                'content-type': 'application/json',
                ...(serviceKey ? { 'X-Service-Key': serviceKey } : {}),
                ...(token ? { Authorization: `Bearer ${token}` } : {}),
                ...headers,
            },
            body: body === undefined ? undefined : JSON.stringify(body),
        },
        env,
    );
    const text = await res.text();
    return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : null };
}

async function waitFor(check, timeoutMs = 3000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const value = await check();
        if (value) return value;
        if (Date.now() > deadline) throw new Error('waitFor timed out');
        await new Promise((r) => setTimeout(r, 10));
    }
}

describe('ABDM routes require a ClinuxFlow session (S3)', () => {
    it('rejects a request with no service key', async () => {
        const { env } = makeEnv();
        expect((await call(env, 'POST', '/hpr/registration/aadhaar-otp', { body: {}, serviceKey: null })).status).toBe(401);
    });

    it('rejects a request carrying only the service key (no session)', async () => {
        const { env } = makeEnv();
        const res = await call(env, 'POST', '/hpr/registration/aadhaar-otp', { body: {} });
        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Sign in required');
    });

    it('rejects a token signed with the wrong secret', async () => {
        const { env } = makeEnv();
        const token = await sessionToken('acct-1', 'clinic-a', 'some-other-secret');
        expect((await call(env, 'POST', '/hpr/registration/aadhaar-otp', { body: {}, token })).status).toBe(401);
    });

    it('fails closed when JWT_SECRET is not configured', async () => {
        const { env } = makeEnv({ JWT_SECRET: undefined });
        const token = await sessionToken('acct-1', 'clinic-a');
        expect((await call(env, 'POST', '/hpr/registration/aadhaar-otp', { body: {}, token })).status).toBe(503);
    });

    it('lets a valid session through to the route handler', async () => {
        const { env } = makeEnv();
        const token = await sessionToken('acct-1', 'clinic-a');
        // Empty body: the handler's own validation answers 400 before any ABDM call is made.
        const res = await call(env, 'POST', '/hpr/registration/aadhaar-otp', { body: {}, token });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('aadhaar is required');
    });

    it('rate-limits OTP-sending routes per account, independently for each account', async () => {
        const { env } = makeEnv();
        const token = await sessionToken('acct-otp', 'clinic-a');
        for (let i = 0; i < 10; i++) {
            expect((await call(env, 'POST', '/abha/enrollment/aadhaar-otp', { body: {}, token })).status).not.toBe(429);
        }
        const limited = await call(env, 'POST', '/abha/enrollment/aadhaar-otp', { body: {}, token });
        expect(limited.status).toBe(429);
        expect(Number(limited.headers.get('Retry-After'))).toBeGreaterThan(0);

        const other = await sessionToken('acct-other', 'clinic-a');
        expect((await call(env, 'POST', '/abha/enrollment/aadhaar-otp', { body: {}, token: other })).status).not.toBe(429);
    });

    it('keeps /health open', async () => {
        const { env } = makeEnv();
        expect((await call(env, 'GET', '/health', { serviceKey: null })).status).toBe(200);
    });
});

describe('UHI: EUA <-> HSPA end to end in one gateway (local mode)', () => {
    async function startSearch(env, token) {
        const res = await call(env, 'POST', '/uhi/eua/internal/search', { token, body: { intent: { item: { descriptor: { code: 'Consultation' } } } } });
        expect(res.status).toBe(202);
        return res.body.transactionId;
    }

    const txn = (env, token, id) => call(env, 'GET', `/uhi/eua/internal/transactions/${id}`, { token }).then((r) => (r.status === 200 ? r.body : undefined));

    it('runs search -> init -> confirm -> status -> cancel, plus on_update/on_message pushes', async () => {
        const { env } = makeEnv();
        const token = await sessionToken('acct-1', 'clinic-a');
        const transactionId = await startSearch(env, token);

        const afterSearch = await waitFor(async () => {
            const t = await txn(env, token, transactionId);
            return t?.catalogs?.length ? t : undefined;
        });
        expect(afterSearch.providerUri).toBe(`${BASE}/uhi/hspa`);
        expect(afterSearch.providerId).toBe('hspa.gw.test');
        expect(afterSearch.clinicId).toBe('clinic-a');
        const itemId = afterSearch.catalogs[0].providers[0].items[0].id;

        expect((await call(env, 'POST', '/uhi/eua/internal/init', { token, body: { transactionId, order: { item: { id: itemId } } } })).status).toBe(202);
        const afterInit = await waitFor(async () => {
            const t = await txn(env, token, transactionId);
            return t?.order?.state === 'INITIALIZED' ? t : undefined;
        });
        const orderId = afterInit.order.id;
        expect(afterInit.order.quote.price.currency).toBe('INR');

        for (const [action, state] of [
            ['confirm', 'CONFIRMED'],
            ['status', 'CONFIRMED'],
            ['cancel', 'CANCELLED'],
        ]) {
            expect((await call(env, 'POST', `/uhi/eua/internal/${action}`, { token, body: { transactionId, order: { id: orderId } } })).status).toBe(202);
            await waitFor(async () => (await txn(env, token, transactionId))?.order?.state === state);
        }

        expect((await call(env, 'POST', '/uhi/hspa/internal/push-update', { token, body: { transactionId, message: { order: { id: orderId, state: 'CANCELLED' } } } })).status).toBe(202);
        expect((await call(env, 'POST', '/uhi/hspa/internal/push-message', { token, body: { transactionId, message: { text: 'Your appointment was cancelled.' } } })).status).toBe(202);
        const final = await waitFor(async () => {
            const t = await txn(env, token, transactionId);
            return t?.pushes?.length === 2 ? t : undefined;
        });
        expect(final.pushes.find((p) => p.action === 'on_message').message.text).toBe('Your appointment was cancelled.');

        const order = await call(env, 'GET', `/uhi/hspa/internal/orders/${orderId}`, { token });
        expect(order.body.state).toBe('CANCELLED');
    });

    it("keeps one clinic's transactions invisible to another clinic", async () => {
        const { env } = makeEnv();
        const tokenA = await sessionToken('acct-a', 'clinic-a');
        const tokenB = await sessionToken('acct-b', 'clinic-b');
        const transactionId = await startSearch(env, tokenA);
        await waitFor(async () => (await txn(env, tokenA, transactionId))?.catalogs?.length);

        expect((await call(env, 'GET', `/uhi/eua/internal/transactions/${transactionId}`, { token: tokenB })).status).toBe(404);
        const drive = await call(env, 'POST', '/uhi/eua/internal/init', { token: tokenB, body: { transactionId, order: { item: { id: 'item-cardio-online-1' } } } });
        expect(drive.status).toBe(409);
    });

    it('restricts HSPA operator routes to the configured clinics', async () => {
        const { env } = makeEnv();
        const tokenB = await sessionToken('acct-b', 'clinic-b');
        expect((await call(env, 'GET', '/uhi/hspa/internal/catalog', { token: tokenB })).status).toBe(403);
        expect((await call(env, 'GET', '/uhi/hspa/internal/catalog', { token: await sessionToken('acct-a', 'clinic-a') })).status).toBe(200);
    });

    it('requires a session on operator routes', async () => {
        const { env } = makeEnv();
        expect((await call(env, 'POST', '/uhi/eua/internal/search', { body: {} })).status).toBe(401);
    });

    it('authenticates network-facing routes by signature only: a ClinuxFlow session is not enough', async () => {
        const { env } = makeEnv();
        const token = await sessionToken('acct-1', 'clinic-a');
        const res = await call(env, 'POST', '/uhi/hspa/search', { token, body: { context: {}, message: {} } });
        expect(res.status).toBe(401);
        expect(res.body.error.code).toBe('UHI-1405');
    });

    it('rejects a forged callback', async () => {
        const { env } = makeEnv();
        const res = await call(env, 'POST', '/uhi/eua/on_search', { serviceKey: null, body: { context: { transaction_id: 'forged' }, message: {} } });
        expect(res.status).toBe(401);
    });

    it('accepts a correctly signed network call without any service key or session', async () => {
        const { env, keys } = makeEnv();
        const context = buildContext({ domain: 'nic2004:85111', action: 'search', city: 'std:011', country: 'IND', consumerId: 'eua.gw.test', consumerUri: `${BASE}/uhi/eua` });
        const body = JSON.stringify({ context, message: { intent: {} } });
        const authorization = buildAuthorizationHeader({ subscriberId: 'eua.gw.test', pubKeyId: 'k1', privateKeyDer: keys.eua.privateKeyDer, body });
        const res = await app.request(`${BASE}/uhi/hspa/search`, { method: 'POST', headers: { 'content-type': 'application/json', authorization }, body }, env);
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ message: { ack: { status: 'ACK' } } });
    });

    it('drops callbacks for transactions this gateway never started', async () => {
        const { env, keys } = makeEnv();
        const token = await sessionToken('acct-1', 'clinic-a');
        const context = { ...buildContext({ domain: 'd', action: 'on_search', city: 'c', country: 'IND', consumerId: 'eua.gw.test', consumerUri: `${BASE}/uhi/eua` }), transaction_id: 'never-started' };
        const body = JSON.stringify({ context, message: { catalog: { providers: [] } } });
        const authorization = buildAuthorizationHeader({ subscriberId: 'hspa.gw.test', pubKeyId: 'k1', privateKeyDer: keys.hspa.privateKeyDer, body });
        const res = await app.request(`${BASE}/uhi/eua/on_search`, { method: 'POST', headers: { 'content-type': 'application/json', authorization }, body }, env);
        expect(res.status).toBe(200);
        await new Promise((r) => setTimeout(r, 30));
        expect((await call(env, 'GET', '/uhi/eua/internal/transactions/never-started', { token })).status).toBe(404);
    });

    it('serves a published catalog on search, and rejects an invalid one', async () => {
        const { env } = makeEnv();
        const token = await sessionToken('acct-a', 'clinic-a');
        expect((await call(env, 'PUT', '/uhi/hspa/internal/catalog', { token, body: { providers: 'not-an-array' } })).status).toBe(400);

        const catalog = {
            descriptor: { name: 'Sunrise Clinic' },
            providers: [
                {
                    id: 'hfr-IN1234',
                    descriptor: { name: 'Sunrise Clinic' },
                    categories: [{ id: 'gm', parent_category_id: null, descriptor: { name: 'General Medicine', code: 'GENERAL' } }],
                    items: [{ id: 'gm-1', descriptor: { name: 'GP Consultation', code: 'Consultation' }, category_id: 'gm', price: { currency: 'INR', value: '300' } }],
                },
            ],
        };
        expect((await call(env, 'PUT', '/uhi/hspa/internal/catalog', { token, body: catalog })).status).toBe(200);

        const transactionId = await startSearch(env, token);
        const t = await waitFor(async () => {
            const r = await txn(env, token, transactionId);
            return r?.catalogs?.length ? r : undefined;
        });
        expect(t.catalogs[0].providers[0].id).toBe('hfr-IN1234');
    });

    it('answers 503 on a role whose key is not configured', async () => {
        const { env } = makeEnv({ UHI_HSPA_PRIVATE_KEY_DER: '' });
        const token = await sessionToken('acct-a', 'clinic-a');
        expect((await call(env, 'GET', '/uhi/hspa/internal/catalog', { token })).status).toBe(503);
    });
});
