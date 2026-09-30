// Citizen routes (/citizen/*, used by cubo-diary): no session, fixed ABDM request shapes,
// per-IP and per-target rate limits, and search results readable only with the searcher's key.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { constants, generateKeyPairSync, privateDecrypt } from 'node:crypto';
import app from './index.js';
import { generateKeyPair } from './uhi/crypto.js';
import { normaliseAbhaNumber } from './routes/citizen.js';

const BASE = 'http://gw.test';
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const decrypt = (b64) => privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, Buffer.from(b64, 'base64')).toString();
const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const namespace = (handler) => ({ idFromName: (n) => n, get: () => ({ fetch: handler }) });

function makeEnv() {
    const hspa = generateKeyPair();
    const eua = generateKeyPair();
    const env = {
        ABDM_CLIENT_ID: 'id',
        ABDM_CLIENT_SECRET: 'secret',
        SESSION_TOKEN: namespace(async () => Response.json({ accessToken: 'gateway-token' })),
        REGISTRATION_TXN: namespace(async () => Response.json({ allowed: true, attempts: 1 })),
        UHI_GATEWAY_MODE: 'local',
        UHI_HSPA_SUBSCRIBER_ID: 'hspa.gw.test',
        UHI_HSPA_PUB_KEY_ID: 'k1',
        UHI_HSPA_PRIVATE_KEY_DER: hspa.privateKeyDer,
        UHI_EUA_SUBSCRIBER_ID: 'eua.gw.test',
        UHI_EUA_PUB_KEY_ID: 'k1',
        UHI_EUA_PRIVATE_KEY_DER: eua.privateKeyDer,
        UHI_HSPA_OPERATOR_CLINIC_IDS: 'clinic-a',
    };
    env.UHI_FETCH_OVERRIDE = (url, init) => app.request(url, init, env);
    return env;
}

async function call(env, method, path, { body, headers = {}, ip = '203.0.113.1' } = {}) {
    const res = await app.request(`${BASE}${path}`, { method, headers: { 'content-type': 'application/json', 'CF-Connecting-IP': ip, ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }, env);
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
}

/** A fake ABDM: records every call; the ABHA cert answers only with the gateway token. */
function fakeAbdm(responses = {}) {
    const calls = [];
    vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
        const u = String(url);
        if (u.endsWith('/profile/public/certificate')) {
            return init.headers?.Authorization === 'Bearer gateway-token' ? Response.json({ publicKey: publicKeyB64 }) : new Response('{}', { status: 401 });
        }
        const body = init.body ? JSON.parse(init.body) : undefined;
        calls.push({ url: u, body, headers: init.headers });
        const key = Object.keys(responses).find((k) => u.endsWith(k));
        return key ? Response.json(responses[key]) : Response.json({}, { status: 404 });
    }));
    return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe('citizen ABHA sign-in', () => {
    it('sends ABDM a fixed login request, whatever else the caller puts in the body', async () => {
        const env = makeEnv();
        const calls = fakeAbdm({ '/profile/login/request/otp': { txnId: 'tx-1', message: 'OTP sent to mobile number ending with ******4723' } });
        const res = await call(env, 'POST', '/citizen/abha/login/request-otp', { body: { method: 'abha-mobile', abhaNumber: '91123456789012', scope: ['abha-profile', 'de-activate'] } });
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, txnId: 'tx-1' });
        expect(calls[0].body).toMatchObject({ scope: ['abha-login', 'mobile-verify'], loginHint: 'abha-number', otpSystem: 'abdm' });
        expect(decrypt(calls[0].body.loginId)).toBe('91-1234-5678-9012');
    });

    it('rejects unknown methods and malformed ABHA numbers without calling ABDM', async () => {
        const env = makeEnv();
        const calls = fakeAbdm();
        expect((await call(env, 'POST', '/citizen/abha/login/request-otp', { body: { method: 'deactivate', abhaNumber: '91123456789012' } })).status).toBe(400);
        expect((await call(env, 'POST', '/citizen/abha/login/request-otp', { body: { method: 'abha-mobile', abhaNumber: '1234' } })).status).toBe(400);
        expect(calls).toHaveLength(0);
    });

    it('limits OTPs to one ABHA number even from many addresses', async () => {
        const env = makeEnv();
        fakeAbdm({ '/profile/login/request/otp': { txnId: 'tx' } });
        const send = (ip, abhaNumber = '91-1234-5678-9012') => call(env, 'POST', '/citizen/abha/login/request-otp', { ip, body: { method: 'abha-mobile', abhaNumber } });
        for (const ip of ['198.51.100.1', '198.51.100.2', '198.51.100.3']) expect((await send(ip)).status).toBe(200);
        expect((await send('198.51.100.4')).status).toBe(429);
        // A different person is unaffected.
        expect((await send('198.51.100.5', '91-9999-8888-7777')).status).toBe(200);
    });

    it('limits OTPs from one address', async () => {
        const env = makeEnv();
        fakeAbdm({ '/profile/login/request/otp': { txnId: 'tx' } });
        const results = [];
        for (let i = 0; i < 6; i++) results.push((await call(env, 'POST', '/citizen/abha/login/request-otp', { ip: '192.0.2.9', body: { method: 'abha-mobile', abhaNumber: `9100000000000${i}` } })).status);
        expect(results).toEqual([200, 200, 200, 200, 200, 429]);
    });

    it('verifies with the encrypted OTP and returns the token but not the refresh token', async () => {
        const env = makeEnv();
        const calls = fakeAbdm({
            '/profile/login/verify': { token: 'x-token', expiresIn: 1800, refreshToken: 'refresh', accounts: [{ ABHANumber: '91-1234-5678-9012', preferredAbhaAddress: 'meera@sbx', name: 'Meera Iyer', kycVerified: true, profilePhoto: 'b64' }] },
        });
        const res = await call(env, 'POST', '/citizen/abha/login/verify-otp', { body: { method: 'abha-mobile', txnId: 'tx-1', otp: '123456' } });
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, abhaToken: 'x-token', expiresIn: 1800, account: { abhaNumber: '91-1234-5678-9012', abhaAddress: 'meera@sbx', name: 'Meera Iyer', kycVerified: true } });
        const otp = calls[0].body.authData.otp;
        expect(otp.txnId).toBe('tx-1');
        expect(decrypt(otp.otpValue)).toBe('123456');
        expect(calls[0].body.scope).toEqual(['abha-login', 'mobile-verify']);
    });

    it('profile needs the ABHA token and returns only the fields the diary uses', async () => {
        const env = makeEnv();
        const calls = fakeAbdm({ '/profile/account': { ABHANumber: '91-1234-5678-9012', name: 'Meera Iyer', gender: 'F', yearOfBirth: '1978', profilePhoto: 'b64', mobile: '9876543210', address: 'x' } });
        expect((await call(env, 'GET', '/citizen/abha/profile')).status).toBe(401);
        const res = await call(env, 'GET', '/citizen/abha/profile', { headers: { 'X-ABHA-Token': 'x-token' } });
        expect(res.body.profile).toMatchObject({ abhaNumber: '91-1234-5678-9012', name: 'Meera Iyer', gender: 'F', yearOfBirth: '1978' });
        expect(JSON.stringify(res.body)).not.toMatch(/b64|9876543210/);
        expect(calls[0].headers['X-token']).toBe('Bearer x-token');
    });

    it('normaliseAbhaNumber', () => {
        expect(normaliseAbhaNumber('91 1234 5678 9012')).toBe('91-1234-5678-9012');
        expect(normaliseAbhaNumber('91-1234-5678-901')).toBeNull();
    });
});

describe('citizen UHI search (anonymous)', () => {
    async function waitFor(check, ms = 3000) {
        const until = Date.now() + ms;
        for (;;) {
            const v = await check();
            if (v) return v;
            if (Date.now() > until) throw new Error('timed out');
            await new Promise((r) => setTimeout(r, 10));
        }
    }

    it('searches without a session and returns results only to the holder of the read key', async () => {
        const env = makeEnv();
        const started = await call(env, 'POST', '/citizen/uhi/search', { body: { by: 'category', code: 'cardiology' } });
        expect(started.status).toBe(202);
        const { transactionId, readKey } = started.body;
        expect(readKey).toMatch(/^[0-9a-f-]{36}$/);
        const got = await waitFor(async () => {
            const r = await call(env, 'GET', `/citizen/uhi/transactions/${transactionId}`, { headers: { 'X-Read-Key': readKey } });
            return r.body?.catalogs?.length ? r : null;
        });
        expect(got.body.catalogs[0].providers[0].items.length).toBeGreaterThan(0);
        expect((await call(env, 'GET', `/citizen/uhi/transactions/${transactionId}`)).status).toBe(404);
        expect((await call(env, 'GET', `/citizen/uhi/transactions/${transactionId}`, { headers: { 'X-Read-Key': 'guess' } })).status).toBe(404);
    });

    it('accepts only a short code, never a free-form intent', async () => {
        const env = makeEnv();
        expect((await call(env, 'POST', '/citizen/uhi/search', { body: { code: '<script>' } })).status).toBe(400);
        expect((await call(env, 'POST', '/citizen/uhi/search', { body: { intent: { provider: { id: 'x' } } } })).status).toBe(400);
    });

    it('rate-limits searches per address', async () => {
        const env = makeEnv();
        const statuses = [];
        for (let i = 0; i < 21; i++) statuses.push((await call(env, 'POST', '/citizen/uhi/search', { ip: '192.0.2.50', body: { code: 'CARDIOLOGY' } })).status);
        expect(statuses.slice(0, 20).every((s) => s === 202)).toBe(true);
        expect(statuses[20]).toBe(429);
    });
});
