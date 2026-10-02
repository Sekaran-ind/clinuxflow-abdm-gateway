// Regression: HPR's cert endpoint (/api/v1/auth/cert) needs the gateway's access token. Without
// it the ABDM sandbox answers 401 and Aadhaar OTP generation fails with "Failed to fetch ABDM
// public key ... HTTP 401" (seen live 2026-09-30).
import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { hprRoutes } from './hpr.js';

const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

/** Durable Object namespace stub whose every instance answers with `handler`. */
const namespace = (handler) => ({ idFromName: (n) => n, get: () => ({ fetch: handler }) });

const env = {
    ABDM_CLIENT_ID: 'id',
    ABDM_CLIENT_SECRET: 'secret',
    SESSION_TOKEN: namespace(async () => Response.json({ accessToken: 'gateway-token', token: 'gateway-token' })),
    REGISTRATION_TXN: namespace(async () => Response.json({ ok: true })),
};

afterEach(() => vi.unstubAllGlobals());

describe('HPR encryption', () => {
    it('fetches the HPR cert with the gateway access token before sending the Aadhaar OTP', async () => {
        const seen = [];
        vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
            seen.push({ url: String(url), auth: init.headers?.Authorization });
            if (String(url).endsWith('/api/v1/auth/cert')) {
                // What the sandbox does: 401 without the bearer token.
                if (init.headers?.Authorization !== 'Bearer gateway-token') return new Response('{}', { status: 401 });
                // Also as the sandbox does: a bare PEM block, not JSON.
                return new Response(`-----BEGIN PUBLIC KEY-----\n${publicKeyB64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`);
            }
            return Response.json({ txnId: 'txn-1', mobileNumber: '******1234' });
        }));
        const res = await hprRoutes.request('/registration/aadhaar-otp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ aadhaar: '999999990019' }) }, env);
        const body = await res.json();
        expect(res.status).toBe(200);
        expect(body).toMatchObject({ success: true, txnId: 'txn-1' });
        const cert = seen.find((s) => s.url.endsWith('/api/v1/auth/cert'));
        expect(cert.auth).toBe('Bearer gateway-token');
    });
});

describe('Aadhaar verification by link (NHA doc v2.0)', () => {
    const envLink = { ...env, REGISTRATION_TXN: namespace(async () => Response.json({ ok: true, allowed: true, attempts: 1 })) };
    const post = (path, body) => hprRoutes.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body ?? {}) }, envLink);
    const stub = (routes) => {
        const calls = [];
        vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
            const u = String(url);
            calls.push({ url: u, body: init.body ? JSON.parse(init.body) : undefined });
            const k = Object.keys(routes).find((x) => u.endsWith(x));
            return k ? routes[k]() : new Response('{}', { status: 404 });
        }));
        return calls;
    };

    it('issues a link to ABDM’s own Aadhaar page, with its expiry', async () => {
        const calls = stub({ '/aadhaar/generateLink': () => Response.json({ status: 'URL GENERATED', txnId: 't1', url: 'https://healthidbeta.abdm.gov.in/abdm/aadhaar/gateway/auth?link_id=x' }) });
        const res = await post('/registration/aadhaar-link');
        const body = await res.json();
        expect(body).toMatchObject({ success: true, txnId: 't1', url: 'https://healthidbeta.abdm.gov.in/abdm/aadhaar/gateway/auth?link_id=x' });
        expect(new Date(body.expiresAt).getTime() - Date.now()).toBeGreaterThan(4 * 60 * 1000);
        expect(calls[0].body).toEqual({ scopes: ['nhpr-register'], source: 'NHPR' });
    });

    it('refuses a link to anywhere but abdm.gov.in', async () => {
        stub({ '/aadhaar/generateLink': () => Response.json({ txnId: 't1', url: 'https://evil.example/abdm.gov.in' }) });
        expect((await post('/registration/aadhaar-link')).status).toBe(502);
    });

    it('reads the bare boolean status, and maps the verified details', async () => {
        stub({ '/aadhaar/isAuthenticated': () => new Response('true', { headers: { 'content-type': 'application/json' } }) });
        expect(await (await post('/registration/aadhaar-link/status', { txnId: 't1' })).json()).toEqual({ success: true, authenticated: true });
        stub({ '/v2/registration/aadhaar/verifyOTP': () => Response.json({ txnId: 't1', mobileNumber: '******5126', photo: 'JPEG', name: 'Rahul Sharma', gender: 'M', birthdate: '1990-01-01', house: '12A', street: 'MG Road', district: 'Bangalore', state: 'Karnataka', pincode: '560001' }) });
        const d = await (await post('/registration/aadhaar-link/details', { txnId: 't1' })).json();
        expect(d).toMatchObject({ success: true, txnId: 't1', maskedMobile: '******5126', name: 'Rahul Sharma', birthdate: '1990-01-01', address: '12A, MG Road, Bangalore, Karnataka, 560001', photo: 'JPEG' });
    });

    it('passes ABDM’s "verification pending" through, and marks the account check as pre-verified', async () => {
        stub({ '/v2/registration/aadhaar/verifyOTP': () => Response.json({ code: 'HIS-422', details: [{ message: 'Aadhaar verification is pending. Please complete it to continue.' }] }, { status: 422 }) });
        const pending = await post('/registration/aadhaar-link/details', { txnId: 't1' });
        expect(pending.status).toBe(502);
        expect(JSON.stringify(await pending.json())).toMatch(/verification is pending/);
        const calls = stub({ '/checkHpIdAccountExist': () => Response.json({ hprId: '', firstName: 'Rahul' }) });
        await post('/registration/check-account-exists', { txnId: 't1', preverifiedCheck: true });
        expect(calls[0].body).toEqual({ txnId: 't1', preverifiedCheck: true });
    });
});

describe('HPR doc v2.0 corrections', () => {
    const envT = { ...env, REGISTRATION_TXN: namespace(async () => Response.json({ ok: true, allowed: true, attempts: 1 })) };
    const post = (path, body) => hprRoutes.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }, envT);
    const cert = () => new Response(`-----BEGIN PUBLIC KEY-----\n${publicKeyB64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`);
    const stub = (routes) => {
        const calls = [];
        vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
            const u = String(url);
            if (u.endsWith('/auth/cert')) return cert();
            calls.push({ url: u, body: init.body ? JSON.parse(init.body) : undefined });
            const k = Object.keys(routes).find((x) => u.endsWith(x));
            return k ? routes[k]() : new Response('{}', { status: 404 });
        }));
        return calls;
    };

    it('reports verified: false from the mobile check instead of success regardless', async () => {
        stub({ '/demographicAuthViaMobile': () => Response.json({ verified: false, errorCode: 'X', reason: 'Mobile number not linked with Aadhaar', uidaiToken: null }) });
        expect(await (await post('/registration/demographic-auth-mobile', { txnId: 't', mobileNumber: '9876543210' })).json()).toMatchObject({ success: true, verified: false, reason: 'Mobile number not linked with Aadhaar', txnId: 't' });
        stub({ '/demographicAuthViaMobile': () => Response.json({ verified: true }) });
        expect((await (await post('/registration/demographic-auth-mobile', { txnId: 't', mobileNumber: '9876543210' })).json()).verified).toBe(true);
    });

    it('returns the KYC photo from the account check (create needs it)', async () => {
        stub({ '/checkHpIdAccountExist': () => Response.json({ hprId: '', firstName: 'Asha', profilePhoto: 'KYC', token: 'secret' }) });
        const body = await (await post('/registration/check-account-exists', { txnId: 't' })).json();
        expect(body).toMatchObject({ hpidExists: false, photo: 'KYC', demographics: { firstName: 'Asha' } });
        expect(JSON.stringify(body)).not.toContain('secret');
    });

    it('sends category, sub-category and role as integers, and the photo', async () => {
        const calls = stub({ '/createHprIdWithPreVerified': () => Response.json({ hprIdNumber: '71-0000', hprId: 'asha@hpr.abdm', token: 't' }) });
        const res = await post('/registration/create', { txnId: 't', email: 'a@example.in', password: 'Str0ng!pass', firstName: 'Asha', lastName: 'Rao', hprId: 'asha.rao', stateCode: '29', districtCode: '572', role: '3', hpCategoryCode: '1', hpSubCategoryCode: '3', profilePhotoBase64: 'KYC' });
        expect(res.status).toBe(200);
        expect(calls[0].body).toMatchObject({ hpCategoryCode: 1, hpSubCategoryCode: 3, role: 3, profilePhoto: 'KYC' });
    });
});
