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
