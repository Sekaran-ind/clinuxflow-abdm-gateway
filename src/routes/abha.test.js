// Regression: /abha/login/verify-otp built the ABDM request without the OTP, so ABDM received an
// encrypted "undefined". The route now passes the caller's OTP through.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { constants, generateKeyPairSync, privateDecrypt } from 'node:crypto';
import { abhaRoutes } from './abha.js';

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const namespace = (handler) => ({ idFromName: (n) => n, get: () => ({ fetch: handler }) });
const env = {
    ABDM_CLIENT_ID: 'id',
    ABDM_CLIENT_SECRET: 'secret',
    SESSION_TOKEN: namespace(async () => Response.json({ accessToken: 'gateway-token' })),
    REGISTRATION_TXN: namespace(async () => Response.json({ allowed: true, attempts: 1 })),
};

afterEach(() => vi.unstubAllGlobals());

describe('ABHA login verify', () => {
    it('sends the OTP to ABDM', async () => {
        let sent;
        vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
            if (String(url).endsWith('/profile/public/certificate')) return Response.json({ publicKey: publicKeyB64 });
            sent = JSON.parse(init.body);
            return Response.json({ token: 't', accounts: [] });
        }));
        const res = await abhaRoutes.request('/login/verify-otp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ txnId: 'tx', otp: '123456', scope: ['abha-login', 'mobile-verify'] }) }, env);
        expect(res.status).toBe(200);
        // ABHA encrypts with RSA-OAEP/SHA-1: decrypt what ABDM would receive.
        const otp = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, Buffer.from(sent.authData.otp.otpValue, 'base64')).toString();
        expect(otp).toBe('123456');
    });
});
