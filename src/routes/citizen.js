// Citizen routes, for cubo-diary: people with no ClinuxFlow account.
//
//   POST /citizen/abha/login/request-otp   { method, abhaNumber }       -> { txnId, message }
//   POST /citizen/abha/login/verify-otp    { method, txnId, otp }       -> { abhaToken, expiresIn, account }
//   GET  /citizen/abha/profile             X-ABHA-Token                 -> the profile fields the diary uses
//   POST /citizen/uhi/search               { by, code }                 -> { transactionId, readKey }
//   GET  /citizen/uhi/transactions/:id     X-Read-Key                   -> { catalogs }
//
// No session and no service key: the person's own ABHA token is their identity for ABHA calls,
// and a UHI search needs none. What stands in for account checks:
//   - the ABDM request shape is fixed here (scope, loginHint, otpSystem), never taken from the
//     caller, so these routes can only do an ABHA login, nothing else ABHA offers;
//   - rate limits by client IP on everything, and on OTP sending also by a SHA-256 of the ABHA
//     number targeted, so one person can't be flooded with OTPs from many addresses;
//   - OTP attempts per transaction are capped (recordOtpAttempt), as on the clinic routes;
//   - search results are readable only with the random key handed to the searcher.
// The refresh token ABDM returns is not passed on: the diary keeps the short-lived token in
// memory only and signs in again when it expires.
import { Hono } from 'hono';
import { AbdmApiError, callAbdm } from '../lib/abdmClient.js';
import { getAbdmConfig } from '../lib/config.js';
import { getAccessToken, putTransactionState, recordOtpAttempt, clearTransactionState } from '../lib/sessionToken.js';
import { rateLimit } from '../lib/rateLimit.js';
import { requestOtp, verifyOtp } from './abha.js';
import { buildEuaCitizenRoutes } from '../uhi/eua/routes.js';
import { euaDeps } from './uhi.js';

// ABHA v3 login variants (NHA ABHA V3 API doc, 7.3 "Login via Abha OTP"). With 'abha-mobile' ABDM
// sends the OTP to the mobile linked to the ABHA; with 'abha-aadhaar' UIDAI sends it to the
// Aadhaar-linked mobile (this one depends on the sandbox's Aadhaar gateway).
export const ABHA_LOGIN = {
    'abha-mobile': { scope: ['abha-login', 'mobile-verify'], loginHint: 'abha-number', otpSystem: 'abdm' },
    'abha-aadhaar': { scope: ['abha-login', 'aadhaar-verify'], loginHint: 'abha-number', otpSystem: 'aadhaar' },
};

const clientIp = (c) => c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';
const sha256Hex = async (text) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))].map((b) => b.toString(16).padStart(2, '0')).join('');

/** 14 digits, returned in ABDM's 2-4-4-4 form, or null. */
export function normaliseAbhaNumber(input) {
    const d = String(input ?? '').replace(/\D/g, '');
    return d.length === 14 ? `${d.slice(0, 2)}-${d.slice(2, 6)}-${d.slice(6, 10)}-${d.slice(10)}` : null;
}

class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

export const citizenRoutes = new Hono();

citizenRoutes.onError((err, c) => {
    if (err instanceof HttpError) return c.json({ success: false, error: err.message }, err.status);
    if (err instanceof AbdmApiError) {
        console.error(`[citizen] ABDM error ${err.status} REQUEST-ID=${err.requestId}:`, JSON.stringify(err.body));
        return c.json({ success: false, error: 'ABDM request failed', abdmStatus: err.status, abdmBody: err.body, abdmRequestId: err.requestId }, 502);
    }
    // ABDM not returning the ABHA encryption key: say so, instead of a bare 500. (A 404 "Invalid
    // Timestamp" here turned out to be missing REQUEST-ID/TIMESTAMP headers, fixed in encryption.js.)
    if (/Failed to fetch ABDM public key .*abha/i.test(err?.message || '')) {
        console.error('[%s] ABHA certificate refused: %s', 'citizen', err.message);
        return c.json({ success: false, error: 'ABDM did not return its ABHA encryption key, so nothing was sent. Try again shortly.' }, 502);
    }
    console.error('[citizen] unexpected error:', err);
    return c.json({ success: false, error: 'Something went wrong' }, 500);
});

citizenRoutes.use('/*', rateLimit({ bucket: 'citizen', limit: 60, windowSeconds: 60, key: clientIp }));

const method = (name) => {
    const m = ABHA_LOGIN[name];
    if (!m) throw new HttpError(400, `method must be one of: ${Object.keys(ABHA_LOGIN).join(', ')}`);
    return m;
};

citizenRoutes.post(
    '/abha/login/request-otp',
    rateLimit({ bucket: 'citizen-otp-ip', limit: 5, windowSeconds: 600, key: clientIp }),
    rateLimit({
        bucket: 'citizen-otp-target',
        limit: 3,
        windowSeconds: 600,
        key: async (c) => sha256Hex(normaliseAbhaNumber((await c.req.json().catch(() => ({}))).abhaNumber) ?? 'invalid'),
    }),
    async (c) => {
        const body = await c.req.json().catch(() => ({}));
        const m = method(body.method);
        const abhaNumber = normaliseAbhaNumber(body.abhaNumber);
        if (!abhaNumber) throw new HttpError(400, 'An ABHA number has 14 digits, e.g. 91-1234-5678-9012.');
        const result = await requestOtp(c, { path: '/profile/login/request/otp', scope: m.scope, loginHint: m.loginHint, plaintextLoginId: abhaNumber, otpSystem: m.otpSystem });
        await putTransactionState(c.env, result.txnId, { flow: 'citizen-abha-login', step: 'otp-sent', method: body.method });
        return c.json({ success: true, txnId: result.txnId, message: result.message });
    },
);

citizenRoutes.post('/abha/login/verify-otp', async (c) => {
    const { method: name, txnId, otp } = await c.req.json().catch(() => ({}));
    const m = method(name);
    if (!txnId || !/^\d{6}$/.test(String(otp ?? ''))) throw new HttpError(400, 'txnId and a 6-digit otp are required');
    const attempt = await recordOtpAttempt(c.env, txnId);
    if (!attempt.allowed) throw new HttpError(429, 'Too many OTP attempts for this transaction');

    const result = await verifyOtp(c, { path: '/profile/login/verify', scope: m.scope, txnId, otp });
    await clearTransactionState(c.env, txnId);
    if (!result?.token) throw new HttpError(502, result?.message || 'ABDM did not return a session');
    const a = (result.accounts || [])[0] || {};
    return c.json({
        success: true,
        abhaToken: result.token,
        expiresIn: result.expiresIn,
        account: { abhaNumber: a.ABHANumber, abhaAddress: a.preferredAbhaAddress, name: a.name, kycVerified: a.kycVerified },
    });
});

citizenRoutes.get('/abha/profile', async (c) => {
    const abhaToken = c.req.header('X-ABHA-Token');
    if (!abhaToken) throw new HttpError(401, 'Sign in with ABHA first');
    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);
    const p = await callAbdm({ url: `${config.abhaBaseUrl}/profile/account`, method: 'GET', xCmId: config.xCmId, accessToken, extraHeaders: { 'X-token': `Bearer ${abhaToken}` } });
    // Only what the diary shows or uses: no photo, no raw KYC payload.
    return c.json({
        success: true,
        profile: {
            abhaNumber: p.ABHANumber,
            abhaAddress: p.preferredAbhaAddress,
            name: p.name,
            firstName: p.firstName,
            middleName: p.middleName,
            lastName: p.lastName,
            gender: p.gender,
            dayOfBirth: p.dayOfBirth,
            monthOfBirth: p.monthOfBirth,
            yearOfBirth: p.yearOfBirth,
            districtName: p.districtName,
            stateName: p.stateName,
            kycVerified: p.kycVerified,
        },
    });
});

// Anonymous UHI search. Reads are frequent (the diary polls for on_search results).
citizenRoutes.use('/uhi/search', rateLimit({ bucket: 'citizen-uhi-search', limit: 20, windowSeconds: 60, key: clientIp }));
citizenRoutes.route('/uhi', buildEuaCitizenRoutes(euaDeps));
