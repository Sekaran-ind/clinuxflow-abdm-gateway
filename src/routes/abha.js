// ABHA (Ayushman Bharat Health Account — patient identity) routes: Aadhaar-based enrolment,
// login (Aadhaar-OTP and mobile-OTP variants), profile lookup, and mobile update. Reuses the
// same session-token/encryption/transaction infra as the HPR/HFR modules — see routes/hpr.js
// for the equivalent doc-fidelity notes; the same "follow the sample payload exactly" discipline
// applies here.
//
// Encryption: ABHA uses RSA-OAEP/SHA-1 (see src/lib/encryption.js's encryptOaepSha1), NOT the
// PKCS1 scheme HPR uses — different public key, different endpoint
// ({abhaBaseUrl}/profile/public/certificate), fetched fresh per encryption operation.
//
// Two-token model, same shape as HPR/HFR but with different names: every call needs the
// gateway's own Authorization: Bearer <client-credential token> (handled transparently here).
// Several calls (email verification, get-profile, update-mobile) additionally need an `X-token`
// — a per-user ABHA session token obtained from a successful enrolment or login call. That
// token is scoped to one patient, not the whole Worker, so — exactly like HPR's x-hprid-auth —
// it is never cached here. Callers must pass it through as the `X-ABHA-Token` header.

import { Hono } from 'hono';
import { callAbdm, AbdmApiError } from '../lib/abdmClient.js';
import { getAbdmConfig } from '../lib/config.js';
import { fetchPublicKey, encryptOaepSha1 } from '../lib/encryption.js';
import { getAccessToken, putTransactionState, recordOtpAttempt, clearTransactionState } from '../lib/sessionToken.js';

export const abhaRoutes = new Hono();

class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

abhaRoutes.onError((err, c) => {
    if (err instanceof HttpError) return c.json({ success: false, error: err.message }, err.status);
    if (err instanceof AbdmApiError) {
        console.error(`[abha] ABDM error ${err.status}:`, JSON.stringify(err.body));
        return c.json({ success: false, error: 'ABDM request failed', abdmStatus: err.status, abdmBody: err.body }, 502);
    }
    console.error('[abha] unexpected error:', err);
    return c.json({ success: false, error: err.message }, 500);
});

function requireAbhaToken(c) {
    const token = c.req.header('X-ABHA-Token');
    if (!token) {
        throw new HttpError(400, 'X-ABHA-Token header is required (per-user token from an enrolment or login call)');
    }
    return token;
}

async function encryptForAbha(config, plaintext) {
    const publicKey = await fetchPublicKey(`${config.abhaBaseUrl}/profile/public/certificate`);
    return encryptOaepSha1(publicKey, plaintext);
}

// Shared by every "generate OTP" call across enrolment/login/profile-update — they all share
// the same { scope, loginHint, loginId, otpSystem } body shape, just against different URLs and
// scopes. loginId is always RSA-OAEP encrypted here.
async function requestOtp(c, { path, scope, loginHint, plaintextLoginId, otpSystem, txnId, xToken }) {
    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedLoginId] = await Promise.all([
        getAccessToken(c.env),
        encryptForAbha(config, plaintextLoginId),
    ]);

    return callAbdm({
        url: `${config.abhaBaseUrl}${path}`,
        xCmId: config.xCmId,
        accessToken,
        extraHeaders: xToken ? { 'X-token': `Bearer ${xToken}` } : {},
        body: { ...(txnId ? { txnId } : {}), scope, loginHint, loginId: encryptedLoginId, otpSystem },
    });
}

// Shared by every "verify OTP" call — { scope, authData: { authMethods: ['otp'], otp: {...} } }.
// otpValue is always RSA-OAEP encrypted. extraOtpFields covers the odd one out (enrolment's
// byAadhaar step also wants `mobile` inside the otp object).
async function verifyOtp(c, { path, scope, txnId, otp, xToken, extraOtpFields = {}, extraBodyFields = {} }) {
    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedOtp] = await Promise.all([
        getAccessToken(c.env),
        encryptForAbha(config, otp),
    ]);

    return callAbdm({
        url: `${config.abhaBaseUrl}${path}`,
        xCmId: config.xCmId,
        accessToken,
        extraHeaders: xToken ? { 'X-token': `Bearer ${xToken}` } : {},
        body: {
            scope,
            ...extraBodyFields,
            authData: {
                authMethods: ['otp'],
                otp: { txnId, otpValue: encryptedOtp, ...extraOtpFields },
            },
        },
    });
}

// =================================================================================================
// Enrolment via Aadhaar (ABHA creation) — doc section 3.0
// =================================================================================================

// Step 1/2: Generate (or resend — same endpoint) Aadhaar OTP.
// POST { aadhaar }
abhaRoutes.post('/enrollment/aadhaar-otp', async (c) => {
    const { aadhaar } = await c.req.json();
    if (!aadhaar) return c.json({ success: false, error: 'aadhaar is required' }, 400);

    const result = await requestOtp(c, {
        path: '/enrollment/request/otp',
        scope: ['abha-enrol'],
        loginHint: 'aadhaar',
        plaintextLoginId: aadhaar,
        otpSystem: 'aadhaar',
    });

    await putTransactionState(c.env, result.txnId, { flow: 'abha-aadhaar-enrollment', step: 'aadhaar-otp-sent' });
    return c.json({ success: true, txnId: result.txnId, message: result.message });
});

// Step 3: Verify the Aadhaar OTP and create the ABHA account.
// POST { txnId, otp, mobile } — `mobile` is the primary mobile to register (may differ from the
// Aadhaar-linked one; ABDM tells you via the response whether it matched).
abhaRoutes.post('/enrollment/verify-aadhaar-otp', async (c) => {
    const { txnId, otp, mobile } = await c.req.json();
    if (!txnId || !otp || !mobile) return c.json({ success: false, error: 'txnId, otp, and mobile are required' }, 400);

    const attempt = await recordOtpAttempt(c.env, txnId);
    if (!attempt.allowed) return c.json({ success: false, error: 'Too many OTP attempts for this transaction' }, 429);

    const result = await verifyOtp(c, {
        path: '/enrollment/enrol/byAadhaar',
        scope: undefined, // this endpoint's body has no top-level scope field, unlike the others
        txnId,
        otp,
        extraOtpFields: { mobile },
        extraBodyFields: { consent: { code: 'abha-enrollment', version: '1.4' } },
    });

    await putTransactionState(c.env, txnId, {
        step: 'aadhaar-otp-verified',
        abhaNumber: result.ABHAProfile?.ABHANumber,
    });

    // result.tokens.token is the per-user ABHA session token (this flow's "X-token") — hand it
    // back so the caller (clinuxflow-api) can use it for the immediately-following steps
    // (mobile verify, email link, address creation) and persist it against the patient's
    // session. Strip the base64 photo blob; it's not needed at this point in the flow.
    const { photo, ...profile } = result.ABHAProfile || {};
    return c.json({
        success: true,
        txnId: result.txnId,
        isNew: result.isNew,
        abhaToken: result.tokens?.token,
        abhaTokenExpiresIn: result.tokens?.expiresIn,
        refreshToken: result.tokens?.refreshToken,
        profile,
    });
});

// Step 4a: Send OTP to a mobile number for verification (used when the primary mobile differs
// from the Aadhaar-linked one). POST { txnId, mobile }
abhaRoutes.post('/enrollment/mobile-otp', async (c) => {
    const { txnId, mobile } = await c.req.json();
    if (!txnId || !mobile) return c.json({ success: false, error: 'txnId and mobile are required' }, 400);

    const result = await requestOtp(c, {
        path: '/enrollment/request/otp',
        scope: ['abha-enrol', 'mobile-verify'],
        loginHint: 'mobile',
        plaintextLoginId: mobile,
        otpSystem: 'abdm',
        txnId,
    });

    return c.json({ success: true, txnId: result.txnId, message: result.message });
});

// Step 4b: Verify that mobile OTP. POST { txnId, otp }
abhaRoutes.post('/enrollment/verify-mobile-otp', async (c) => {
    const { txnId, otp } = await c.req.json();
    if (!txnId || !otp) return c.json({ success: false, error: 'txnId and otp are required' }, 400);

    const attempt = await recordOtpAttempt(c.env, txnId);
    if (!attempt.allowed) return c.json({ success: false, error: 'Too many OTP attempts for this transaction' }, 429);

    const result = await verifyOtp(c, {
        path: '/enrollment/auth/byAbdm',
        scope: ['abha-enrol', 'mobile-verify'],
        txnId,
        otp,
        extraOtpFields: { timeStamp: new Date().toISOString().replace('T', ' ').slice(0, 19) },
    });

    await putTransactionState(c.env, txnId, { step: 'mobile-otp-verified' });
    return c.json({ success: true, txnId: result.txnId, authResult: result.authResult });
});

// Step 5: Send an email verification link. POST { email }, header X-ABHA-Token required.
// ABDM's response here is 200 with no body — the user completes verification by clicking the
// emailed link, there's nothing further for this Worker to poll.
abhaRoutes.post('/enrollment/email-verification-link', async (c) => {
    const abhaToken = requireAbhaToken(c);
    const { email } = await c.req.json();
    if (!email) return c.json({ success: false, error: 'email is required' }, 400);

    await requestOtp(c, {
        path: '/profile/account/request/emailVerificationLink',
        scope: ['abha-profile', 'email-link-verify'],
        loginHint: 'email',
        plaintextLoginId: email,
        otpSystem: 'abdm',
        xToken: abhaToken,
    });

    return c.json({ success: true, message: 'Verification link sent' });
});

// Step 6a: ABHA address suggestions. GET ?txnId=...
// Note the odd header name here — ABDM wants the txnId as a `Transaction_Id` header on this one
// call, not in the body/query like everywhere else.
abhaRoutes.get('/enrollment/address-suggestions', async (c) => {
    const txnId = c.req.query('txnId');
    if (!txnId) return c.json({ success: false, error: 'txnId query param is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.abhaBaseUrl}/enrollment/enrol/suggestion`,
        method: 'GET',
        xCmId: config.xCmId,
        accessToken,
        extraHeaders: { Transaction_Id: txnId },
    });

    return c.json({ success: true, txnId: result.txnId, suggestions: result.abhaAddressList });
});

// Step 6b: Create the custom ABHA address, finalizing enrolment. POST { txnId, abhaAddress }
abhaRoutes.post('/enrollment/address', async (c) => {
    const { txnId, abhaAddress } = await c.req.json();
    if (!txnId || !abhaAddress) return c.json({ success: false, error: 'txnId and abhaAddress are required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.abhaBaseUrl}/enrollment/enrol/abha-address`,
        xCmId: config.xCmId,
        accessToken,
        body: { txnId, abhaAddress, preferred: 1 },
    });

    await clearTransactionState(c.env, txnId);
    return c.json({ success: true, ...result });
});

// =================================================================================================
// Login — doc section 7.0. ABDM exposes several near-identical variants (login via ABHA number +
// Aadhaar OTP, login via raw Aadhaar number, login via ABHA-address OTP, login via mobile OTP,
// biometric variants, ...) that all share the same request/verify body shape and just vary
// `loginHint` / `otpSystem` / `scope`. Rather than one route per variant, these two generic
// routes take those as parameters — the frontend picks the combination per the table below,
// matching the doc's sections 7.1 (aadhaar-linked ABHA number), 7.2 (raw Aadhaar), 7.4 (mobile):
//
//   scope                              loginHint      otpSystem   loginId is...
//   ['abha-login','aadhaar-verify']    'abha-number'  'aadhaar'   the ABHA number
//   ['abha-login','aadhaar-verify']    'aadhaar'      'aadhaar'   the raw Aadhaar number
//   ['abha-login','mobile-verify']     'mobile'       'abdm'      the mobile number
//
// Login via ABHA-address/password and the biometric variants (7.3, 7.5) aren't wired up yet —
// see README.
// =================================================================================================

abhaRoutes.post('/login/request-otp', async (c) => {
    const { scope, loginHint, loginId, otpSystem } = await c.req.json();
    if (!scope || !loginHint || !loginId || !otpSystem) {
        return c.json({ success: false, error: 'scope, loginHint, loginId, and otpSystem are required' }, 400);
    }

    const result = await requestOtp(c, {
        path: '/profile/login/request/otp',
        scope,
        loginHint,
        plaintextLoginId: loginId,
        otpSystem,
    });

    await putTransactionState(c.env, result.txnId, { flow: 'abha-login', step: 'otp-sent' });
    return c.json({ success: true, txnId: result.txnId, message: result.message });
});

abhaRoutes.post('/login/verify-otp', async (c) => {
    const { txnId, otp, scope } = await c.req.json();
    if (!txnId || !otp || !scope) return c.json({ success: false, error: 'txnId, otp, and scope are required' }, 400);

    const attempt = await recordOtpAttempt(c.env, txnId);
    if (!attempt.allowed) return c.json({ success: false, error: 'Too many OTP attempts for this transaction' }, 429);

    const result = await verifyOtp(c, {
        path: '/profile/login/verify',
        scope,
        txnId,
    });

    await clearTransactionState(c.env, txnId);

    // Strip photo blobs from the account list before returning — keep the payload light, the
    // frontend can fetch a fresh profile (with photo) via GET /abha/profile if it needs one.
    const accounts = (result.accounts || []).map(({ profilePhoto, ...rest }) => rest);
    return c.json({
        success: true,
        txnId: result.txnId,
        authResult: result.authResult,
        abhaToken: result.token,
        abhaTokenExpiresIn: result.expiresIn,
        refreshToken: result.refreshToken,
        accounts,
    });
});

// =================================================================================================
// Profile — doc section 9.0
// =================================================================================================

abhaRoutes.get('/profile', async (c) => {
    const abhaToken = requireAbhaToken(c);
    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.abhaBaseUrl}/profile/account`,
        method: 'GET',
        xCmId: config.xCmId,
        accessToken,
        extraHeaders: { 'X-token': `Bearer ${abhaToken}` },
    });

    const includePhoto = c.req.query('includePhoto') === 'true';
    const { profilePhoto, ...rest } = result;
    return c.json({ success: true, ...rest, ...(includePhoto ? { profilePhoto } : {}) });
});

// =================================================================================================
// Update mobile — doc section 8.1
// =================================================================================================

abhaRoutes.post('/profile/mobile/request-otp', async (c) => {
    const abhaToken = requireAbhaToken(c);
    const { mobile } = await c.req.json();
    if (!mobile) return c.json({ success: false, error: 'mobile is required' }, 400);

    const result = await requestOtp(c, {
        path: '/profile/account/request/otp',
        scope: ['abha-profile', 'mobile-verify'],
        loginHint: 'mobile',
        plaintextLoginId: mobile,
        otpSystem: 'abdm',
        xToken: abhaToken,
    });

    await putTransactionState(c.env, result.txnId, { flow: 'abha-update-mobile', step: 'otp-sent' });
    return c.json({ success: true, txnId: result.txnId, message: result.message });
});

abhaRoutes.post('/profile/mobile/verify-otp', async (c) => {
    const abhaToken = requireAbhaToken(c);
    const { txnId, otp } = await c.req.json();
    if (!txnId || !otp) return c.json({ success: false, error: 'txnId and otp are required' }, 400);

    const attempt = await recordOtpAttempt(c.env, txnId);
    if (!attempt.allowed) return c.json({ success: false, error: 'Too many OTP attempts for this transaction' }, 429);

    const result = await verifyOtp(c, {
        path: '/profile/account/verify',
        scope: ['abha-profile', 'mobile-verify'],
        txnId,
        otp,
        xToken: abhaToken,
    });

    await clearTransactionState(c.env, txnId);
    return c.json({ success: true, txnId: result.txnId, authResult: result.authResult, accounts: result.accounts });
});
