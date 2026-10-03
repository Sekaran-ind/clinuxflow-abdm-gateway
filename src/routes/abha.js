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
import { fetchCard, fetchProfile } from '../lib/abhaSession.js';

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
    // ABDM not returning the ABHA encryption key: say so, instead of a bare 500. (A 404 "Invalid
    // Timestamp" here turned out to be missing REQUEST-ID/TIMESTAMP headers, fixed in encryption.js.)
    if (/Failed to fetch ABDM public key .*abha/i.test(err?.message || '')) {
        console.error('[%s] ABHA certificate refused: %s', 'abha', err.message);
        return c.json({ success: false, error: 'ABDM did not return its ABHA encryption key, so nothing was sent. Try again shortly.' }, 502);
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

// accessToken is required, not optional — see fetchPublicKey's own header (real bug found live:
// ABHA's /profile/public/certificate 401s without it, despite fetching a "public" key).
async function encryptForAbha(config, plaintext, accessToken) {
    const publicKey = await fetchPublicKey(`${config.abhaBaseUrl}/profile/public/certificate`, accessToken);
    return encryptOaepSha1(publicKey, plaintext);
}

// Shared by every "generate OTP" call across enrolment/login/profile-update — they all share
// the same { scope, loginHint, loginId, otpSystem } body shape, just against different URLs and
// scopes. loginId is always RSA-OAEP encrypted here.
export async function requestOtp(c, { path, scope, loginHint, plaintextLoginId, otpSystem, txnId, xToken }) {
    const config = getAbdmConfig(c.env);
    // Sequential, not Promise.all — encryptForAbha now genuinely depends on accessToken (see its
    // own header), not just an independent parallel step.
    const accessToken = await getAccessToken(c.env);
    const encryptedLoginId = await encryptForAbha(config, plaintextLoginId, accessToken);

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
export async function verifyOtp(c, { path, scope, txnId, otp, xToken, extraOtpFields = {}, extraBodyFields = {} }) {
    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);
    const encryptedOtp = await encryptForAbha(config, otp, accessToken);

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
// Find ABHA — doc §7.6.1 "Search ABHA using Mobile". SPEC-24 §7 step 6 (Patient) — closes the one
// real gap in this file: before creating a NEW ABHA, front desk needs to check whether the
// patient already has one. Confirmed directly against the doc's own sample request/response
// (not assumed): the two follow-up steps (send an OTP to the chosen match, verify it) are the
// SAME generic `/profile/login/request/otp` + `/profile/login/verify` pair the Login routes below
// already wrap fully parametrically (loginHint:'index', the matched entry's own index RSA-
// encrypted as loginId, otpSystem:'abdm') — so this is the only new endpoint this gap needs.
// =================================================================================================

// POST { mobile } -> { success, txnId, matches: [{index, abhaNumber, name, gender, kycVerified, authMethods}] }
abhaRoutes.post('/find/search', async (c) => {
    const { mobile } = await c.req.json();
    if (!mobile) return c.json({ success: false, error: 'mobile is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);
    const encryptedMobile = await encryptForAbha(config, mobile, accessToken);

    const result = await callAbdm({
        url: `${config.abhaBaseUrl}/profile/account/abha/search`,
        xCmId: config.xCmId,
        accessToken,
        body: { scope: ['search-abha'], mobile: encryptedMobile },
    });

    // The doc's own sample response wraps a single {txnId, ABHA:[...]} object in a top-level
    // array — defensively unwrapped here rather than assumed, since every OTHER ABHA endpoint in
    // this file returns a bare object.
    const payload = Array.isArray(result) ? result[0] : result;
    const matches = (payload?.ABHA || []).map((m) => ({
        index: m.index, abhaNumber: m.ABHANumber, name: m.name, gender: m.gender,
        kycVerified: m.kycVerified, authMethods: m.authMethods,
    }));

    return c.json({ success: true, txnId: payload?.txnId, matches });
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
        otp, // was missing: ABDM received an encrypted "undefined" as the OTP
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

// =================================================================================================
// ABDM M1 lanes beyond Aadhaar OTP (NHA ABHA V3 API doc v1, 31-07-2025)
// =================================================================================================

/** What every enrolment that creates an account answers with: { txnId, tokens, ABHAProfile }. */
function enrolled(c, result) {
    const { photo, ...profile } = result.ABHAProfile || {};
    return c.json({
        success: true,
        txnId: result.txnId,
        isNew: result.isNew,
        abhaToken: result.tokens?.token,
        abhaTokenExpiresIn: result.tokens?.expiresIn,
        profile,
    });
}

// ── Creation via Aadhaar face authentication (doc §6.2.2) ────────────────────────────────────
// No fingerprint device needed: the patient's own phone does the face capture. ABDM issues a
// txnId; the patient scans a QR of <phr>/face-auth?txnId=… with the ABHA app and completes the
// capture there; the clinic polls capturePID until COMPLETE, then enrols with the Aadhaar number.

// POST {} -> { txnId, qrUrl }
abhaRoutes.post('/enrollment/face/init', async (c) => {
    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);
    const result = await callAbdm({
        url: `${config.abhaBaseUrl}/enrollment/enrol/auth/init`,
        xCmId: config.xCmId,
        accessToken,
        body: { scope: ['abha-enrol', 'face-auth'] },
    });
    await putTransactionState(c.env, result.txnId, { flow: 'abha-face-enrollment', step: 'awaiting-capture' });
    return c.json({ success: true, txnId: result.txnId, qrUrl: `${config.phrBaseUrl}/face-auth?txnId=${encodeURIComponent(result.txnId)}` });
});

// POST { txnId } -> { status: PENDING | VERIFIED | FAILED | COMPLETE, txnId }
abhaRoutes.post('/enrollment/face/status', async (c) => {
    const { txnId } = await c.req.json();
    if (!txnId) return c.json({ success: false, error: 'txnId is required' }, 400);
    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);
    const result = await callAbdm({
        url: `${config.abhaBaseUrl}/enrollment/enrol/capturePID`,
        xCmId: config.xCmId,
        accessToken,
        body: { scope: ['abha-enrol', 'face-verify'], txnId },
    });
    return c.json({ success: true, status: result.status, message: result.message, txnId: result.txnId || txnId });
});

// POST { txnId, aadhaar, mobile } -> same shape as /enrollment/verify-aadhaar-otp
abhaRoutes.post('/enrollment/face/enrol', async (c) => {
    const { txnId, aadhaar, mobile } = await c.req.json();
    if (!txnId || !aadhaar || !mobile) return c.json({ success: false, error: 'txnId, aadhaar and mobile are required' }, 400);
    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);
    const encryptedAadhaar = await encryptForAbha(config, aadhaar, accessToken);
    const result = await callAbdm({
        url: `${config.abhaBaseUrl}/enrollment/enrol/byAadhaar`,
        xCmId: config.xCmId,
        accessToken,
        body: {
            authData: { authMethods: ['face_auth'], face: { txnId, aadhaar: encryptedAadhaar, mobile } },
            consent: { code: 'abha-enrollment', version: '1.4' },
        },
    });
    await putTransactionState(c.env, result.txnId || txnId, { step: 'face-enrolled' });
    return enrolled(c, result);
});

// ── Creation via driving licence (doc §4.0) ──────────────────────────────────────────────────
// Mobile OTP (scope dl-flow), then the licence with both sides' photos, checked by ABDM against
// the licence registry. Answers with an enrolment number, not an ABHA session.
const DL_SCOPE = ['abha-enrol', 'mobile-verify', 'dl-flow'];
const abdmTimeStamp = () => new Date().toISOString().replace('T', ' ').slice(0, 19);

// POST { mobile } -> { txnId, message }
abhaRoutes.post('/enrollment/dl/mobile-otp', async (c) => {
    const { mobile } = await c.req.json();
    if (!/^[6-9]\d{9}$/.test(String(mobile ?? ''))) return c.json({ success: false, error: 'A 10-digit mobile number is required' }, 400);
    const result = await requestOtp(c, { path: '/enrollment/request/otp', scope: DL_SCOPE, loginHint: 'mobile', plaintextLoginId: mobile, otpSystem: 'abdm' });
    await putTransactionState(c.env, result.txnId, { flow: 'abha-dl-enrollment', step: 'mobile-otp-sent' });
    return c.json({ success: true, txnId: result.txnId, message: result.message });
});

// POST { txnId, otp } -> { txnId, authResult }
abhaRoutes.post('/enrollment/dl/verify-mobile-otp', async (c) => {
    const { txnId, otp } = await c.req.json();
    if (!txnId || !otp) return c.json({ success: false, error: 'txnId and otp are required' }, 400);
    const attempt = await recordOtpAttempt(c.env, txnId);
    if (!attempt.allowed) return c.json({ success: false, error: 'Too many OTP attempts for this transaction' }, 429);
    const result = await verifyOtp(c, { path: '/enrollment/auth/byAbdm', scope: DL_SCOPE, txnId, otp, extraOtpFields: { timeStamp: abdmTimeStamp() } });
    await putTransactionState(c.env, txnId, { step: 'mobile-otp-verified' });
    return c.json({ success: true, txnId: result.txnId || txnId, authResult: result.authResult, message: result.message });
});

// POST { txnId, documentId, firstName, middleName?, lastName?, dob (yyyy-mm-dd), gender,
//        frontSidePhoto, backSidePhoto (base64 JPEG), address, state, district, pinCode }
//   -> { enrolment: { enrolmentNumber, enrolmentState, abhaStatus, phrAddress, ... } }
abhaRoutes.post('/enrollment/dl/document', async (c) => {
    const b = await c.req.json();
    const missing = ['txnId', 'documentId', 'firstName', 'dob', 'gender', 'frontSidePhoto', 'backSidePhoto', 'address', 'state', 'district', 'pinCode'].filter((k) => !b[k]);
    if (missing.length) return c.json({ success: false, error: `Missing: ${missing.join(', ')}` }, 400);
    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);
    const result = await callAbdm({
        url: `${config.abhaBaseUrl}/enrollment/enrol/byDocument`,
        xCmId: config.xCmId,
        accessToken,
        body: {
            txnId: b.txnId, documentType: 'DRIVING_LICENCE', documentId: b.documentId,
            firstName: b.firstName, middleName: b.middleName || '', lastName: b.lastName || '',
            dob: b.dob, gender: b.gender, frontSidePhoto: b.frontSidePhoto, backSidePhoto: b.backSidePhoto,
            address: b.address, state: b.state, district: b.district, pinCode: b.pinCode,
            consent: { code: 'abha-enrollment', version: '1.4' },
        },
    });
    await clearTransactionState(c.env, b.txnId);
    return c.json({ success: true, enrolment: result.EnrolProfile || result.enrolProfile || result });
});

// ── Verification of an ABHA address by OTP (doc §14.1 / §12 step 2-3) ────────────────────────
// The OTP goes to the mobile linked to that ABHA address; the answer is a PHR session, so the
// profile and card are read with X-ABHA-Kind: phr.
const ADDRESS_LOGIN = { scope: ['abha-address-login', 'mobile-verify'], loginHint: 'abha-address', otpSystem: 'abdm' };

// POST { abhaAddress } -> { txnId, message }
abhaRoutes.post('/login/address/request-otp', async (c) => {
    const { abhaAddress } = await c.req.json();
    const address = String(abhaAddress ?? '').trim().toLowerCase();
    if (!/^[a-z0-9._]{3,}@(sbx|abdm)$/.test(address)) return c.json({ success: false, error: 'An ABHA address looks like name@sbx' }, 400);
    const result = await requestOtp(c, { path: '/phr/web/login/abha/request/otp', ...ADDRESS_LOGIN, plaintextLoginId: address });
    await putTransactionState(c.env, result.txnId, { flow: 'abha-address-login', step: 'otp-sent' });
    return c.json({ success: true, txnId: result.txnId, message: result.message });
});

// POST { txnId, otp } -> { abhaToken, tokenKind: 'phr', account }
abhaRoutes.post('/login/address/verify-otp', async (c) => {
    const { txnId, otp } = await c.req.json();
    if (!txnId || !otp) return c.json({ success: false, error: 'txnId and otp are required' }, 400);
    const attempt = await recordOtpAttempt(c.env, txnId);
    if (!attempt.allowed) return c.json({ success: false, error: 'Too many OTP attempts for this transaction' }, 429);
    const result = await verifyOtp(c, { path: '/phr/web/login/abha/verify', scope: ADDRESS_LOGIN.scope, txnId, otp });
    await clearTransactionState(c.env, txnId);
    const token = result?.tokens?.token ?? result?.token;
    if (!token) throw new HttpError(502, result?.message || 'ABDM did not return a session');
    const { profilePhoto, ...account } = (result.users || result.accounts || [])[0] || {};
    return c.json({ success: true, abhaToken: token, tokenKind: 'phr', account });
});

// ── With the patient's ABHA session: profile and ABHA card (doc §9, §11, §14.4) ───────────────
// X-ABHA-Token plus X-ABHA-Kind (abha | phr, default abha). The card is ABDM's own (PNG or PDF).
const sessionOf = (c) => ({ token: requireAbhaToken(c), kind: c.req.header('X-ABHA-Kind') === 'phr' ? 'phr' : 'abha' });

abhaRoutes.get('/session/profile', async (c) => {
    const { photo, ...profile } = await fetchProfile(c.env, sessionOf(c));
    return c.json({ success: true, profile: { ...profile, ...(c.req.query('photo') === '1' && photo ? { photo } : {}) } });
});

abhaRoutes.get('/session/card', async (c) => c.json({ success: true, ...(await fetchCard(c.env, sessionOf(c))) }));
