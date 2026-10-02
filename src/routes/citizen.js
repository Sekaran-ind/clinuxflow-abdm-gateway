// Citizen routes, for cubo-diary: people with no ClinuxFlow account.
//
//   POST /citizen/abha/login/request-otp   { method, abhaNumber | abhaAddress } -> { txnId, message }
//   POST /citizen/abha/login/verify-otp    { method, txnId, otp }       -> { abhaToken, tokenKind, expiresIn, account }
//   GET  /citizen/abha/profile[?photo=1]   X-ABHA-Token, X-ABHA-Kind    -> the profile fields the diary uses
//   GET  /citizen/abha/card                X-ABHA-Token, X-ABHA-Kind    -> { contentType, data (base64) }
//   POST /citizen/uhi/search               { by, code }                 -> { transactionId, readKey }
//   GET  /citizen/uhi/transactions/:id     X-Read-Key                   -> { catalogs, order? }
//   POST /citizen/uhi/init|confirm         X-Read-Key + ABHA headers    -> booking for the signed-in ABHA
//
// Two kinds of ABHA session: signing in with an ABHA number gives an ABHA token ("abha": profile
// and card under /profile/account); signing in with an ABHA address gives a PHR token ("phr":
// profile and card under /phr/web/login/profile). The caller says which with X-ABHA-Kind.
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
import { AbdmApiError } from '../lib/abdmClient.js';
import { getAbdmConfig } from '../lib/config.js';
import { getAccessToken, putTransactionState, recordOtpAttempt, clearTransactionState } from '../lib/sessionToken.js';
import { rateLimit } from '../lib/rateLimit.js';
import { requestOtp, verifyOtp } from './abha.js';
import { buildEuaCitizenRoutes } from '../uhi/eua/routes.js';
import { euaDeps } from './uhi.js';

// ABHA v3 login variants (NHA ABHA V3 API doc, 7.3 "Login via Abha OTP"). With 'abha-mobile' ABDM
// sends the OTP to the mobile linked to the ABHA; with 'abha-aadhaar' UIDAI sends it to the
// Aadhaar-linked mobile (this one depends on the sandbox's Aadhaar gateway).
//
// 'abha-address': ABDM's PHR login (NHA ABHA V3 doc, ABHA address login): OTP to the mobile
// linked to that ABHA address; returns a PHR token and the profile photo.
const NUMBER_PATHS = { request: '/profile/login/request/otp', verify: '/profile/login/verify', kind: 'abha' };
const ADDRESS_PATHS = { request: '/phr/web/login/abha/request/otp', verify: '/phr/web/login/abha/verify', kind: 'phr' };
export const ABHA_LOGIN = {
    'abha-mobile': { scope: ['abha-login', 'mobile-verify'], loginHint: 'abha-number', otpSystem: 'abdm', ...NUMBER_PATHS },
    'abha-aadhaar': { scope: ['abha-login', 'aadhaar-verify'], loginHint: 'abha-number', otpSystem: 'aadhaar', ...NUMBER_PATHS },
    'abha-address': { scope: ['abha-address-login', 'mobile-verify'], loginHint: 'abha-address', otpSystem: 'abdm', ...ADDRESS_PATHS },
};

const clientIp = (c) => c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';
const sha256Hex = async (text) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))].map((b) => b.toString(16).padStart(2, '0')).join('');

/** 14 digits, returned in ABDM's 2-4-4-4 form, or null. */
export function normaliseAbhaNumber(input) {
    const d = String(input ?? '').replace(/\D/g, '');
    return d.length === 14 ? `${d.slice(0, 2)}-${d.slice(2, 6)}-${d.slice(6, 10)}-${d.slice(10)}` : null;
}

/** An ABHA address like name@sbx (sandbox) or name@abdm, lower-cased, or null. */
export function normaliseAbhaAddress(input) {
    const a = String(input ?? '').trim().toLowerCase();
    return /^[a-z0-9._]{3,}@(sbx|abdm)$/.test(a) ? a : null;
}

/** The login id for a method: an ABHA number in 2-4-4-4 form, or an ABHA address. */
const loginIdFor = (m, body) => (m.loginHint === 'abha-address' ? normaliseAbhaAddress(body.abhaAddress) : normaliseAbhaNumber(body.abhaNumber));

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
        key: async (c) => {
            const body = await c.req.json().catch(() => ({}));
            return sha256Hex(normaliseAbhaNumber(body.abhaNumber) ?? normaliseAbhaAddress(body.abhaAddress) ?? 'invalid');
        },
    }),
    async (c) => {
        const body = await c.req.json().catch(() => ({}));
        const m = method(body.method);
        const loginId = loginIdFor(m, body);
        if (!loginId) throw new HttpError(400, m.loginHint === 'abha-address' ? 'An ABHA address looks like name@sbx.' : 'An ABHA number has 14 digits, e.g. 91-1234-5678-9012.');
        const result = await requestOtp(c, { path: m.request, scope: m.scope, loginHint: m.loginHint, plaintextLoginId: loginId, otpSystem: m.otpSystem });
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

    const result = await verifyOtp(c, { path: m.verify, scope: m.scope, txnId, otp });
    await clearTransactionState(c.env, txnId);
    // ABHA-number login: { token, accounts: [...] }; ABHA-address (PHR) login: { tokens: { token }, users: [...] }.
    const token = result?.token ?? result?.tokens?.token;
    if (!token) throw new HttpError(502, result?.message || 'ABDM did not return a session');
    const a = (result.accounts || result.users || [])[0] || {};
    return c.json({
        success: true,
        abhaToken: token,
        tokenKind: m.kind,
        expiresIn: result.expiresIn ?? result.tokens?.expiresIn,
        account: { abhaNumber: a.ABHANumber ?? a.abhaNumber, abhaAddress: a.preferredAbhaAddress ?? a.abhaAddress, name: a.name ?? a.fullName, kycVerified: a.kycVerified ?? (a.kycStatus ? a.kycStatus === 'VERIFIED' : undefined) },
    });
});

// The ABHA session a request carries: token and kind (abha | phr).
function session(c) {
    const token = c.req.header('X-ABHA-Token');
    if (!token) throw new HttpError(401, 'Sign in with ABHA first');
    return { token, kind: c.req.header('X-ABHA-Kind') === 'phr' ? 'phr' : 'abha' };
}

// Raw GET against ABHA with the user's token, for endpoints that return JSON or a file.
async function abhaGet(c, paths, { token }) {
    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);
    let last;
    // The sandbox PHR paths are given without hyphens in NHA's PDF (a text-extraction artefact:
    // production uses phr-card / abha-profile); the first that isn't 404 wins.
    for (const path of paths) {
        const res = await fetch(`${config.abhaBaseUrl}${path}`, {
            headers: { 'REQUEST-ID': crypto.randomUUID(), TIMESTAMP: new Date().toISOString(), 'X-CM-ID': config.xCmId, Authorization: `Bearer ${accessToken}`, 'X-token': `Bearer ${token}` },
        });
        if (res.status === 404 && path !== paths.at(-1)) {
            last = res;
            continue;
        }
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            let body;
            try {
                body = JSON.parse(text);
            } catch {
                body = text.slice(0, 300);
            }
            throw new AbdmApiError(res.status, body);
        }
        return res;
    }
    throw new AbdmApiError(last?.status ?? 404, 'not found');
}

const PROFILE_PATHS = { abha: ['/profile/account'], phr: ['/phr/web/login/profile/abha-profile', '/phr/web/login/profile/abhaprofile'] };
const CARD_PATHS = { abha: ['/profile/account/abha-card'], phr: ['/phr/web/login/profile/abha/phr-card', '/phr/web/login/profile/abha/phrcard'] };

/** The ABHA profile, normalised across the two token kinds. */
async function fetchProfile(c, s) {
    const p = await (await abhaGet(c, PROFILE_PATHS[s.kind], s)).json();
    return {
        abhaNumber: p.ABHANumber ?? p.abhaNumber ?? p.healthIdNumber,
        abhaAddress: p.preferredAbhaAddress ?? p.abhaAddress ?? p.healthId,
        name: p.name ?? p.fullName ?? [p.firstName, p.middleName, p.lastName].filter(Boolean).join(' '),
        firstName: p.firstName,
        middleName: p.middleName,
        lastName: p.lastName,
        gender: p.gender,
        dayOfBirth: p.dayOfBirth,
        monthOfBirth: p.monthOfBirth,
        yearOfBirth: p.yearOfBirth,
        districtName: p.districtName,
        stateName: p.stateName,
        kycVerified: p.kycVerified ?? (p.kycStatus ? p.kycStatus === 'VERIFIED' : undefined),
        photo: p.profilePhoto ?? null,
    };
}

citizenRoutes.get('/abha/profile', async (c) => {
    const { photo, ...profile } = await fetchProfile(c, session(c));
    // Only what the diary shows or uses: the photo only when asked for, no mobile, no raw KYC.
    return c.json({ success: true, profile: { ...profile, ...(c.req.query('photo') === '1' && photo ? { photo } : {}) } });
});

citizenRoutes.get('/abha/card', async (c) => {
    const res = await abhaGet(c, CARD_PATHS[session(c).kind], session(c));
    const contentType = (res.headers.get('content-type') || 'application/octet-stream').split(';')[0].trim();
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (!bytes.length) throw new HttpError(502, 'ABDM returned an empty ABHA card');
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return c.json({ success: true, contentType, data: btoa(bin) });
});

/** Who is booking: confirmed with ABDM from the caller's ABHA session, never from the request. */
async function verifyCustomer(c) {
    const p = await fetchProfile(c, session(c));
    if (!p.abhaNumber && !p.abhaAddress) throw new HttpError(401, 'The ABHA session could not be confirmed. Sign in with ABHA again.');
    return { abhaNumber: p.abhaNumber, abhaAddress: p.abhaAddress, name: p.name };
}

// Anonymous UHI search. Reads are frequent (the diary polls for on_search results).
citizenRoutes.use('/uhi/search', rateLimit({ bucket: 'citizen-uhi-search', limit: 20, windowSeconds: 60, key: clientIp }));
citizenRoutes.use('/uhi/init', rateLimit({ bucket: 'citizen-uhi-book', limit: 10, windowSeconds: 600, key: clientIp }));
citizenRoutes.route('/uhi', buildEuaCitizenRoutes(euaDeps, verifyCustomer));
