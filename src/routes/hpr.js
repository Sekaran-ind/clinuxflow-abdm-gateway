// HPR (Health Professional Registry) routes — Aadhaar-based registration flow for doctors/nurses,
// plus password login (needed to obtain the per-user HPR token that HFR facility-creation calls
// require as x-hprid-auth) and professional lookup.
//
// Encryption note: per the supplied "Register Healthcare Professional" doc, which fields get
// RSA/ECB/PKCS1-encrypted is inconsistent by design across these endpoints — e.g. `aadhaar` is
// encrypted in generate-otp, but the `mobile` field in generate-mobile-otp is sent PLAINTEXT
// (only the OTP itself is encrypted when verifying). Each handler below follows exactly what the
// sample payloads in the doc show rather than blanket-encrypting every field — double check
// against the swagger/Postman collection before relying on this for anything beyond sandbox
// testing.
//
// None of these calls hit ABDM directly from the browser/Alpine layer — the frontend posts plain
// form values to this Worker over HTTPS, and encryption + the ABDM call both happen here.

import { Hono } from 'hono';
import { callAbdm, AbdmApiError } from '../lib/abdmClient.js';
import { getAbdmConfig } from '../lib/config.js';
import { fetchPublicKey, encryptPkcs1 } from '../lib/encryption.js';
import { getAccessToken, putTransactionState, recordOtpAttempt, clearTransactionState } from '../lib/sessionToken.js';
import { getCachedMasterData } from '../lib/masterData.js';

export const hprRoutes = new Hono();

hprRoutes.onError((err, c) => {
    if (err instanceof AbdmApiError) {
        console.error(`[hpr] ABDM error ${err.status}:`, JSON.stringify(err.body));
        return c.json({ success: false, error: 'ABDM request failed', abdmStatus: err.status, abdmBody: err.body }, 502);
    }
    console.error('[hpr] unexpected error:', err);
    return c.json({ success: false, error: err.message }, 500);
});

// Every ABDM-encryption call needs a fresh public key — HPR's is a different key/endpoint from
// ABHA's, and a different padding scheme (PKCS1 vs OAEP). See src/lib/encryption.js.
async function encryptForHpr(config, plaintext) {
    const publicKey = await fetchPublicKey(`${config.hprHfrBaseUrl}/api/v1/auth/cert`);
    return encryptPkcs1(publicKey, plaintext);
}

// --- Step 1: Generate Aadhaar OTP -----------------------------------------------------------
// POST { aadhaar: "123412341234" }
hprRoutes.post('/registration/aadhaar-otp', async (c) => {
    const { aadhaar } = await c.req.json();
    if (!aadhaar) return c.json({ success: false, error: 'aadhaar is required' }, 400);

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedAadhaar] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(config, aadhaar),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v2/registration/aadhaar/generateOtp`,
        xCmId: config.xCmId,
        accessToken,
        body: { aadhaar: encryptedAadhaar },
    });

    await putTransactionState(c.env, result.txnId, { flow: 'hpr-aadhaar-registration', step: 'aadhaar-otp-sent' });

    // Never echo back the full mobile number to the caller — mask it, the doc's own sample
    // responses already mask everything but the last few digits.
    return c.json({ success: true, txnId: result.txnId, maskedMobile: result.mobileNumber });
});

// --- Step 2: Verify Aadhaar OTP --------------------------------------------------------------
hprRoutes.post('/registration/verify-aadhaar-otp', async (c) => {
    const { txnId, otp } = await c.req.json();
    if (!txnId || !otp) return c.json({ success: false, error: 'txnId and otp are required' }, 400);

    const attempt = await recordOtpAttempt(c.env, txnId);
    if (!attempt.allowed) {
        return c.json({ success: false, error: 'Too many OTP attempts for this transaction' }, 429);
    }

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedOtp] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(config, otp),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v2/registration/aadhaar/verifyOTP`,
        xCmId: config.xCmId,
        accessToken,
        body: { domainName: '@hpr.abdm', idType: 'hpr_id', otp: encryptedOtp, restrictions: '', txnId },
    });

    await putTransactionState(c.env, txnId, { step: 'aadhaar-otp-verified' });
    return c.json({ success: true, txnId: result.txnId });
});

// --- Step 3: Check if an HPID already exists for this Aadhaar (avoid duplicate registration) --
hprRoutes.post('/registration/check-account-exists', async (c) => {
    const { txnId } = await c.req.json();
    if (!txnId) return c.json({ success: false, error: 'txnId is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1/registration/aadhaar/checkHpIdAccountExist`,
        xCmId: config.xCmId,
        accessToken,
        body: { txnId },
    });

    const exists = Boolean(result.hprId);
    await putTransactionState(c.env, txnId, { step: 'account-checked', hpidExists: exists });

    // Demographic details are useful to prefill the registration form, but strip the base64
    // profilePhoto blob and any token before returning — the caller doesn't need it at this step.
    const { profilePhoto, token, ...demographics } = result;
    return c.json({ success: true, hpidExists: exists, demographics });
});

// --- Step 4a: Confirm Aadhaar-linked mobile matches the number the user provides --------------
hprRoutes.post('/registration/demographic-auth-mobile', async (c) => {
    const { txnId, mobileNumber } = await c.req.json();
    if (!txnId || !mobileNumber) return c.json({ success: false, error: 'txnId and mobileNumber are required' }, 400);

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedMobile] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(config, mobileNumber),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v2/registration/aadhaar/demographicAuthViaMobile`,
        xCmId: config.xCmId,
        accessToken,
        body: { txnId, mobileNumber: encryptedMobile },
    });

    return c.json({ success: true, txnId: result.txnId });
});

// --- Step 4b: Fallback path — send a fresh OTP to a mobile number that doesn't match Aadhaar's -
// Note: `mobile` is sent PLAINTEXT here per the doc's sample payload (see file header note).
hprRoutes.post('/registration/mobile-otp', async (c) => {
    const { txnId, mobile } = await c.req.json();
    if (!txnId || !mobile) return c.json({ success: false, error: 'txnId and mobile are required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1/registration/aadhaar/generateMobileOTP`,
        xCmId: config.xCmId,
        accessToken,
        body: { mobile, txnId },
    });

    return c.json({ success: true, txnId: result.txnId });
});

hprRoutes.post('/registration/verify-mobile-otp', async (c) => {
    const { txnId, otp } = await c.req.json();
    if (!txnId || !otp) return c.json({ success: false, error: 'txnId and otp are required' }, 400);

    const attempt = await recordOtpAttempt(c.env, txnId);
    if (!attempt.allowed) {
        return c.json({ success: false, error: 'Too many OTP attempts for this transaction' }, 429);
    }

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedOtp] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(config, otp),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1/registration/aadhaar/verifyMobileOTP`,
        xCmId: config.xCmId,
        accessToken,
        body: { otp: encryptedOtp, txnId },
    });

    await putTransactionState(c.env, txnId, { step: 'mobile-otp-verified' });
    return c.json({ success: true, txnId: result.txnId });
});

// --- Step 5: HPID username suggestions --------------------------------------------------------
hprRoutes.get('/registration/hpid-suggestions', async (c) => {
    const txnId = c.req.query('txnId');
    if (!txnId) return c.json({ success: false, error: 'txnId query param is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const suggestions = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1/registration/aadhaar/hpid/suggestion`,
        xCmId: config.xCmId,
        accessToken,
        body: { txnId },
    });

    return c.json({ success: true, suggestions });
});

// --- Step 6: Create the HPR ID ------------------------------------------------------------------
// Body: { txnId, email, password, firstName, middleName, lastName, hprId, sourceType,
//         hpCategoryCode, hpSubCategoryCode, stateCode, districtCode, council, role,
//         profilePhotoBase64? }
// See the doc's category/subcategory/role code tables — worth surfacing those as a small
// lookup table in the frontend rather than free-typed integers.
hprRoutes.post('/registration/create', async (c) => {
    const payload = await c.req.json();
    const required = ['txnId', 'email', 'password', 'firstName', 'lastName', 'hprId', 'stateCode', 'districtCode', 'role'];
    const missing = required.filter((field) => !payload[field]);
    if (missing.length) {
        return c.json({ success: false, error: `Missing required field(s): ${missing.join(', ')}` }, 400);
    }

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedEmail, encryptedPassword] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(config, payload.email),
        encryptForHpr(config, payload.password),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v2/registration/aadhaar/createHprIdWithPreVerified`,
        xCmId: config.xCmId,
        accessToken,
        body: {
            txnId: payload.txnId,
            email: encryptedEmail,
            idType: 'hpr_id',
            domainName: '@hpr.abdm',
            firstName: payload.firstName,
            middleName: payload.middleName || '',
            lastName: payload.lastName,
            password: encryptedPassword,
            profilePhoto: payload.profilePhotoBase64 || '',
            hprId: payload.hprId,
            sourceType: payload.sourceType || 'AADHAAR',
            hpCategoryCode: payload.hpCategoryCode,
            hpSubCategoryCode: payload.hpSubCategoryCode,
            clientId: '',
            stateCode: payload.stateCode,
            districtCode: payload.districtCode,
            council: payload.council ?? false,
            role: payload.role,
        },
    });

    await clearTransactionState(c.env, payload.txnId);

    // `token` here is a per-user HPR auth token (short-lived) — hand it back to the caller so
    // clinuxflow-api can persist hprIdNumber against the doctor's ClinuxFlow profile, but this
    // gateway itself does not store business records; that's clinuxflow-api's D1, not ours.
    return c.json({
        success: true,
        hprIdNumber: result.hprIdNumber,
        hprId: result.hprId,
        name: result.name,
        token: result.token,
    });
});

// --- HPR password login -----------------------------------------------------------------------
// Needed to obtain a per-user HPR token: HFR's facility basic-information API requires this as
// the x-hprid-auth header, for the individual acting as Facility Manager (see routes/hfr.js).
// Per the doc's own sample payload, the password is sent PLAINTEXT here (unlike createHprId,
// which encrypts it) — flagged in the file header note; verify against swagger before shipping.
hprRoutes.post('/auth/password-login', async (c) => {
    const { hprId, password } = await c.req.json();
    if (!hprId || !password) return c.json({ success: false, error: 'hprId and password are required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/api/v1/auth/authPassword`,
        xCmId: config.xCmId,
        accessToken,
        body: { idType: 'hpr_id', domainName: '@hpr.abdm', hprId, password },
    });

    // This is a per-user token, distinct from the gateway's own client-credential access token.
    // Hand it straight back to the authenticated caller — do not cache it in a shared DO, since
    // it's scoped to one individual, not the whole Worker.
    return c.json({ success: true, token: result.token, expiresIn: result.expiresIn });
});

// --- Fetch professional details -----------------------------------------------------------------
hprRoutes.post('/professional/fetch', async (c) => {
    const { hprId, name, contactNumber, state, registrationNumber } = await c.req.json();

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/apis/v1/doctors/fetch-professional-info`,
        xCmId: config.xCmId,
        accessToken,
        body: {
            practitioner: {
                id: hprId || '',
                name: name || '',
                contactNumber: contactNumber || '',
                state: state || '',
                registrationNumber: registrationNumber || '',
            },
        },
    });

    return c.json({ success: true, ...result });
});

// --- Master data (cached) ----------------------------------------------------------------------
// A small starter set — the same getCachedMasterData/callAbdm pattern extends to the rest of the
// Master API HPR doc's list (universities, courses, colleges, nurse councils, sub-districts, ...)
// as those fields show up in the actual registration form.
hprRoutes.get('/master/system-of-medicine', async (c) => {
    const config = getAbdmConfig(c.env);
    const data = await getCachedMasterData(c.env.MASTER_DATA_CACHE, 'hpr:system-of-medicine', async () => {
        const accessToken = await getAccessToken(c.env);
        return callAbdm({
            url: `${config.hprHfrBaseUrl}/apis/v1/masters/system-of-medicines`,
            method: 'GET',
            xCmId: config.xCmId,
            accessToken,
        });
    });
    return c.json({ success: true, data });
});

hprRoutes.get('/master/medical-councils', async (c) => {
    const config = getAbdmConfig(c.env);
    const data = await getCachedMasterData(c.env.MASTER_DATA_CACHE, 'hpr:medical-councils', async () => {
        const accessToken = await getAccessToken(c.env);
        return callAbdm({
            url: `${config.hprHfrBaseUrl}/apis/v1/masters/medical-councils`,
            method: 'GET',
            xCmId: config.xCmId,
            accessToken,
        });
    });
    return c.json({ success: true, data });
});

hprRoutes.get('/master/states', async (c) => {
    const config = getAbdmConfig(c.env);
    const data = await getCachedMasterData(c.env.MASTER_DATA_CACHE, 'hpr:states', async () => {
        const accessToken = await getAccessToken(c.env);
        return callAbdm({
            url: `${config.hprHfrBaseUrl}/apis/v1/masters/states`,
            method: 'GET',
            xCmId: config.xCmId,
            accessToken,
        });
    });
    return c.json({ success: true, data });
});

hprRoutes.get('/master/districts/:stateId', async (c) => {
    const stateId = c.req.param('stateId');
    const config = getAbdmConfig(c.env);
    const data = await getCachedMasterData(c.env.MASTER_DATA_CACHE, `hpr:districts:${stateId}`, async () => {
        const accessToken = await getAccessToken(c.env);
        return callAbdm({
            url: `${config.hprHfrBaseUrl}/apis/v1/masters/district/${stateId}`,
            method: 'GET',
            xCmId: config.xCmId,
            accessToken,
        });
    });
    return c.json({ success: true, data });
});
