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
import { getAccessToken, getTransactionState, putTransactionState, recordOtpAttempt, clearTransactionState } from '../lib/sessionToken.js';
import { getCachedMasterData } from '../lib/masterData.js';

export const hprRoutes = new Hono();

hprRoutes.onError((err, c) => {
    if (err instanceof AbdmApiError) {
        // REQUEST-ID is what NHA's sandbox support asks for when reporting a failing call.
        console.error(`[hpr] ABDM error ${err.status} REQUEST-ID=${err.requestId}:`, JSON.stringify(err.body));
        return c.json({ success: false, error: 'ABDM request failed', abdmStatus: err.status, abdmBody: err.body, abdmRequestId: err.requestId }, 502);
    }
    console.error('[hpr] unexpected error:', err);
    return c.json({ success: false, error: err.message }, 500);
});

// Every ABDM-encryption call needs a fresh public key — HPR's is a different key/endpoint from
// ABHA's, and a different padding scheme (PKCS1 vs OAEP). See src/lib/encryption.js.
//
// The cert endpoint needs the gateway's own access token: without it the sandbox answers 401
// ("Failed to fetch ABDM public key ... HTTP 401", seen live 2026-09-30 on Aadhaar OTP). The ABHA
// cert fetch was fixed the same way earlier; this one had been missed. getAccessToken() is cached
// by the SessionTokenManager Durable Object, so asking for it here costs nothing extra.
async function encryptForHpr(env, config, plaintext) {
    const accessToken = await getAccessToken(env);
    const publicKey = await fetchPublicKey(`${config.hprHfrBaseUrl}/api/v1/auth/cert`, accessToken);
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
        encryptForHpr(c.env, config, aadhaar),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v2/registration/aadhaar/generateOtp`,
        xCmId: config.xCmId,
        accessToken,
        body: { aadhaar: encryptedAadhaar },
    });

    // Diagnostics without personal data: which kind of number was used (12-digit Aadhaar or
    // 16-digit Virtual ID) and when the OTP went out, so a failed verification can be explained.
    const idKind = String(aadhaar).replace(/\D/g, '').length === 16 ? 'vid' : 'aadhaar';
    await putTransactionState(c.env, result.txnId, { flow: 'hpr-aadhaar-registration', step: 'aadhaar-otp-sent', idKind, otpSentAt: Date.now() });
    console.log(`[hpr] aadhaar OTP sent txnId=${result.txnId} idKind=${idKind}`);

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
        encryptForHpr(c.env, config, otp),
    ]);

    let result;
    try {
        result = await callAbdm({
            url: `${config.hprHfrBaseUrl}/v2/registration/aadhaar/verifyOTP`,
            xCmId: config.xCmId,
            accessToken,
            body: { domainName: '@hpr.abdm', idType: 'hpr_id', otp: encryptedOtp, restrictions: '', txnId },
        });
    } catch (err) {
        // "Failed to retrieve aadhaar transaction details" (HIS-500) has been seen live; record what
        // can explain it (number kind, time since the OTP, attempts) without any personal data.
        const state = await getTransactionState(c.env, txnId).catch(() => null);
        const seconds = state?.otpSentAt ? Math.round((Date.now() - state.otpSentAt) / 1000) : 'unknown';
        console.error(`[hpr] verify-aadhaar-otp failed txnId=${txnId} knownTxn=${!!state?.otpSentAt} idKind=${state?.idKind ?? 'unknown'} secondsSinceOtp=${seconds} attempt=${attempt.attempts ?? '?'}`);
        throw err;
    }

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
        encryptForHpr(c.env, config, mobileNumber),
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
        encryptForHpr(c.env, config, otp),
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
        encryptForHpr(c.env, config, payload.email),
        encryptForHpr(c.env, config, payload.password),
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

// --- Update professional / documents / email verification --------------------------------------
// Real, confirmed-missing routes found by checking this gateway against the real NHPR sandbox
// docs (not assumed) — "3. Update healthcare professional API.pdf", "4.
// Update_Professional_Documents.pdf" (really just document RETRIEVAL — no separate upload
// endpoint is documented, despite the filename), "5. Generate, regenerate & verify Email link
// API-1.pdf". All three doc sets show the caller's own per-user HPR token (obtained via
// /auth/password-login above, or the Aadhaar/mobile-OTP login flow) traveling INSIDE the request
// body (hprToken/hpr_token), not as a header the way HFR's x-hprid-auth is — thin passthrough,
// same "don't re-declare ABDM's own schema" discipline hfr.js's own header already documents; the
// large "Update Professional" body especially would just drift out of sync if re-declared here.

// --- Register professional (full profile submission) --------------------------------------------
// Real, confirmed-missing route (explicit user instruction, reading the real spec PDF directly —
// "I do not see create HPR id which is likely the first step to registration... Refer to the
// document and create the Practitioner registration correctly"): createHprIdWithPreVerified
// (POST /registration/create above) only creates the HPR ID/account itself — the practitioner's
// full profile (personalInformation/contactInformation/registrationAcademic.registrationData[]/
// currentWorkDetails, the same 4 real blocks system-provider-composition-v1.yaml's own Personal
// Details/Qualifications/Work Experience fields are modeled against) is a SEPARATE, later
// submission via this endpoint. Same thin-passthrough discipline /professional/update already
// established below (a REAL sibling endpoint, same doctors/*-professional-new naming convention;
// the create-side path is inferred from that established pattern, not independently confirmed
// against the sandbox yet — verify the exact path/shape against a real response before relying on
// this beyond sandbox testing, same caveat this file's own header already gives for encryption).
hprRoutes.post('/professional/register', async (c) => {
    const body = await c.req.json();
    if (!body.hprToken) return c.json({ success: false, error: 'hprToken is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/apis/v1/doctors/register-professional-new`,
        xCmId: config.xCmId,
        accessToken,
        body,
    });

    return c.json({ success: true, ...result });
});

// --- Update professional -----------------------------------------------------------------------
// Body must include { hprToken, ... } — the full update-professional-new schema per the doc's own
// sample (practitioner/personalInformation/contactInformation/registrationAcademic/... nested
// objects), forwarded as-is.
hprRoutes.post('/professional/update', async (c) => {
    const body = await c.req.json();
    if (!body.hprToken) return c.json({ success: false, error: 'hprToken is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/apis/v1/doctors/update-professional-new`,
        xCmId: config.xCmId,
        accessToken,
        body,
    });

    return c.json({ success: true, ...result });
});

// --- Retrieve professional document list ---------------------------------------------------------
// Body: { hprid }.
hprRoutes.post('/professional/documents', async (c) => {
    const { hprid } = await c.req.json();
    if (!hprid) return c.json({ success: false, error: 'hprid is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/apis/v1/doctors/fetch-documents-list`,
        xCmId: config.xCmId,
        accessToken,
        body: { hprid },
    });

    return c.json({ success: true, ...result });
});

// --- Upload a professional document ---------------------------------------------------------------
// Real, confirmed-missing route — a prior session's own comment here claimed "no separate
// document-upload API is shown" in the doc; re-reading the real spec PDF directly (explicit user
// instruction) confirms this was wrong: the Upload Documents API is real spec section 10/11
// (POST .../uploads/upload-document), and document_id correlates one uploaded file to a specific
// qualification/registration entry (registrationAcademic.registrationData[].document_id) or the
// top-level profilePhoto — practitionerDocs.js's own DOC_TYPES (profilePhoto/degreeCertificate/
// registrationCertificate/proofOfWorkCertificate/proofOfNameChangeRegCertificate/
// proofOfNameChangeQualCertificate) are this same real 6-type list, not invented. Body: { hprToken,
// hprId, documentType, documentBase64, documentId? } — thin passthrough, same discipline as
// /professional/update.
hprRoutes.post('/professional/documents/upload', async (c) => {
    const body = await c.req.json();
    if (!body.hprToken) return c.json({ success: false, error: 'hprToken is required' }, 400);
    if (!body.documentType || !body.documentBase64) return c.json({ success: false, error: 'documentType and documentBase64 are required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        // hprHfrBaseUrl already carries the /v4/int prefix (see lib/config.js) — every other
        // route in this file appends only the path after that, same here.
        url: `${config.hprHfrBaseUrl}/apis/v1/uploads/upload-document`,
        xCmId: config.xCmId,
        accessToken,
        body,
    });

    return c.json({ success: true, ...result });
});

// --- Email verification (generate / regenerate / verify) -----------------------------------------
// Real 3-step flow, parallel to the existing mobile-OTP one above but for a professional's own
// official email address. Each body needs hpr_token (the caller's own per-user token) — same
// passthrough discipline as the two routes just above.
hprRoutes.post('/professional/email/generate-otp', async (c) => {
    const { hpr_token, emailAddress, otp_type } = await c.req.json();
    if (!hpr_token || !emailAddress) return c.json({ success: false, error: 'hpr_token and emailAddress are required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/apis/v1/doctors/generate-verification-email`,
        xCmId: config.xCmId,
        accessToken,
        body: { hpr_token, emailAddress, otp_type: otp_type || 'official' },
    });

    return c.json({ success: true, ...result });
});

hprRoutes.post('/professional/email/resend-otp', async (c) => {
    const { hpr_token, emailAddress, otp_type } = await c.req.json();
    if (!hpr_token || !emailAddress) return c.json({ success: false, error: 'hpr_token and emailAddress are required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/apis/v1/doctors/resent-verify-email`,
        xCmId: config.xCmId,
        accessToken,
        body: { hpr_token, emailAddress, otp_type: otp_type || 'official' },
    });

    return c.json({ success: true, ...result });
});

hprRoutes.post('/professional/email/verify-otp', async (c) => {
    const { hpr_token, hprId, officialEmail, emailOtp } = await c.req.json();
    if (!hpr_token || !hprId || !officialEmail || !emailOtp) {
        return c.json({ success: false, error: 'hpr_token, hprId, officialEmail and emailOtp are required' }, 400);
    }

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/apis/v1/doctors/verify-email-otp`,
        xCmId: config.xCmId,
        accessToken,
        // Real field name is hpr_id (snake_case) per the doc's own sample, unlike this route's
        // own query param — kept as the caller-facing hprId for consistency with every other
        // route in this file, translated at the wire boundary here.
        body: { hpr_token, hpr_id: hprId, officialEmail, emailOtp },
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

// --- Change/Forgot Password, Forgot HPR ID, Id Card, Account Profile, Logout -------------------
// The 4 real gaps found by reading "HPID/2. Change password.pdf", "HPID/3. Forgot hprid.pdf",
// and "HPID/1. Logout_Idcard_Account_Profile api.pdf" directly (not assumed) — none of these
// existed in this file before. Two genuinely different auth shapes below, both already
// established elsewhere in this file, not new conventions:
//   - Change/Forgot Password + Forgot HPR ID use the GATEWAY's own access token (getAccessToken),
//     same as every /registration/* and /professional/* route above.
//   - Id Card / Account Profile / Logout are different — the doc's own sample for each shows
//     ONLY "Authorization: Bearer <the user's own per-user token>", no gateway token involved at
//     all. The frontend supplies that per-user hprToken (from password-login or the OTP-login
//     flow) in the request body; it's forwarded here as callAbdm's own `accessToken` instead of
//     the gateway's, not stored or cached (scoped to one individual, same reasoning
//     /auth/password-login's own header comment already gives for not caching it).

// --- Forgot Password: via Mobile OTP ------------------------------------------------------------
hprRoutes.post('/password/forgot/mobile/send-otp', async (c) => {
    const { hprId } = await c.req.json();
    if (!hprId) return c.json({ success: false, error: 'hprId is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/password/recover/byMobile/sendMobileOTP`,
        xCmId: config.xCmId,
        accessToken,
        body: { hprId },
    });

    return c.json({ success: true, ...result });
});

hprRoutes.post('/password/forgot/mobile/verify-otp', async (c) => {
    const { txnId, otp } = await c.req.json();
    if (!txnId || !otp) return c.json({ success: false, error: 'txnId and otp are required' }, 400);

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedOtp] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(c.env, config, otp),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/password/recover/byMobile/verifyMobileOTP`,
        xCmId: config.xCmId,
        accessToken,
        body: { txnId, otp: encryptedOtp },
    });

    return c.json({ success: true, ...result });
});

// --- Forgot Password: via Aadhaar-linked mobile --------------------------------------------------
hprRoutes.post('/password/forgot/aadhaar/send-otp', async (c) => {
    const { hprId } = await c.req.json();
    if (!hprId) return c.json({ success: false, error: 'hprId is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/password/recover/byAadhaar`,
        xCmId: config.xCmId,
        accessToken,
        body: { hprId },
    });

    return c.json({ success: true, ...result });
});

hprRoutes.post('/password/forgot/aadhaar/verify-otp', async (c) => {
    const { txnId, otp } = await c.req.json();
    if (!txnId || !otp) return c.json({ success: false, error: 'txnId and otp are required' }, 400);

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedOtp] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(c.env, config, otp),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/password/recover/confirmByAadhaar`,
        xCmId: config.xCmId,
        accessToken,
        body: { txnId, otp: encryptedOtp },
    });

    return c.json({ success: true, ...result });
});

// --- Forgot Password: reset (shared by both mobile and Aadhaar flows above) --------------------
hprRoutes.post('/password/forgot/reset', async (c) => {
    const { txnId, newPassword } = await c.req.json();
    if (!txnId || !newPassword) return c.json({ success: false, error: 'txnId and newPassword are required' }, 400);

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedPassword] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(c.env, config, newPassword),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/password/resetPassword`,
        xCmId: config.xCmId,
        accessToken,
        body: { txnId, newPassword: encryptedPassword },
    });

    return c.json({ success: true, ...result });
});

// --- Change Password (already logged in) ---------------------------------------------------------
hprRoutes.post('/password/change', async (c) => {
    const { oldPassword, newPassword } = await c.req.json();
    if (!oldPassword || !newPassword) return c.json({ success: false, error: 'oldPassword and newPassword are required' }, 400);

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedOld, encryptedNew] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(c.env, config, oldPassword),
        encryptForHpr(c.env, config, newPassword),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/password/change/byPassword`,
        xCmId: config.xCmId,
        accessToken,
        body: { oldPassword: encryptedOld, newPassword: encryptedNew },
    });

    return c.json({ success: true, ...result });
});

// --- Forgot HPR ID: via Aadhaar ---------------------------------------------------------------
hprRoutes.post('/hprid/forgot/aadhaar/send-otp', async (c) => {
    const { aadhaar } = await c.req.json();
    if (!aadhaar) return c.json({ success: false, error: 'aadhaar is required' }, 400);

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedAadhaar] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(c.env, config, aadhaar),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1/forgot/hprId/aadhaar/generateOtp`,
        xCmId: config.xCmId,
        accessToken,
        body: { aadhaar: encryptedAadhaar, iAgree: true },
    });

    return c.json({ success: true, ...result });
});

hprRoutes.post('/hprid/forgot/aadhaar/verify-otp', async (c) => {
    const { txnId, otp } = await c.req.json();
    if (!txnId || !otp) return c.json({ success: false, error: 'txnId and otp are required' }, 400);

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedOtp] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(c.env, config, otp),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1/forgot/hprId/aadhaar`,
        xCmId: config.xCmId,
        accessToken,
        body: { txnId, otp: encryptedOtp },
    });

    // hprId/hprIdNumber come back here — never cache, this is the whole point of the call.
    return c.json({ success: true, ...result });
});

// --- Forgot HPR ID: via Mobile ------------------------------------------------------------------
hprRoutes.post('/hprid/forgot/mobile/send-otp', async (c) => {
    const { mobileNumber } = await c.req.json();
    if (!mobileNumber) return c.json({ success: false, error: 'mobileNumber is required' }, 400);

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedMobile] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(c.env, config, mobileNumber),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1/forgot/hprId/mobile/generateOtp`,
        xCmId: config.xCmId,
        accessToken,
        body: { mobileNumber: encryptedMobile },
    });

    return c.json({ success: true, ...result });
});

hprRoutes.post('/hprid/forgot/mobile/verify-otp', async (c) => {
    const { txnId, otp, firstName, middleName, lastName, yearOfBirth, monthOfBirth, dayOfBirth, gender } = await c.req.json();
    if (!txnId || !otp) return c.json({ success: false, error: 'txnId and otp are required' }, 400);

    const config = getAbdmConfig(c.env);
    const [accessToken, encryptedOtp] = await Promise.all([
        getAccessToken(c.env),
        encryptForHpr(c.env, config, otp),
    ]);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1/forgot/hprId/mobile`,
        xCmId: config.xCmId,
        accessToken,
        body: { txnId, otp: encryptedOtp, firstName, middleName, lastName, yearOfBirth, monthOfBirth, dayOfBirth, gender },
    });

    return c.json({ success: true, ...result });
});

// --- Id Card ---------------------------------------------------------------------------------
// Per-user hprToken only (see this section's own header note) — no gateway access token used.
hprRoutes.post('/account/id-card', async (c) => {
    const { hprToken } = await c.req.json();
    if (!hprToken) return c.json({ success: false, error: 'hprToken is required' }, 400);

    const config = getAbdmConfig(c.env);
    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1/account/getIdCard`,
        method: 'GET',
        xCmId: config.xCmId,
        accessToken: hprToken,
    });

    // { pdf: <base64> } — handed straight back; this Worker never stores it.
    return c.json({ success: true, ...result });
});

// --- Account / Profile ------------------------------------------------------------------------
hprRoutes.post('/account/profile', async (c) => {
    const { hprToken } = await c.req.json();
    if (!hprToken) return c.json({ success: false, error: 'hprToken is required' }, 400);

    const config = getAbdmConfig(c.env);
    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1/account/information`,
        method: 'GET',
        xCmId: config.xCmId,
        accessToken: hprToken,
    });

    return c.json({ success: true, ...result });
});

// --- Logout --------------------------------------------------------------------------------------
hprRoutes.post('/account/logout', async (c) => {
    const { hprToken } = await c.req.json();
    if (!hprToken) return c.json({ success: false, error: 'hprToken is required' }, 400);

    const config = getAbdmConfig(c.env);
    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v4/auth/logout`,
        method: 'GET',
        xCmId: config.xCmId,
        accessToken: hprToken,
    });

    return c.json({ success: true, ...result });
});
