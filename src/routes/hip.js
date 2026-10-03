// ABDM Milestone 2: ClinuxFlow facilities as Health Information Providers (NHA M2 sandbox doc
// v2.8, 13-02-2026; request shapes checked against NHA's own ABDM wrapper, NHA-ABDM/ABDM-wrapper v3).
//
// A clinic's visit record lives in the browser (local-first). When staff share a visit to the
// patient's ABHA (Checkout), the browser sends its FHIR document here: it becomes a care context,
// kept in the shared D1 so this gateway can serve it whenever a consented HIU asks.
//
// HIP-initiated linking (doc §4)
//   POST /hie/hip/care-contexts             staff: store a visit's FHIR document and link it
//   -> {hiecm}/v3/token/generate-token      a link token for (facility, ABHA address)
//   <- /api/v3/hip/token/on-generate-token  the token; every waiting care context is then linked
//   -> {hiecm}/hip/v3/link/carecontext      (X-LINK-TOKEN)
//   <- /api/v3/link/on_carecontext          linked; then link/context/notify (doc §4.3.6)
// User-initiated linking (doc §5): the patient's ABHA app finds records here by ABHA / mobile
//   <- /api/v3/hip/patient/care-context/discover  -> on-discover
//   <- /api/v3/hip/link/care-context/init         -> on-init (an OTP goes to the patient's mobile)
//   <- /api/v3/hip/link/care-context/confirm      -> on-confirm
// Data flow (doc §6): a HIU asks, under a consent the patient granted
//   <- /api/v3/consent/request/hip/notify          the consent artefact -> hip/on-notify
//   <- /api/v3/hip/health-information/request      -> hip/on-request; the documents are
//      encrypted with Fidelius (src/lib/fidelius.js) and POSTed to the HIU's dataPushUrl; then
//      health-information/notify with what was delivered.
import { Hono } from 'hono';
import { AbdmApiError } from '../lib/abdmClient.js';
import {
    abdmCallbackAuth, abdmErrorText, answerLater, facilityOwner, hiecm, requestIdOf, staffAbdmErrorHandler, unverifiedClaims,
} from '../lib/abdmCallback.js';
import { encrypt, generateKeyMaterial, KEY_MATERIAL } from '../lib/fidelius.js';
import { MAX_OTP_ATTEMPTS, deliverOtp, newOtp, otpExpiry, otpHash } from '../lib/linkOtp.js';
import { createHash } from 'node:crypto';

export const HI_TYPES = ['OPConsultation', 'Prescription', 'DiagnosticReport', 'DischargeSummary', 'ImmunizationRecord', 'HealthDocumentRecord', 'WellnessRecord'];
export const hiTypeOf = (t) => HI_TYPES.find((h) => h.toLowerCase() === String(t || '').trim().toLowerCase()) || null;

const MAX_BUNDLE_CHARS = 1_500_000; // a D1 row holds 2 MB
const GENDERS = { m: 'M', male: 'M', f: 'F', female: 'F', o: 'O', other: 'O', t: 'O', d: 'D', undisclosed: 'D' };
export const genderCode = (g) => GENDERS[String(g || '').trim().toLowerCase()] || null;
export const abhaNumberDigits = (v) => { const d = String(v ?? '').replace(/\D/g, ''); return d.length === 14 ? d : null; };
export const abhaAddressOf = (v) => { const a = String(v ?? '').trim().toLowerCase(); return /^[a-z0-9][a-z0-9._]*@[a-z]+$/.test(a) ? a : null; };
const mobileDigits = (v) => { const d = String(v ?? '').replace(/\D/g, ''); return d.length >= 10 ? d.slice(-10) : null; };
const nowIso = () => new Date().toISOString();

// ── HIP-initiated linking ───────────────────────────────────────────────────────────────────

async function usableLinkToken(db, hipId, abhaAddress) {
    const row = await db.prepare('SELECT * FROM hip_link_tokens WHERE hip_id = ? AND abha_address = ?').bind(hipId, abhaAddress).first();
    if (!row || row.status !== 'ready' || !row.link_token) return null;
    if (row.expires_at && Date.parse(row.expires_at) < Date.now() + 5 * 60 * 1000) return null;
    return row;
}

/** Asks ABDM for a link token (answered by on-generate-token). Returns false when ABDM refused at once. */
export async function requestLinkToken(env, db, { hipId, abhaAddress, name, gender, yearOfBirth }) {
    const requestId = crypto.randomUUID();
    await db
        .prepare(
            `INSERT INTO hip_link_tokens (hip_id, abha_address, request_id, status) VALUES (?, ?, ?, 'requested')
             ON CONFLICT (hip_id, abha_address) DO UPDATE SET request_id = excluded.request_id, status = 'requested', link_token = NULL, expires_at = NULL, error = NULL, updated_at = datetime('now')`,
        )
        .bind(hipId, abhaAddress, requestId)
        .run();
    try {
        // NHA's wrapper sends exactly these four (GenerateTokenRequest); the ABHA number is optional when the address is given.
        await hiecm(env, '/v3/token/generate-token', { abhaAddress, name, gender, yearOfBirth: Number(yearOfBirth) }, { hipId, requestId });
        return true;
    } catch (err) {
        const message = err instanceof AbdmApiError ? abdmErrorText(err) : err.message;
        await failTokenWait(db, hipId, abhaAddress, message);
        return false;
    }
}

async function failTokenWait(db, hipId, abhaAddress, message) {
    await db.prepare(`UPDATE hip_link_tokens SET status = 'failed', error = ?, updated_at = datetime('now') WHERE hip_id = ? AND abha_address = ?`).bind(message, hipId, abhaAddress).run();
    await db
        .prepare(`UPDATE hip_care_contexts SET link_status = 'failed', link_error = ?, updated_at = datetime('now') WHERE hip_id = ? AND abha_address = ? AND link_status = 'awaiting_token'`)
        .bind(message, hipId, abhaAddress)
        .run();
}

/** The care contexts as ABDM lists them: one entry per (patient, hiType). */
export function patientGroups(rows, { withDisplay = true } = {}) {
    const groups = new Map();
    for (const r of rows) {
        const key = `${r.patient_reference}\u0000${r.hi_type}`;
        if (!groups.has(key)) groups.set(key, { referenceNumber: r.patient_reference, display: r.patient_display || r.patient_name || r.patient_reference, careContexts: [], hiType: r.hi_type, count: 0 });
        const g = groups.get(key);
        g.careContexts.push(withDisplay ? { referenceNumber: r.care_context_reference, display: r.display } : { referenceNumber: r.care_context_reference });
        g.count = g.careContexts.length;
    }
    return [...groups.values()];
}

/** Links every care context waiting for this (facility, ABHA address), if a link token is at hand. */
export async function linkWaiting(env, db, hipId, abhaAddress) {
    const token = await usableLinkToken(db, hipId, abhaAddress);
    if (!token) return { linked: 0 };
    const { results: rows } = await db
        .prepare(`SELECT * FROM hip_care_contexts WHERE hip_id = ? AND abha_address = ? AND link_status = 'awaiting_token' ORDER BY created_at`)
        .bind(hipId, abhaAddress)
        .all();
    if (!rows.length) return { linked: 0 };

    const requestId = crypto.randomUUID();
    const ids = rows.map((r) => r.id);
    const marks = ids.map(() => '?').join(',');
    await db.prepare(`UPDATE hip_care_contexts SET link_status = 'linking', link_request_id = ?, link_error = NULL, updated_at = datetime('now') WHERE id IN (${marks})`).bind(requestId, ...ids).run();
    const abhaNumber = unverifiedClaims(token.link_token).abhaNumber || rows.find((r) => r.abha_number)?.abha_number;
    try {
        await hiecm(env, '/hip/v3/link/carecontext', { ...(abhaNumber ? { abhaNumber: String(abhaNumber) } : {}), abhaAddress, patient: patientGroups(rows) }, { hipId, requestId, extraHeaders: { 'X-LINK-TOKEN': token.link_token } });
        return { linked: rows.length, requestId };
    } catch (err) {
        const message = err instanceof AbdmApiError ? abdmErrorText(err) : err.message;
        await db.prepare(`UPDATE hip_care_contexts SET link_status = 'failed', link_error = ? WHERE id IN (${marks})`).bind(message, ...ids).run();
        // A token ABDM no longer takes (expired, or for another ABHA): drop it, so a retry asks for a fresh one.
        if (/ABDM-10(66|63|62|38)|token/i.test(message) || err?.status === 401) {
            await db.prepare(`UPDATE hip_link_tokens SET status = 'failed', error = ? WHERE hip_id = ? AND abha_address = ?`).bind(message, hipId, abhaAddress).run();
        }
        return { linked: 0, error: message };
    }
}

/** link/context/notify: tells ABDM (and through it subscribed HIUs) that a linked record exists or changed. */
export async function notifyContext(env, db, row) {
    try {
        await hiecm(env, '/hip/v3/link/context/notify', {
            notification: {
                patient: { id: row.abha_address },
                careContext: { patientReference: row.patient_reference, careContextReference: row.care_context_reference },
                hiTypes: [row.hi_type],
                date: nowIso(),
                hip: { id: row.hip_id },
            },
        }, { hipId: row.hip_id });
        await db.prepare(`UPDATE hip_care_contexts SET notified_at = datetime('now') WHERE id = ?`).bind(row.id).run();
    } catch (err) {
        console.error('[hip] context notify failed:', err instanceof AbdmApiError ? abdmErrorText(err) : err.message);
    }
}

// ── ABDM -> gateway (HIP callbacks) ─────────────────────────────────────────────────────────
// Each route carries the check itself: a use('*') here would become '/*' on the app this is mounted into.
export const hipCallbacks = new Hono();
const signed = abdmCallbackAuth();

hipCallbacks.post('/api/v3/hip/token/on-generate-token', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    return answerLater(c, 'hip on-generate-token', async () => {
        const db = c.env.DB;
        const row = await db.prepare('SELECT * FROM hip_link_tokens WHERE request_id = ?').bind(body?.response?.requestId || '').first();
        if (!row) return console.warn('[hip] on-generate-token for an unknown request', body?.response?.requestId);
        if (body.error || !body.linkToken) return failTokenWait(db, row.hip_id, row.abha_address, [body.error?.code, body.error?.message].filter(Boolean).join(' ') || 'No link token');
        const exp = unverifiedClaims(body.linkToken).exp;
        await db
            .prepare(`UPDATE hip_link_tokens SET link_token = ?, expires_at = ?, status = 'ready', error = NULL, updated_at = datetime('now') WHERE hip_id = ? AND abha_address = ?`)
            .bind(body.linkToken, exp ? new Date(exp * 1000).toISOString() : null, row.hip_id, row.abha_address)
            .run();
        await linkWaiting(c.env, db, row.hip_id, row.abha_address);
    });
});

hipCallbacks.post('/api/v3/link/on_carecontext', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    return answerLater(c, 'hip on_carecontext', async () => {
        const db = c.env.DB;
        const requestId = body?.response?.requestId || '';
        const { results: rows } = await db.prepare('SELECT * FROM hip_care_contexts WHERE link_request_id = ?').bind(requestId).all();
        if (!rows.length) return console.warn('[hip] on_carecontext for an unknown request', requestId);
        const status = String(body.status || '');
        const ok = !body.error && /successfully linked|already linked/i.test(status);
        if (!ok) {
            const message = [body.error?.code, body.error?.message].filter(Boolean).join(' ') || status || 'ABDM did not link the records';
            await db.prepare(`UPDATE hip_care_contexts SET link_status = 'failed', link_error = ?, updated_at = datetime('now') WHERE link_request_id = ?`).bind(message, requestId).run();
            return;
        }
        await db.prepare(`UPDATE hip_care_contexts SET link_status = 'linked', linked_via = 'hip', linked_at = datetime('now'), link_error = NULL, updated_at = datetime('now') WHERE link_request_id = ?`).bind(requestId).run();
        for (const row of rows) await notifyContext(c.env, db, row);
    });
});

// Acknowledgements of context/notify and SMS notify: nothing to do but record failures.
for (const path of ['/api/v3/links/context/on-notify', '/api/v3/patients/sms/on-notify']) {
    hipCallbacks.post(path, signed, async (c) => {
        const body = await c.req.json().catch(() => ({}));
        if (body?.error) console.warn(`[hip] ${path}:`, JSON.stringify(body.error));
        return c.json({}, 202);
    });
}

// User-initiated linking: discovery.
export function discoveryMatch(rows, patient) {
    const verified = Object.fromEntries((patient?.verifiedIdentifiers || []).map((i) => [String(i.type).toUpperCase(), i.value]));
    const unverified = Object.fromEntries((patient?.unverifiedIdentifiers || []).map((i) => [String(i.type).toUpperCase(), i.value]));
    const abhaAddress = abhaAddressOf(patient?.id);
    const abhaNumber = abhaNumberDigits(verified.ABHA_NUMBER);
    const mobile = mobileDigits(verified.MOBILE);
    const gender = genderCode(patient?.gender);
    const yob = Number(patient?.yearOfBirth) || null;
    const firstName = String(patient?.name || '').trim().split(/\s+/)[0]?.toLowerCase();
    // Demographics must agree before a mobile number or MR number alone may reveal a record.
    const demographicsAgree = (r) => (!gender || !r.gender || r.gender === gender)
        && (!yob || !r.year_of_birth || Math.abs(Number(r.year_of_birth) - yob) <= 1)
        && (!firstName || !r.patient_name || String(r.patient_name).toLowerCase().split(/\s+/)[0] === firstName);
    const matchedBy = new Set();
    const hits = rows.filter((r) => {
        if (abhaAddress && r.abha_address === abhaAddress) return matchedBy.add('ABHA_ADDRESS');
        if (abhaNumber && r.abha_number === abhaNumber) return matchedBy.add('ABHA_NUMBER');
        if (mobile && r.mobile === mobile && demographicsAgree(r)) return matchedBy.add('MOBILE');
        if (unverified.MR && r.patient_reference === String(unverified.MR) && demographicsAgree(r)) return matchedBy.add('MR');
        return false;
    });
    return { hits, matchedBy: [...matchedBy], abhaAddress, abhaNumber, mobile };
}

hipCallbacks.post('/api/v3/hip/patient/care-context/discover', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const requestId = requestIdOf(c);
    const hipId = String(c.req.header('X-HIP-ID') || body?.hip?.id || '').trim();
    return answerLater(c, 'hip discover', async () => {
        const db = c.env.DB;
        const transactionId = body.transactionId;
        const reply = (payload) => hiecm(c.env, '/user-initiated-linking/v3/patient/care-context/on-discover', { transactionId, ...payload, response: { requestId } }, { hipId });
        const facility = await facilityOwner(db, hipId);
        if (!facility) return reply({ error: { code: 'ABDM-1010', message: 'Patient not found' } });
        const { results } = await db.prepare(`SELECT * FROM hip_care_contexts WHERE hip_id = ? AND link_status != 'linked'`).bind(hipId).all();
        const { hits, matchedBy, abhaAddress, abhaNumber, mobile } = discoveryMatch(results, body.patient);
        if (!hits.length) return reply({ error: { code: 'ABDM-1010', message: 'Patient not found' } });
        await db
            .prepare(
                `INSERT OR REPLACE INTO hip_link_requests (transaction_id, hip_id, clinic_id, abha_address, abha_number, mobile, matched_by, offered_json, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'discovered')`,
            )
            .bind(transactionId, hipId, facility.clinic_id, abhaAddress, abhaNumber, mobile || hits.find((h) => h.mobile)?.mobile || null, matchedBy.join(','), JSON.stringify(hits.map((h) => h.id)))
            .run();
        await reply({ patient: patientGroups(hits), matchedBy });
    });
});

hipCallbacks.post('/api/v3/hip/link/care-context/init', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const requestId = requestIdOf(c);
    const hipId = String(c.req.header('X-HIP-ID') || '').trim();
    return answerLater(c, 'hip link init', async () => {
        const db = c.env.DB;
        const transactionId = body.transactionId;
        const reply = (payload) => hiecm(c.env, '/user-initiated-linking/v3/link/care-context/on-init', { transactionId, ...payload, response: { requestId } }, { hipId });
        const fail = (message, code = 'ABDM-9999') => reply({ error: { code, message } });

        const lr = await db.prepare('SELECT * FROM hip_link_requests WHERE transaction_id = ?').bind(transactionId || '').first();
        if (!lr || (hipId && lr.hip_id !== hipId)) return fail('Discover the records first');
        const offered = new Set(JSON.parse(lr.offered_json || '[]'));
        const refs = (body.patient || []).flatMap((p) => (p.careContexts || []).map((cc) => String(cc.referenceNumber)));
        if (!refs.length) return fail('No care contexts to link');
        const marks = refs.map(() => '?').join(',');
        const { results: rows } = await db.prepare(`SELECT * FROM hip_care_contexts WHERE hip_id = ? AND care_context_reference IN (${marks})`).bind(lr.hip_id, ...refs).all();
        if (rows.some((r) => r.link_status === 'linked')) return fail('These care contexts have been already linked');
        if (rows.length !== new Set(refs).size || rows.some((r) => !offered.has(r.id))) return fail('Care contexts not found for this patient');

        const mobile = lr.mobile || rows.find((r) => r.mobile)?.mobile;
        if (!mobile) return fail('No mobile number on record to send the OTP to');
        const facility = await facilityOwner(db, lr.hip_id);
        const otp = newOtp();
        let delivery;
        try {
            ({ delivery } = await deliverOtp(c.env, { mobile, otp, facilityName: facility?.hip_name || facility?.facility_name }));
        } catch (err) {
            await db.prepare(`UPDATE hip_link_requests SET status = 'failed', error = ?, updated_at = datetime('now') WHERE transaction_id = ?`).bind(err.message, transactionId).run();
            return fail(err.message);
        }
        const linkRefNumber = crypto.randomUUID();
        const expiry = otpExpiry();
        await db
            .prepare(
                `UPDATE hip_link_requests SET abha_address = COALESCE(?, abha_address), requested_json = ?, link_ref_number = ?, otp_hash = ?, otp_expires_at = ?, otp_attempts = 0,
                   otp_delivery = ?, sandbox_otp = ?, status = 'otp_sent', error = NULL, updated_at = datetime('now') WHERE transaction_id = ?`,
            )
            .bind(abhaAddressOf(body.abhaAddress), JSON.stringify(rows.map((r) => r.id)), linkRefNumber, await otpHash(transactionId, otp), expiry, delivery, delivery === 'sandbox' ? otp : null, transactionId)
            .run();
        await reply({ link: { referenceNumber: linkRefNumber, authenticationType: 'MEDIATE', meta: { communicationMedium: 'MOBILE', communicationHint: 'OTP', communicationExpiry: expiry } } });
    });
});

hipCallbacks.post('/api/v3/hip/link/care-context/confirm', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const requestId = requestIdOf(c);
    const hipId = String(c.req.header('X-HIP-ID') || '').trim();
    return answerLater(c, 'hip link confirm', async () => {
        const db = c.env.DB;
        const { linkRefNumber, token } = body.confirmation || body;
        const reply = (payload) => hiecm(c.env, '/user-initiated-linking/v3/link/care-context/on-confirm', { ...payload, response: { requestId } }, { hipId: hipId || undefined });
        const lr = await db.prepare('SELECT * FROM hip_link_requests WHERE link_ref_number = ?').bind(linkRefNumber || '').first();
        if (!lr || lr.status !== 'otp_sent') return reply({ error: { code: 'ABDM-9999', message: 'Invalid link reference number' } });
        if (lr.otp_attempts >= MAX_OTP_ATTEMPTS) return reply({ error: { code: 'ABDM-9999', message: 'Too many wrong OTPs. Start linking again.' } });
        if (Date.parse(lr.otp_expires_at) < Date.now()) return reply({ error: { code: 'ABDM-9999', message: 'The OTP has expired. Start linking again.' } });
        if ((await otpHash(lr.transaction_id, token)) !== lr.otp_hash) {
            await db.prepare(`UPDATE hip_link_requests SET otp_attempts = otp_attempts + 1, updated_at = datetime('now') WHERE transaction_id = ?`).bind(lr.transaction_id).run();
            return reply({ error: { code: 'ABDM-9999', message: 'Invalid OTP' } });
        }
        const ids = JSON.parse(lr.requested_json || '[]');
        const marks = ids.map(() => '?').join(',');
        await db
            .prepare(
                `UPDATE hip_care_contexts SET link_status = 'linked', linked_via = 'patient', linked_at = datetime('now'), link_error = NULL,
                   abha_address = COALESCE(abha_address, ?), abha_number = COALESCE(abha_number, ?), updated_at = datetime('now') WHERE id IN (${marks})`,
            )
            .bind(lr.abha_address, lr.abha_number, ...ids)
            .run();
        await db.prepare(`UPDATE hip_link_requests SET status = 'linked', otp_hash = NULL, sandbox_otp = NULL, updated_at = datetime('now') WHERE transaction_id = ?`).bind(lr.transaction_id).run();
        const { results: rows } = await db.prepare(`SELECT * FROM hip_care_contexts WHERE id IN (${marks})`).bind(...ids).all();
        await reply({ patient: patientGroups(rows) });
    });
});

// Data flow: consent artefacts.
hipCallbacks.post('/api/v3/consent/request/hip/notify', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const requestId = requestIdOf(c);
    return answerLater(c, 'hip consent notify', async () => {
        const db = c.env.DB;
        const n = body.notification || {};
        const detail = n.consentDetail || {};
        const consentId = n.consentId || detail.consentId;
        const hipId = String(detail.hip?.id || c.req.header('X-HIP-ID') || '').trim();
        const ack = (status, error) => hiecm(c.env, '/consent/v3/request/hip/on-notify', { acknowledgement: { status, consentId }, ...(error ? { error } : {}), response: { requestId } }, { hipId: hipId || undefined });
        if (!consentId) return ack('FAILURE', { code: 'ABDM-9999', message: 'Invalid hip/notify request' });
        const facility = await facilityOwner(db, hipId);
        const existing = await db.prepare('SELECT * FROM hip_consents WHERE consent_id = ?').bind(consentId).first();
        if (!facility && !existing) return ack('FAILURE', { code: 'ABDM-9999', message: 'Unknown HIP' });
        const status = String(n.status || '').toUpperCase();
        if (existing && !n.consentDetail) {
            await db.prepare(`UPDATE hip_consents SET status = ?, updated_at = datetime('now') WHERE consent_id = ?`).bind(status, consentId).run();
            return ack('OK');
        }
        const p = detail.permission || {};
        await db
            .prepare(
                `INSERT INTO hip_consents (consent_id, hip_id, clinic_id, status, patient_abha, hiu_id, purpose_code, requester_name, hi_types_json, care_contexts_json, date_from, date_to, data_erase_at, detail_json, signature)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (consent_id) DO UPDATE SET status = excluded.status, detail_json = excluded.detail_json, signature = excluded.signature,
                   care_contexts_json = excluded.care_contexts_json, data_erase_at = excluded.data_erase_at, updated_at = datetime('now')`,
            )
            .bind(
                consentId, hipId, facility?.clinic_id || existing?.clinic_id, status, String(detail.patient?.id || '').toLowerCase() || null, detail.hiu?.id || null,
                detail.purpose?.code || null, detail.requester?.name || null, JSON.stringify(detail.hiTypes || []), JSON.stringify(detail.careContexts || []),
                p.dateRange?.from || null, p.dateRange?.to || null, p.dataEraseAt || null, JSON.stringify(detail), n.signature || null,
            )
            .run();
        await ack('OK');
    });
});

const inRange = (date, from, to) => {
    if (!date) return true;
    const t = Date.parse(date);
    return !(from && t < Date.parse(from)) && !(to && t > Date.parse(to));
};

/** The care contexts a consent lets this HIP share for a data request (linked, listed, right type, in the date ranges). */
export async function shareableRecords(db, consent, dateRange = {}) {
    const listed = new Set(JSON.parse(consent.care_contexts_json || '[]').map((cc) => String(cc.careContextReference)));
    const types = new Set(JSON.parse(consent.hi_types_json || '[]').map((t) => String(t).toLowerCase()));
    if (!listed.size) return [];
    const refs = [...listed];
    const { results } = await db
        .prepare(`SELECT * FROM hip_care_contexts WHERE hip_id = ? AND link_status = 'linked' AND care_context_reference IN (${refs.map(() => '?').join(',')})`)
        .bind(consent.hip_id, ...refs)
        .all();
    return results.filter((r) => (!types.size || types.has(r.hi_type.toLowerCase()))
        && inRange(r.record_date, consent.date_from, consent.date_to)
        && inRange(r.record_date, dateRange.from, dateRange.to));
}

const md5 = (s) => createHash('md5').update(s).digest('hex');

/** Encrypts the records for the HIU (Fidelius) and builds the data push body (as NHA's wrapper does: one page). */
export async function buildDataPush({ transactionId, records, keyMaterial }) {
    const mine = generateKeyMaterial();
    const entries = [];
    for (const r of records) {
        entries.push({
            content: await encrypt({ plaintext: r.bundle_json, senderNonce: mine.nonce, requesterNonce: keyMaterial.nonce, senderPrivateKey: mine.privateKey, requesterPublicKey: keyMaterial.dhPublicKey.keyValue }),
            media: 'application/fhir+json',
            checksum: md5(r.bundle_json),
            careContextReference: r.care_context_reference,
        });
    }
    return {
        pageNumber: 0,
        pageCount: 1,
        transactionId,
        entries,
        keyMaterial: {
            cryptoAlg: keyMaterial.cryptoAlg || KEY_MATERIAL.cryptoAlg,
            curve: keyMaterial.curve || KEY_MATERIAL.curve,
            dhPublicKey: { expiry: keyMaterial.dhPublicKey.expiry, parameters: keyMaterial.dhPublicKey.parameters || KEY_MATERIAL.parameters, keyValue: mine.x509PublicKey },
            nonce: mine.nonce,
        },
    };
}

hipCallbacks.post('/api/v3/hip/health-information/request', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const requestId = requestIdOf(c);
    const headerHip = String(c.req.header('X-HIP-ID') || '').trim();
    return answerLater(c, 'hip health-information request', async () => {
        const db = c.env.DB;
        const hi = body.hiRequest || {};
        const transactionId = body.transactionId || hi.transactionId;
        const consentId = hi.consent?.id;
        const consent = consentId ? await db.prepare('SELECT * FROM hip_consents WHERE consent_id = ?').bind(consentId).first() : null;
        const hipId = consent?.hip_id || headerHip;

        let refusal = null;
        if (!transactionId) refusal = 'transactionId is missing';
        else if (!consent) refusal = 'Consent not found';
        else if (consent.status !== 'GRANTED') refusal = `Consent is ${consent.status}`;
        else if (headerHip && headerHip !== consent.hip_id) refusal = 'Consent is for another HIP';
        else if (consent.data_erase_at && Date.parse(consent.data_erase_at) < Date.now()) refusal = 'Consent has expired';
        else if (!/^https:\/\//.test(hi.dataPushUrl || '') && c.env.ABDM_CALLBACK_AUTH !== 'off') refusal = 'dataPushUrl must be https';
        else if (!hi.keyMaterial?.dhPublicKey?.keyValue || !hi.keyMaterial?.nonce) refusal = 'keyMaterial is missing';
        else if (hi.keyMaterial.dhPublicKey.expiry && Date.parse(hi.keyMaterial.dhPublicKey.expiry) < Date.now()) refusal = 'The HIU’s key has expired';

        await db
            .prepare(
                `INSERT OR REPLACE INTO hip_data_transfers (transaction_id, consent_id, hip_id, clinic_id, request_id, data_push_url, date_from, date_to, status, error)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .bind(transactionId || crypto.randomUUID(), consentId || '', hipId || '', consent?.clinic_id || null, requestId, hi.dataPushUrl || null, hi.dateRange?.from || null, hi.dateRange?.to || null, refusal ? 'refused' : 'requested', refusal)
            .run();

        await hiecm(c.env, '/data-flow/v3/health-information/hip/on-request', refusal
            ? { error: { code: 'ABDM-9999', message: refusal }, response: { requestId } }
            : { hiRequest: { transactionId, sessionStatus: 'ACKNOWLEDGED' }, response: { requestId } }, { hipId: hipId || undefined });
        if (refusal) return;

        const records = await shareableRecords(db, consent, hi.dateRange);
        let pushed = false;
        let error = null;
        if (records.length) {
            try {
                const push = await buildDataPush({ transactionId, records, keyMaterial: hi.keyMaterial });
                // Straight to the HIU, not through HIE-CM: and never with this gateway's ABDM token (the URL is the HIU's).
                const res = await fetch(hi.dataPushUrl, { method: 'POST', headers: { 'Content-Type': 'application/json', 'REQUEST-ID': crypto.randomUUID(), TIMESTAMP: nowIso() }, body: JSON.stringify(push) });
                pushed = res.ok;
                if (!res.ok) error = `The HIU answered ${res.status}`;
            } catch (err) {
                error = err.message;
            }
        } else {
            error = 'No linked records match this consent';
        }
        const delivered = new Set(pushed ? records.map((r) => r.care_context_reference) : []);
        const listed = JSON.parse(consent.care_contexts_json || '[]');
        const statusResponses = listed.map((cc) => ({
            careContextReference: cc.careContextReference,
            hiStatus: delivered.has(String(cc.careContextReference)) ? 'DELIVERED' : 'ERRORED',
            description: delivered.has(String(cc.careContextReference)) ? 'Delivered' : error || 'Not available',
        }));
        await db
            .prepare(`UPDATE hip_data_transfers SET status = ?, entries_json = ?, error = ?, updated_at = datetime('now') WHERE transaction_id = ?`)
            .bind(pushed ? 'transferred' : 'failed', JSON.stringify(statusResponses), error, transactionId)
            .run();
        await hiecm(c.env, '/data-flow/v3/health-information/notify', {
            notification: {
                consentId,
                transactionId,
                doneAt: nowIso(),
                notifier: { type: 'HIP', id: hipId },
                statusNotification: { sessionStatus: pushed ? 'TRANSFERRED' : 'FAILED', hipId, statusResponses },
            },
        }, { hipId });
    });
});

// ── Staff (behind the session gate of /hie/*) ───────────────────────────────────────────────
export const hipStaffRoutes = new Hono();
hipStaffRoutes.onError(staffAbdmErrorHandler('hip', AbdmApiError));

const careContextView = (r) => ({
    id: r.id, facilityId: r.hip_id, patientReference: r.patient_reference, abhaAddress: r.abha_address, careContextReference: r.care_context_reference,
    display: r.display, hiType: r.hi_type, recordDate: r.record_date, linkStatus: r.link_status, linkError: r.link_error, linkedVia: r.linked_via,
    linkedAt: r.linked_at, notifiedAt: r.notified_at, updatedAt: r.updated_at,
});

async function ownFacility(c, facilityId) {
    const f = await facilityOwner(c.env.DB, facilityId);
    return f && f.clinic_id === c.get('user').clinicId ? f : null;
}

hipStaffRoutes.get('/care-contexts', async (c) => {
    const { clinicId } = c.get('user');
    const { patientReference, abhaAddress } = c.req.query();
    const where = ['clinic_id = ?'];
    const args = [clinicId];
    if (patientReference) { where.push('patient_reference = ?'); args.push(patientReference); }
    if (abhaAddress) { where.push('abha_address = ?'); args.push(String(abhaAddress).toLowerCase()); }
    const { results } = await c.env.DB.prepare(`SELECT * FROM hip_care_contexts WHERE ${where.join(' AND ')} ORDER BY updated_at DESC LIMIT 200`).bind(...args).all();
    return c.json({ success: true, careContexts: results.map(careContextView) });
});

/** Validates a share request; returns { error } or the normalised values. */
export function parseShare(body) {
    const p = body?.patient || {};
    const cc = body?.careContext || {};
    const hiType = hiTypeOf(cc.hiType);
    if (!hiType) return { error: `hiType must be one of ${HI_TYPES.join(', ')}` };
    const reference = String(cc.reference || '').trim();
    const patientReference = String(p.reference || '').trim();
    if (!reference || reference.length > 100 || !patientReference || patientReference.length > 100) return { error: 'The visit and the patient need a reference (at most 100 characters).' };
    const name = String(p.name || '').trim();
    const gender = genderCode(p.gender);
    const yearOfBirth = Number(p.yearOfBirth);
    if (!name) return { error: 'The patient’s name is needed.' };
    if (!gender) return { error: 'The patient’s gender is needed (M, F, O or D).' };
    if (!(yearOfBirth >= 1900 && yearOfBirth <= 2200)) return { error: 'The patient’s year of birth is needed.' };
    const abhaAddress = p.abhaAddress ? abhaAddressOf(p.abhaAddress) : null;
    if (p.abhaAddress && !abhaAddress) return { error: 'That ABHA address is not valid (like name@sbx).' };
    const bundle = body?.bundle;
    if (bundle?.resourceType !== 'Bundle') return { error: 'bundle must be a FHIR Bundle' };
    const bundleJson = JSON.stringify(bundle);
    if (bundleJson.length > MAX_BUNDLE_CHARS) return { error: 'This record is too large to share through ABDM (attachments included).' };
    return {
        value: {
            facilityId: String(body.facilityId || '').trim().toUpperCase(), reference, patientReference, hiType, name, gender, yearOfBirth, abhaAddress,
            abhaNumber: abhaNumberDigits(p.abhaNumber), mobile: mobileDigits(p.mobile), patientDisplay: String(p.display || name).slice(0, 200),
            display: String(cc.display || hiType).trim().slice(0, 200), recordDate: cc.date ? new Date(cc.date).toISOString() : nowIso(), bundleJson,
        },
    };
}

hipStaffRoutes.post('/care-contexts', async (c) => {
    const { clinicId, accountId } = c.get('user');
    const parsed = parseShare(await c.req.json().catch(() => ({})));
    if (parsed.error) return c.json({ success: false, error: parsed.error }, 400);
    const v = parsed.value;
    const db = c.env.DB;
    if (!(await ownFacility(c, v.facilityId))) return c.json({ success: false, error: 'Register this facility for ABDM first (Scan & Share → Start taking shares).' }, 400);

    const existing = await db.prepare('SELECT * FROM hip_care_contexts WHERE hip_id = ? AND care_context_reference = ?').bind(v.facilityId, v.reference).first();
    if (existing && existing.clinic_id !== clinicId) return c.json({ success: false, error: 'This record reference belongs to another clinic.' }, 409);
    const alreadyLinked = existing?.link_status === 'linked';
    const status = alreadyLinked ? 'linked' : v.abhaAddress ? 'awaiting_token' : 'unlinked';
    const id = existing?.id || crypto.randomUUID();
    await db
        .prepare(
            `INSERT INTO hip_care_contexts (id, clinic_id, hip_id, patient_reference, patient_display, abha_address, abha_number, patient_name, gender, year_of_birth, mobile,
               care_context_reference, display, hi_type, record_date, bundle_json, link_status, created_by_account_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (hip_id, care_context_reference) DO UPDATE SET patient_display = excluded.patient_display, abha_address = COALESCE(excluded.abha_address, hip_care_contexts.abha_address),
               abha_number = COALESCE(excluded.abha_number, hip_care_contexts.abha_number), patient_name = excluded.patient_name, gender = excluded.gender,
               year_of_birth = excluded.year_of_birth, mobile = COALESCE(excluded.mobile, hip_care_contexts.mobile), display = excluded.display, hi_type = excluded.hi_type,
               record_date = excluded.record_date, bundle_json = excluded.bundle_json, link_status = excluded.link_status, link_error = NULL, updated_at = datetime('now')`,
        )
        .bind(id, clinicId, v.facilityId, v.patientReference, v.patientDisplay, v.abhaAddress, v.abhaNumber, v.name, v.gender, v.yearOfBirth, v.mobile, v.reference, v.display, v.hiType, v.recordDate, v.bundleJson, status, accountId ?? null)
        .run();

    if (alreadyLinked) {
        // The record changed after it was linked: tell ABDM, so subscribed HIUs can fetch it again.
        await notifyContext(c.env, db, await db.prepare('SELECT * FROM hip_care_contexts WHERE id = ?').bind(id).first());
    } else if (v.abhaAddress) {
        const token = await usableLinkToken(db, v.facilityId, v.abhaAddress);
        if (token) await linkWaiting(c.env, db, v.facilityId, v.abhaAddress);
        else {
            const pending = await db.prepare('SELECT status FROM hip_link_tokens WHERE hip_id = ? AND abha_address = ?').bind(v.facilityId, v.abhaAddress).first();
            // One token request per (facility, ABHA) at a time: ABDM refuses duplicates (ABDM-1092) and blocks after 3.
            if (pending?.status !== 'requested') await requestLinkToken(c.env, db, { hipId: v.facilityId, abhaAddress: v.abhaAddress, name: v.name, gender: v.gender, yearOfBirth: v.yearOfBirth });
        }
    }
    const row = await db.prepare('SELECT * FROM hip_care_contexts WHERE id = ?').bind(id).first();
    return c.json({ success: true, careContext: careContextView(row) }, existing ? 200 : 201);
});

hipStaffRoutes.post('/care-contexts/:id/link', async (c) => {
    const { clinicId } = c.get('user');
    const db = c.env.DB;
    const row = await db.prepare('SELECT * FROM hip_care_contexts WHERE id = ? AND clinic_id = ?').bind(c.req.param('id'), clinicId).first();
    if (!row) return c.json({ success: false, error: 'No such record.' }, 404);
    if (row.link_status === 'linked') return c.json({ success: true, careContext: careContextView(row) });
    if (!row.abha_address) return c.json({ success: false, error: 'The patient has no ABHA address on this record. They can still find it from their ABHA app (by mobile number).' }, 400);
    await db.prepare(`UPDATE hip_care_contexts SET link_status = 'awaiting_token', link_error = NULL, updated_at = datetime('now') WHERE id = ?`).bind(row.id).run();
    if (await usableLinkToken(db, row.hip_id, row.abha_address)) await linkWaiting(c.env, db, row.hip_id, row.abha_address);
    else await requestLinkToken(c.env, db, { hipId: row.hip_id, abhaAddress: row.abha_address, name: row.patient_name, gender: row.gender, yearOfBirth: row.year_of_birth });
    return c.json({ success: true, careContext: careContextView(await db.prepare('SELECT * FROM hip_care_contexts WHERE id = ?').bind(row.id).first()) });
});

// Doc §4.3.8: an SMS from ABDM telling a patient (no ABHA yet, or not linked) that records await them.
hipStaffRoutes.post('/sms-notify', async (c) => {
    const { facilityId, phoneNo } = await c.req.json().catch(() => ({}));
    const facility = await ownFacility(c, String(facilityId || '').toUpperCase());
    if (!facility) return c.json({ success: false, error: 'Unknown facility.' }, 400);
    const phone = mobileDigits(phoneNo);
    if (!phone) return c.json({ success: false, error: 'A 10-digit mobile number is needed.' }, 400);
    await hiecm(c.env, '/hip/v3/link/patient/links/sms/notify2', {
        notification: { phoneNo: phone, hip: { id: facility.facility_id, name: facility.hip_name || facility.facility_name } },
    }, { hipId: facility.facility_id });
    return c.json({ success: true });
});

hipStaffRoutes.get('/link-requests', async (c) => {
    const { clinicId } = c.get('user');
    const { results } = await c.env.DB.prepare(`SELECT * FROM hip_link_requests WHERE clinic_id = ? ORDER BY updated_at DESC LIMIT 50`).bind(clinicId).all();
    return c.json({
        success: true,
        linkRequests: results.map((r) => ({
            transactionId: r.transaction_id, facilityId: r.hip_id, abhaAddress: r.abha_address, matchedBy: r.matched_by, status: r.status, error: r.error,
            offered: JSON.parse(r.offered_json || '[]').length, otpDelivery: r.otp_delivery, otpExpiresAt: r.otp_expires_at,
            // Sandbox without an SMS provider only: the OTP the patient would have been sent.
            sandboxOtp: r.status === 'otp_sent' && r.otp_delivery === 'sandbox' && Date.parse(r.otp_expires_at) > Date.now() ? r.sandbox_otp : null,
            updatedAt: r.updated_at,
        })),
    });
});

hipStaffRoutes.get('/consents', async (c) => {
    const { clinicId } = c.get('user');
    const db = c.env.DB;
    const { results: consents } = await db.prepare(`SELECT * FROM hip_consents WHERE clinic_id = ? ORDER BY updated_at DESC LIMIT 100`).bind(clinicId).all();
    const { results: transfers } = await db.prepare(`SELECT * FROM hip_data_transfers WHERE clinic_id = ? ORDER BY created_at DESC LIMIT 100`).bind(clinicId).all();
    return c.json({
        success: true,
        consents: consents.map((r) => ({
            consentId: r.consent_id, facilityId: r.hip_id, status: r.status, patientAbha: r.patient_abha, hiuId: r.hiu_id, purpose: r.purpose_code, requester: r.requester_name,
            hiTypes: JSON.parse(r.hi_types_json || '[]'), careContexts: JSON.parse(r.care_contexts_json || '[]').length, from: r.date_from, to: r.date_to, eraseAt: r.data_erase_at, updatedAt: r.updated_at,
        })),
        transfers: transfers.map((r) => ({
            transactionId: r.transaction_id, consentId: r.consent_id, facilityId: r.hip_id, status: r.status, error: r.error, entries: JSON.parse(r.entries_json || '[]'), at: r.created_at,
        })),
    });
});
