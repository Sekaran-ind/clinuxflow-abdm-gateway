// ABDM Milestone 3: ClinuxFlow facilities as Health Information Users (NHA M3 sandbox doc,
// 16-02-2026; shapes checked against NHA-ABDM/ABDM-wrapper v3). A clinician asks a patient,
// through ABDM, to see their records held at other facilities; the patient approves in their ABHA
// app; HIPs push the records here, encrypted for this request only.
//
//   POST /hie/hiu/consent-requests           staff -> {hiecm}/consent/v3/request/init
//   <- /api/v3/hiu/consent/request/on-init   ABDM's consent request id
//   <- /api/v3/hiu/consent/request/notify    GRANTED (artefact ids) / DENIED / REVOKED / EXPIRED -> hiu/on-notify
//   -> {hiecm}/consent/v3/fetch               each granted artefact
//   <- /api/v3/hiu/consent/on-fetch           the artefact -> {hiecm}/data-flow/v3/health-information/request,
//                                             with a fresh Fidelius key and a one-off data push URL
//   <- /api/v3/hiu/health-information/on-request  the transaction id
//   <- POST /hiu/data-push/:id                the HIP's encrypted records (no ABDM signature: the
//                                             unguessable id and the decryption key are the guard)
//   -> {hiecm}/data-flow/v3/health-information/notify   what was received
//
// Decrypted records are kept only until the consent's dataEraseAt, and deleted when the patient
// revokes it. The private key is deleted once the transfer is in.
import { Hono } from 'hono';
import { AbdmApiError } from '../lib/abdmClient.js';
import { getAbdmConfig } from '../lib/config.js';
import { abdmCallbackAuth, abdmErrorText, answerLater, facilityOwner, hiecm, publicOrigin, requestIdOf, staffAbdmErrorHandler } from '../lib/abdmCallback.js';
import { decrypt, generateKeyMaterial, KEY_MATERIAL } from '../lib/fidelius.js';
import { HI_TYPES, abhaAddressOf, hiTypeOf } from './hip.js';

// The purposes ABDM accepts (a subset of HL7 v3 PurposeOfUse; M3 doc §4.3.1).
export const PURPOSES = {
    CAREMGT: 'Care Management',
    BTG: 'Break the Glass',
    PUBHLTH: 'Public Health',
    HPAYMT: 'Healthcare Payment',
    DSRCH: 'Disease Specific Healthcare Research',
    PATRQT: 'Self Requested',
};
const PURPOSE_URI = 'http://terminology.hl7.org/ValueSet/v3-PurposeOfUse';
const nowIso = () => new Date().toISOString();
const errorText = (e) => [e?.code, e?.message].filter(Boolean).join(' ') || 'ABDM refused';

export async function purgeExpiredRecords(db) {
    await db.prepare('DELETE FROM hiu_health_records WHERE erase_at IS NOT NULL AND erase_at < ?').bind(nowIso()).run();
}

/** Asks the HIP (through ABDM) for the records under a granted artefact. */
export async function requestData(env, db, artefact, origin) {
    const detail = JSON.parse(artefact.detail_json || '{}');
    const range = detail.permission?.dateRange;
    if (!range?.from || !range?.to) throw new Error('The consent artefact has no date range');
    const keys = generateKeyMaterial();
    const id = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const requestId = crypto.randomUUID();
    await db
        .prepare(`INSERT INTO hiu_data_requests (id, clinic_id, hiu_id, consent_id, request_id, private_key, nonce) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .bind(id, artefact.clinic_id, artefact.hiu_id, artefact.consent_id, requestId, keys.privateKey, keys.nonce)
        .run();
    try {
        await hiecm(env, '/data-flow/v3/health-information/request', {
            hiRequest: {
                consent: { id: artefact.consent_id },
                dateRange: { from: range.from, to: range.to },
                dataPushUrl: `${origin}/hiu/data-push/${id}`,
                keyMaterial: {
                    ...KEY_MATERIAL,
                    dhPublicKey: { expiry: detail.permission?.dataEraseAt || artefact.data_erase_at, parameters: KEY_MATERIAL.parameters, keyValue: keys.x509PublicKey },
                    nonce: keys.nonce,
                },
            },
        }, { hiuId: artefact.hiu_id, requestId });
    } catch (err) {
        const message = err instanceof AbdmApiError ? abdmErrorText(err) : err.message;
        await db.prepare(`UPDATE hiu_data_requests SET status = 'failed', error = ?, private_key = NULL, updated_at = datetime('now') WHERE id = ?`).bind(message, id).run();
        throw err;
    }
    return id;
}

async function fetchArtefact(env, db, { consentId, consentRequestId, clinicId, hiuId }) {
    const fetchRequestId = crypto.randomUUID();
    await db
        .prepare(
            `INSERT INTO hiu_consent_artefacts (consent_id, consent_request_id, clinic_id, hiu_id, status, fetch_request_id) VALUES (?, ?, ?, ?, 'GRANTED', ?)
             ON CONFLICT (consent_id) DO UPDATE SET status = 'GRANTED', fetch_request_id = excluded.fetch_request_id, updated_at = datetime('now')`,
        )
        .bind(consentId, consentRequestId, clinicId, hiuId, fetchRequestId)
        .run();
    await hiecm(env, '/consent/v3/fetch', { consentId }, { hiuId, requestId: fetchRequestId });
}

async function withdraw(db, consentIds, status) {
    for (const id of consentIds) {
        await db.prepare(`UPDATE hiu_consent_artefacts SET status = ?, updated_at = datetime('now') WHERE consent_id = ?`).bind(status, id).run();
        await db.prepare('DELETE FROM hiu_health_records WHERE consent_id = ?').bind(id).run();
        await db.prepare(`UPDATE hiu_data_requests SET private_key = NULL, updated_at = datetime('now') WHERE consent_id = ?`).bind(id).run();
    }
}

// ── ABDM -> gateway ─────────────────────────────────────────────────────────────────────────
export const hiuCallbacks = new Hono();
const signed = abdmCallbackAuth();

hiuCallbacks.post('/api/v3/hiu/consent/request/on-init', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    return answerLater(c, 'hiu consent on-init', async () => {
        const requestId = body?.response?.requestId || '';
        if (body.error || !body.consentRequest?.id) {
            await c.env.DB.prepare(`UPDATE hiu_consent_requests SET status = 'failed', error = ?, updated_at = datetime('now') WHERE request_id = ?`).bind(errorText(body.error), requestId).run();
            return;
        }
        await c.env.DB.prepare(`UPDATE hiu_consent_requests SET consent_request_id = ?, status = 'REQUESTED', error = NULL, updated_at = datetime('now') WHERE request_id = ?`).bind(body.consentRequest.id, requestId).run();
    });
});

async function onConsentStatus(env, db, { consentRequestId, status, artefactIds }) {
    const cr = await db.prepare('SELECT * FROM hiu_consent_requests WHERE consent_request_id = ?').bind(consentRequestId || '').first();
    if (!cr) return null;
    status = String(status || '').toUpperCase();
    await db.prepare(`UPDATE hiu_consent_requests SET status = ?, updated_at = datetime('now') WHERE id = ?`).bind(status, cr.id).run();
    if (status === 'GRANTED') {
        for (const consentId of artefactIds) {
            const known = await db.prepare('SELECT status, detail_json FROM hiu_consent_artefacts WHERE consent_id = ?').bind(consentId).first();
            if (known?.detail_json && known.status === 'GRANTED') continue;
            try {
                await fetchArtefact(env, db, { consentId, consentRequestId, clinicId: cr.clinic_id, hiuId: cr.hiu_id });
            } catch (err) {
                console.error('[hiu] consent fetch failed:', err instanceof AbdmApiError ? abdmErrorText(err) : err.message);
            }
        }
    } else if (['REVOKED', 'EXPIRED'].includes(status)) {
        const ids = artefactIds.length ? artefactIds : (await db.prepare('SELECT consent_id FROM hiu_consent_artefacts WHERE consent_request_id = ?').bind(consentRequestId).all()).results.map((r) => r.consent_id);
        await withdraw(db, ids, status);
    }
    return cr;
}

hiuCallbacks.post('/api/v3/hiu/consent/request/notify', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const requestId = requestIdOf(c);
    return answerLater(c, 'hiu consent notify', async () => {
        const n = body.notification || {};
        const artefactIds = (n.consentArtefacts || []).map((a) => a.id).filter(Boolean);
        const cr = await onConsentStatus(c.env, c.env.DB, { consentRequestId: n.consentRequestId, status: n.status, artefactIds });
        if (n.reason && cr) await c.env.DB.prepare('UPDATE hiu_consent_requests SET error = ? WHERE id = ?').bind(String(n.reason).slice(0, 300), cr.id).run();
        await hiecm(c.env, '/consent/v3/request/hiu/on-notify', {
            acknowledgement: artefactIds.map((consentId) => ({ status: 'OK', consentId })),
            ...(cr ? {} : { error: { code: 'ABDM-9999', message: 'Unknown consent request' } }),
            response: { requestId },
        }, { hiuId: cr?.hiu_id || c.req.header('X-HIU-ID') || undefined });
    });
});

hiuCallbacks.post('/api/v3/hiu/consent/request/on-status', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    return answerLater(c, 'hiu consent on-status', async () => {
        const cr = body.consentRequest || {};
        if (body.error || !cr.id) return console.warn('[hiu] on-status:', JSON.stringify(body.error || body));
        await onConsentStatus(c.env, c.env.DB, { consentRequestId: cr.id, status: cr.status, artefactIds: (cr.consentArtefacts || []).map((a) => a.id).filter(Boolean) });
    });
});

hiuCallbacks.post('/api/v3/hiu/consent/on-fetch', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const origin = publicOrigin(c, getAbdmConfig(c.env));
    return answerLater(c, 'hiu consent on-fetch', async () => {
        const db = c.env.DB;
        const detail = body.consent?.consentDetail;
        const artefact = await db.prepare('SELECT * FROM hiu_consent_artefacts WHERE fetch_request_id = ? OR consent_id = ?').bind(body?.response?.requestId || '', detail?.consentId || '').first();
        if (!artefact) return console.warn('[hiu] on-fetch for an unknown artefact');
        if (body.error || !detail) {
            await db.prepare(`UPDATE hiu_consent_artefacts SET status = 'failed', updated_at = datetime('now') WHERE consent_id = ?`).bind(artefact.consent_id).run();
            return;
        }
        const status = String(body.consent.status || 'GRANTED').toUpperCase();
        await db
            .prepare(`UPDATE hiu_consent_artefacts SET status = ?, hip_id = ?, patient_abha = ?, detail_json = ?, signature = ?, data_erase_at = ?, updated_at = datetime('now') WHERE consent_id = ?`)
            .bind(status, detail.hip?.id || null, String(detail.patient?.id || '').toLowerCase() || null, JSON.stringify(detail), body.consent.signature || null, detail.permission?.dataEraseAt || null, artefact.consent_id)
            .run();
        if (status === 'GRANTED') await requestData(c.env, db, await db.prepare('SELECT * FROM hiu_consent_artefacts WHERE consent_id = ?').bind(artefact.consent_id).first(), origin);
    });
});

hiuCallbacks.post('/api/v3/hiu/health-information/on-request', signed, async (c) => {
    const body = await c.req.json().catch(() => ({}));
    return answerLater(c, 'hiu health-information on-request', async () => {
        const requestId = body?.response?.requestId || '';
        if (body.error || !body.hiRequest?.transactionId) {
            await c.env.DB.prepare(`UPDATE hiu_data_requests SET status = 'failed', error = ?, private_key = NULL, updated_at = datetime('now') WHERE request_id = ?`).bind(errorText(body.error), requestId).run();
            return;
        }
        await c.env.DB
            .prepare(`UPDATE hiu_data_requests SET transaction_id = ?, status = CASE WHEN status = 'requested' THEN 'acknowledged' ELSE status END, updated_at = datetime('now') WHERE request_id = ?`)
            .bind(body.hiRequest.transactionId, requestId)
            .run();
    });
});

/** Decrypts one page a HIP pushed and stores its records. Returns the per-record statuses. */
export async function receivePage(db, dr, artefact, page) {
    const senderPublicKey = page.keyMaterial?.dhPublicKey?.keyValue;
    const senderNonce = page.keyMaterial?.nonce;
    const statuses = [];
    for (const entry of page.entries || []) {
        const ref = String(entry.careContextReference || '');
        try {
            if (!entry.content) throw new Error('Linked (not inline) content is not supported');
            const json = await decrypt({ encryptedData: entry.content, requesterNonce: dr.nonce, senderNonce, requesterPrivateKey: dr.private_key, senderPublicKey });
            const bundle = JSON.parse(json);
            if (bundle?.resourceType !== 'Bundle') throw new Error('Not a FHIR Bundle');
            await db
                .prepare(
                    `INSERT INTO hiu_health_records (id, clinic_id, consent_id, transaction_id, hip_id, patient_abha, care_context_reference, bundle_json, erase_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                     ON CONFLICT (consent_id, care_context_reference) DO UPDATE SET bundle_json = excluded.bundle_json, transaction_id = excluded.transaction_id, received_at = datetime('now')`,
                )
                .bind(crypto.randomUUID(), dr.clinic_id, dr.consent_id, page.transactionId, artefact?.hip_id || null, artefact?.patient_abha || null, ref, json, artefact?.data_erase_at || null)
                .run();
            statuses.push({ careContextReference: ref, hiStatus: 'OK', description: 'Received' });
        } catch (err) {
            statuses.push({ careContextReference: ref, hiStatus: 'ERRORED', description: String(err.message || 'Could not read the record').slice(0, 200) });
        }
    }
    return statuses;
}

// The HIP's push: straight from the HIP, not through HIE-CM, so no ABDM signature.
export const dataPushRoutes = new Hono();
dataPushRoutes.post('/:id', async (c) => {
    const db = c.env.DB;
    const dr = await db.prepare('SELECT * FROM hiu_data_requests WHERE id = ?').bind(c.req.param('id')).first();
    if (!dr || !dr.private_key) return c.json({ error: { code: 'ABDM-9999', message: 'Unknown or finished data request' } }, 404);
    const page = await c.req.json().catch(() => null);
    if (!page?.transactionId || !Array.isArray(page.entries)) return c.json({ error: { code: 'ABDM-9999', message: 'Invalid data push' } }, 400);
    if (dr.transaction_id && dr.transaction_id !== page.transactionId) return c.json({ error: { code: 'ABDM-9999', message: 'Transaction mismatch' } }, 400);
    const artefact = await db.prepare('SELECT * FROM hiu_consent_artefacts WHERE consent_id = ?').bind(dr.consent_id).first();
    if (!artefact || artefact.status !== 'GRANTED') return c.json({ error: { code: 'ABDM-9999', message: 'Consent is not active' } }, 409);

    const statuses = [...JSON.parse(dr.statuses_json || '[]'), ...(await receivePage(db, dr, artefact, page))];
    const pages = dr.pages_received + 1;
    const done = pages >= Math.max(1, Number(page.pageCount) || 1);
    await db
        .prepare(
            `UPDATE hiu_data_requests SET transaction_id = ?, pages_received = ?, statuses_json = ?, records_received = ?,
               status = ?, private_key = CASE WHEN ? THEN NULL ELSE private_key END, updated_at = datetime('now') WHERE id = ?`,
        )
        .bind(page.transactionId, pages, JSON.stringify(statuses), statuses.filter((s) => s.hiStatus === 'OK').length, done ? 'received' : dr.status, done ? 1 : 0, dr.id)
        .run();

    if (done) {
        const work = hiecm(c.env, '/data-flow/v3/health-information/notify', {
            notification: {
                consentId: dr.consent_id,
                transactionId: page.transactionId,
                doneAt: nowIso(),
                notifier: { type: 'HIU', id: dr.hiu_id },
                statusNotification: { sessionStatus: statuses.some((s) => s.hiStatus === 'OK') ? 'TRANSFERRED' : 'FAILED', hipId: artefact.hip_id, statusResponses: statuses },
            },
        }, { hiuId: dr.hiu_id }).catch((err) => console.error('[hiu] notify failed:', err instanceof AbdmApiError ? abdmErrorText(err) : err.message));
        try { c.executionCtx.waitUntil(work); } catch { await work; }
    }
    return c.json({}, 202);
});

// ── Staff (behind the session gate of /hie/*) ───────────────────────────────────────────────
export const hiuStaffRoutes = new Hono();
hiuStaffRoutes.onError(staffAbdmErrorHandler('hiu', AbdmApiError));

/** Validates a consent request; returns { error } or the request ABDM is sent. */
export function parseConsentRequest(body, now = Date.now()) {
    const abhaAddress = abhaAddressOf(body?.abhaAddress);
    if (!abhaAddress) return { error: 'The patient’s ABHA address is needed (like name@sbx).' };
    const purposeCode = String(body?.purposeCode || 'CAREMGT').toUpperCase();
    if (!PURPOSES[purposeCode]) return { error: `Purpose must be one of ${Object.keys(PURPOSES).join(', ')}.` };
    const hiTypes = [...new Set((body?.hiTypes?.length ? body.hiTypes : HI_TYPES).map(hiTypeOf))];
    if (hiTypes.includes(null) || !hiTypes.length) return { error: `Record types must be among ${HI_TYPES.join(', ')}.` };
    const from = new Date(body?.from || now - 5 * 365 * 86400000);
    const to = new Date(body?.to || now);
    const eraseAt = new Date(body?.eraseAt || now + 30 * 86400000);
    if ([from, to, eraseAt].some((d) => Number.isNaN(d.getTime()))) return { error: 'Dates must be valid.' };
    if (from >= to) return { error: 'The date range must start before it ends.' };
    if (eraseAt.getTime() <= now) return { error: 'Keep the records until a date in the future.' };
    const requesterName = String(body?.requester?.name || '').trim();
    if (!requesterName) return { error: 'Who is asking (the requester’s name) is needed.' };
    const identifier = body?.requester?.identifier || {};
    const requester = { name: requesterName, identifier: { type: identifier.type || 'REGNO', value: String(identifier.value || '').trim() || 'NA', system: identifier.system || 'https://www.mciindia.org' } };
    return {
        value: {
            facilityId: String(body?.facilityId || '').trim().toUpperCase(), abhaAddress, purposeCode, hiTypes, requester,
            from: from.toISOString(), to: to.toISOString(), eraseAt: eraseAt.toISOString(),
        },
    };
}

export const consentInitBody = (v) => ({
    consent: {
        purpose: { text: PURPOSES[v.purposeCode], code: v.purposeCode, refUri: PURPOSE_URI },
        patient: { id: v.abhaAddress },
        hiu: { id: v.facilityId },
        requester: v.requester,
        hiTypes: v.hiTypes,
        permission: { accessMode: 'VIEW', dateRange: { from: v.from, to: v.to }, dataEraseAt: v.eraseAt, frequency: { unit: 'HOUR', value: 1, repeats: 0 } },
    },
});

hiuStaffRoutes.post('/consent-requests', async (c) => {
    const { clinicId, accountId } = c.get('user');
    const parsed = parseConsentRequest(await c.req.json().catch(() => ({})));
    if (parsed.error) return c.json({ success: false, error: parsed.error }, 400);
    const v = parsed.value;
    const db = c.env.DB;
    const facility = await facilityOwner(db, v.facilityId);
    if (!facility || facility.clinic_id !== clinicId) return c.json({ success: false, error: 'Unknown facility.' }, 400);
    if (!facility.hiu_enabled) return c.json({ success: false, error: 'This facility does not receive records yet: turn on “Receive records (HIU)” for it on the ABDM records page.' }, 400);
    const id = crypto.randomUUID();
    const requestId = crypto.randomUUID();
    await db
        .prepare(
            `INSERT INTO hiu_consent_requests (id, clinic_id, hiu_id, request_id, patient_abha, purpose_code, purpose_text, hi_types_json, date_from, date_to, data_erase_at, requester_json, created_by_account_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(id, clinicId, v.facilityId, requestId, v.abhaAddress, v.purposeCode, PURPOSES[v.purposeCode], JSON.stringify(v.hiTypes), v.from, v.to, v.eraseAt, JSON.stringify(v.requester), accountId ?? null)
        .run();
    try {
        await hiecm(c.env, '/consent/v3/request/init', consentInitBody(v), { hiuId: v.facilityId, requestId });
    } catch (err) {
        const message = err instanceof AbdmApiError ? abdmErrorText(err) : err.message;
        await db.prepare(`UPDATE hiu_consent_requests SET status = 'failed', error = ?, updated_at = datetime('now') WHERE id = ?`).bind(message, id).run();
        return c.json({ success: false, error: message, id }, 502);
    }
    return c.json({ success: true, id }, 201);
});

const consentRequestView = (r, artefacts) => ({
    id: r.id, facilityId: r.hiu_id, consentRequestId: r.consent_request_id, abhaAddress: r.patient_abha, purpose: r.purpose_text, purposeCode: r.purpose_code,
    hiTypes: JSON.parse(r.hi_types_json || '[]'), from: r.date_from, to: r.date_to, eraseAt: r.data_erase_at, status: r.status, error: r.error, createdAt: r.created_at, updatedAt: r.updated_at,
    artefacts: artefacts.filter((a) => a.consent_request_id === r.consent_request_id).map((a) => ({ consentId: a.consent_id, hipId: a.hip_id, status: a.status, eraseAt: a.data_erase_at })),
});

hiuStaffRoutes.get('/consent-requests', async (c) => {
    const { clinicId } = c.get('user');
    const abha = c.req.query('abhaAddress');
    const db = c.env.DB;
    const { results } = abha
        ? await db.prepare('SELECT * FROM hiu_consent_requests WHERE clinic_id = ? AND patient_abha = ? ORDER BY created_at DESC LIMIT 50').bind(clinicId, String(abha).toLowerCase()).all()
        : await db.prepare('SELECT * FROM hiu_consent_requests WHERE clinic_id = ? ORDER BY created_at DESC LIMIT 50').bind(clinicId).all();
    const { results: artefacts } = await db.prepare('SELECT * FROM hiu_consent_artefacts WHERE clinic_id = ?').bind(clinicId).all();
    return c.json({ success: true, purposes: PURPOSES, hiTypes: HI_TYPES, consentRequests: results.map((r) => consentRequestView(r, artefacts)) });
});

hiuStaffRoutes.post('/consent-requests/:id/status', async (c) => {
    const { clinicId } = c.get('user');
    const cr = await c.env.DB.prepare('SELECT * FROM hiu_consent_requests WHERE id = ? AND clinic_id = ?').bind(c.req.param('id'), clinicId).first();
    if (!cr) return c.json({ success: false, error: 'No such request.' }, 404);
    if (!cr.consent_request_id) return c.json({ success: false, error: 'ABDM has not acknowledged this request yet.' }, 409);
    await hiecm(c.env, '/consent/v3/request/status', { consentRequestId: cr.consent_request_id }, { hiuId: cr.hiu_id, requestId: crypto.randomUUID() });
    return c.json({ success: true });
});

hiuStaffRoutes.post('/artefacts/:consentId/fetch-data', async (c) => {
    const { clinicId } = c.get('user');
    const db = c.env.DB;
    const artefact = await db.prepare('SELECT * FROM hiu_consent_artefacts WHERE consent_id = ? AND clinic_id = ?').bind(c.req.param('consentId'), clinicId).first();
    if (!artefact) return c.json({ success: false, error: 'No such consent.' }, 404);
    if (artefact.status !== 'GRANTED' || !artefact.detail_json) return c.json({ success: false, error: `This consent is ${artefact.status.toLowerCase()}.` }, 409);
    if (artefact.data_erase_at && Date.parse(artefact.data_erase_at) < Date.now()) return c.json({ success: false, error: 'This consent has expired.' }, 409);
    await requestData(c.env, db, artefact, publicOrigin(c, getAbdmConfig(c.env)));
    return c.json({ success: true });
});

hiuStaffRoutes.get('/records', async (c) => {
    const { clinicId } = c.get('user');
    const db = c.env.DB;
    await purgeExpiredRecords(db);
    const abha = abhaAddressOf(c.req.query('abhaAddress'));
    if (!abha) return c.json({ success: false, error: 'abhaAddress is required' }, 400);
    const { results } = await db.prepare('SELECT * FROM hiu_health_records WHERE clinic_id = ? AND patient_abha = ? ORDER BY received_at DESC').bind(clinicId, abha).all();
    return c.json({
        success: true,
        records: results.map((r) => ({ id: r.id, consentId: r.consent_id, hipId: r.hip_id, careContextReference: r.care_context_reference, receivedAt: r.received_at, eraseAt: r.erase_at, bundle: JSON.parse(r.bundle_json) })),
    });
});
