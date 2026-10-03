// Scan & Share (ABDM M1, "Scan Health Facility QR"; NHA's Scan & Share sandbox doc v1.0,
// 03-03-2025, §4). A patient scans the facility's QR — a URL of the form
// <phr>/share-profile?hipid=<HFR facility id>&counterid=<counter> — with the ABHA app; ABDM's
// HIE-CM then calls this gateway's HIP callback with their verified profile, and the gateway
// answers through on-share with a token number for that counter. The clinic's front desk sees the
// queue and turns each share into a patient record with the Patient ABHA journey.
//
//   POST /api/v3/hip/patient/share           ABDM -> gateway (public; ABDM's JWT verified)
//   GET  /abha/scan-share/facilities         the clinic's facilities that take Scan & Share
//   POST /abha/scan-share/facilities         { facilityId, facilityName, hipName, linkWithAbdm }
//   DELETE /abha/scan-share/facilities/:id   stop taking shares for a facility
//   GET  /abha/scan-share/queue              today's shares (?facilityId=&context=)
//   POST /abha/scan-share/queue/:id/claim    -> the shared profile, once; then it is cleared
//   POST /abha/scan-share/queue/:id/dismiss
//   PATCH /abha/scan-share/facilities/:id    { hiuEnabled, scanPayEnabled, upiVpa, payeeName } (M2/M3, Scan & Pay)
//
// Running Token Status (NHA "Running Token Status" doc): staff call the next token at a counter;
// ABDM asks on a patient's behalf which token is being served there.
//   POST /abha/scan-share/counters/call-next  { facilityId, context } -> the token now being served
//   GET  /abha/scan-share/counters            today's counters (?facilityId=)
//   POST /api/v3/hip/patient/running-token/status  ABDM -> gateway -> running-token/on-status
//
// For ABDM to reach the callback, the gateway's public URL must be set as this client's bridge
// URL (scripts/set-bridge-url.js) and the facility linked to the bridge as a HIP service — through
// POST /abha/scan-share/facilities with linkWithAbdm, or on the HFR portal (doc §3.2.5 option 1).
//
// Storage: the shared `clinuxflow` D1 (clinuxflow-api migrations/0018). A shared profile is kept
// only until it is claimed, or a day at most.
import { Hono } from 'hono';
import { callAbdm, AbdmApiError } from '../lib/abdmClient.js';
import { getAbdmConfig } from '../lib/config.js';
import { getAccessToken } from '../lib/sessionToken.js';
import { verifyAbdmJwt } from '../lib/abdmJwt.js';
import { abdmCallbackAuth, answerLater, hiecm, requestIdOf } from '../lib/abdmCallback.js';

/** Today in India (token numbers restart each day per counter). */
export const shareDate = (now = Date.now()) => new Date(now + 5.5 * 3600 * 1000).toISOString().slice(0, 10);

/** The facility's Scan & Share QR contents (doc §4.1). */
export const shareQrUrl = (phrBaseUrl, facilityId, counterId) =>
    `${phrBaseUrl}/share-profile?hipid=${encodeURIComponent(facilityId)}&counterid=${encodeURIComponent(counterId)}`;

/** HFR's rule for a HIP name (doc §3.2.5): at most 15 characters, no special characters. */
export const validHipName = (s) => /^[A-Za-z0-9 ]{1,15}$/.test(String(s ?? '').trim());

/**
 * Why HFR's bridge-link answer is a failure, or null. "Already associated" with this facility is
 * success for us: the link we wanted is there.
 */
export function linkFailure(result, bridgeId) {
    const entries = Array.isArray(result) ? result : [result];
    for (const e of entries) {
        if (!e?.error) continue;
        const message = String(e.error.message || e.error.code || 'HFR refused the link');
        if (/already associated/i.test(message) && message.includes(bridgeId)) continue;
        return message;
    }
    return null;
}

const masked = (v) => (v ? `••••••${String(v).slice(-4)}` : '');

async function forgetOldProfiles(db) {
    await db.prepare(`UPDATE scan_share_requests SET profile_json = NULL WHERE profile_json IS NOT NULL AND created_at < datetime('now', '-1 day')`).run();
}

/** Stores one share and returns its token number (the same one if this ABHA is already waiting). */
export async function recordShare(db, { clinicId, hipId, context, requestId, patient, now = Date.now() }) {
    const date = shareDate(now);
    const abhaAddress = patient.abhaAddress ? String(patient.abhaAddress) : null;
    const abhaNumber = patient.abhaNumber ? String(patient.abhaNumber) : null;
    const profileJson = JSON.stringify(patient);

    if (abhaAddress || abhaNumber) {
        const existing = await db
            .prepare(`SELECT id, token_number FROM scan_share_requests WHERE hip_id = ? AND context = ? AND share_date = ? AND status = 'waiting' AND (abha_address = ? OR abha_number = ?)`)
            .bind(hipId, context, date, abhaAddress, abhaNumber)
            .first();
        if (existing) {
            await db.prepare(`UPDATE scan_share_requests SET request_id = ?, profile_json = ?, acknowledged = 0, ack_error = NULL WHERE id = ?`).bind(requestId, profileJson, existing.id).run();
            return { id: existing.id, tokenNumber: existing.token_number, repeat: true };
        }
    }

    const id = crypto.randomUUID();
    // One statement, so two shares arriving together can't take the same number (UNIQUE backs it up).
    await db
        .prepare(
            `INSERT INTO scan_share_requests (id, clinic_id, hip_id, context, share_date, token_number, request_id, abha_number, abha_address, display_name, gender, year_of_birth, profile_json)
             SELECT ?, ?, ?, ?, ?, COALESCE(MAX(token_number), 0) + 1, ?, ?, ?, ?, ?, ?, ?
             FROM scan_share_requests WHERE hip_id = ? AND context = ? AND share_date = ?`,
        )
        .bind(id, clinicId, hipId, context, date, requestId, abhaNumber, abhaAddress, patient.name || null, patient.gender || null, patient.yearOfBirth ? String(patient.yearOfBirth) : null, profileJson, hipId, context, date)
        .run();
    const row = await db.prepare('SELECT token_number FROM scan_share_requests WHERE id = ?').bind(id).first();
    return { id, tokenNumber: row.token_number, repeat: false };
}

// ── ABDM -> gateway ──────────────────────────────────────────────────────────────────────────
export const hipCallbackRoutes = new Hono();

async function onShare(env, body) {
    const config = getAbdmConfig(env);
    const accessToken = await getAccessToken(env);
    return callAbdm({ url: `${config.hiecmBaseUrl}/patient-share/v3/on-share`, xCmId: config.xCmId, accessToken, body, maxAttempts: 2 });
}

hipCallbackRoutes.post('/patient/share', async (c) => {
    const config = getAbdmConfig(c.env);
    // ABDM's signature on the callback. ABDM_CALLBACK_AUTH=off exists only for local testing.
    if (c.env.ABDM_CALLBACK_AUTH !== 'off') {
        const token = (c.req.header('Authorization') || '').replace(/^Bearer\s+/i, '');
        try {
            await verifyAbdmJwt(token, { certsUrl: `${config.hiecmBaseUrl}/gateway/v3/certs`, xCmId: config.xCmId });
        } catch (err) {
            console.warn('[scan-share] callback refused:', err.message);
            return c.json({ error: { code: 'ABDM-1017', message: 'Invalid authorization' } }, 401);
        }
    }

    const body = await c.req.json().catch(() => null);
    const requestId = c.req.header('REQUEST-ID') || crypto.randomUUID();
    const patient = body?.profile?.patient;
    const hipId = String(body?.metaData?.hipId || c.req.header('X-HIP-ID') || '').trim();
    const context = String(body?.metaData?.context ?? '').trim();
    if (body?.intent && body.intent !== 'PROFILE_SHARE') return c.json({ error: { code: 'ABDM-9999', message: `Unsupported intent ${body.intent}` } }, 400);
    if (!patient || !hipId) return c.json({ error: { code: 'ABDM-9999', message: 'metaData.hipId and profile.patient are required' } }, 400);

    const db = c.env.DB;
    const facility = await db.prepare('SELECT clinic_id FROM hip_facilities WHERE facility_id = ? AND active = 1').bind(hipId).first();

    const acknowledge = async () => {
        if (!facility) {
            await onShare(c.env, { error: { code: 'ABDM-9999', message: 'This facility does not take Scan & Share through ClinuxFlow' }, response: { requestId } });
            return;
        }
        const share = await recordShare(db, { clinicId: facility.clinic_id, hipId, context, requestId, patient });
        try {
            await onShare(c.env, {
                acknowledgement: { abhaAddress: patient.abhaAddress, status: 'success', profile: { context, tokenNumber: String(share.tokenNumber), expiry: '180' } },
                response: { requestId },
            });
            await db.prepare('UPDATE scan_share_requests SET acknowledged = 1 WHERE id = ?').bind(share.id).run();
        } catch (err) {
            const message = err instanceof AbdmApiError ? `ABDM ${err.status}` : err.message;
            console.error('[scan-share] on-share failed:', message);
            await db.prepare('UPDATE scan_share_requests SET ack_error = ? WHERE id = ?').bind(String(message).slice(0, 200), share.id).run();
        }
    };

    // Answer ABDM at once; the token goes back through on-share (doc §4.3.3).
    const work = acknowledge().catch((err) => console.error('[scan-share] could not record a share:', err));
    try {
        c.executionCtx.waitUntil(work);
    } catch {
        await work; // no execution context (tests, plain Node)
    }
    return c.json({}, 202);
});

/** The token being served at a counter today, and the average minutes per token once two have been called. */
export async function runningToken(db, hipId, context, now = Date.now()) {
    const row = await db.prepare('SELECT * FROM counter_tokens WHERE hip_id = ? AND context = ? AND token_date = ?').bind(hipId, context, shareDate(now)).first();
    if (!row || !row.running_token) return null;
    const minutes = row.calls > 1 ? (Date.parse(row.last_called_at) - Date.parse(row.first_called_at)) / 60000 / (row.calls - 1) : null;
    return { runningToken: row.running_token, averageMinutes: minutes === null ? null : Math.max(1, Math.round(minutes)) };
}

hipCallbackRoutes.post('/patient/running-token/status', abdmCallbackAuth(), async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const requestId = requestIdOf(c);
    return answerLater(c, 'running-token', async () => {
        const hipId = String(body.hipId || c.req.header('X-HIP-ID') || '').trim();
        const context = String(body.context ?? '').trim();
        const reply = (payload) => hiecm(c.env, '/patient-share/v3/running-token/on-status', { ...payload, response: { requestId } }, { hipId: hipId || undefined });
        const facility = await c.env.DB.prepare('SELECT 1 FROM hip_facilities WHERE facility_id = ? AND active = 1').bind(hipId).first();
        if (!facility) return reply({ error: { code: 'ABDM-9999', message: 'This facility does not issue tokens through ClinuxFlow' } });
        const now = await runningToken(c.env.DB, hipId, context);
        if (!now) return reply({ error: { code: 'ABDM-1031', message: 'No token has been called at this counter yet today' } });
        await reply({ token: { hipId, context, runningTokenNumber: String(now.runningToken), ...(now.averageMinutes ? { averageTokenServiceTimeInMinutes: now.averageMinutes } : {}) } });
    });
});

// ── Staff (behind the session gate of /abha/*) ───────────────────────────────────────────────
export const scanShareRoutes = new Hono();

scanShareRoutes.onError((err, c) => {
    if (err instanceof AbdmApiError) {
        console.error(`[scan-share] ABDM error ${err.status}:`, JSON.stringify(err.body));
        return c.json({ success: false, error: 'ABDM request failed', abdmStatus: err.status, abdmBody: err.body, abdmRequestId: err.requestId }, 502);
    }
    console.error('[scan-share] unexpected error:', err);
    return c.json({ success: false, error: err.message }, 500);
});

const facilityRow = (r, phrBaseUrl) => ({
    facilityId: r.facility_id, facilityName: r.facility_name, hipName: r.hip_name, linkedWithAbdm: !!r.linked_with_abdm, active: !!r.active,
    hiuEnabled: !!r.hiu_enabled, scanPayEnabled: !!r.scan_pay_enabled, upiVpa: r.upi_vpa || '', payeeName: r.payee_name || '',
    qrUrl: shareQrUrl(phrBaseUrl, r.facility_id, '{counter}'),
});

scanShareRoutes.get('/facilities', async (c) => {
    const { clinicId } = c.get('user');
    const config = getAbdmConfig(c.env);
    const { results } = await c.env.DB.prepare('SELECT * FROM hip_facilities WHERE clinic_id = ? AND active = 1 ORDER BY facility_name').bind(clinicId).all();
    return c.json({ success: true, phrBaseUrl: config.phrBaseUrl, facilities: results.map((r) => facilityRow(r, config.phrBaseUrl)) });
});

scanShareRoutes.post('/facilities', async (c) => {
    const { clinicId, accountId } = c.get('user');
    const { facilityId, facilityName, hipName, linkWithAbdm } = await c.req.json().catch(() => ({}));
    const id = String(facilityId || '').trim().toUpperCase();
    if (!/^IN[A-Z0-9]{10}$/.test(id)) return c.json({ success: false, error: 'An HFR facility id starts with IN and has 12 characters.' }, 400);
    if (linkWithAbdm && !validHipName(hipName)) return c.json({ success: false, error: 'The name ABHA apps show must be at most 15 letters, digits or spaces.' }, 400);

    const db = c.env.DB;
    const owner = await db.prepare('SELECT clinic_id FROM hip_facilities WHERE facility_id = ?').bind(id).first();
    if (owner && owner.clinic_id !== clinicId) return c.json({ success: false, error: 'Another ClinuxFlow clinic already takes Scan & Share for this facility.' }, 409);

    let linked = false;
    if (linkWithAbdm) {
        const config = getAbdmConfig(c.env);
        const accessToken = await getAccessToken(c.env);
        // HFR's Multiple HRP API (New_HFR_APIs_Documentation_SBX §4): this gateway's client id is
        // the bridge. It lives on the HPR/HFR host (the Scan & Share doc's facilitysbx URL is out of
        // date), and answers 200 with [{ servicesLinked }] or [{ error: { code, message } }].
        const result = await callAbdm({
            url: `${config.hprHfrBaseUrl}/v1/bridges/MutipleHRPAddUpdateServices`,
            xCmId: config.xCmId,
            accessToken,
            maxAttempts: 1,
            body: { facilityId: id, facilityName: String(facilityName || '').trim(), HRP: [{ bridgeId: config.clientId, hipName: String(hipName).trim(), type: 'HIP', active: true }] },
        });
        const failure = linkFailure(result, config.clientId);
        if (failure) return c.json({ success: false, error: failure }, 502);
        linked = true;
    }

    await db
        .prepare(
            `INSERT INTO hip_facilities (facility_id, clinic_id, facility_name, hip_name, linked_with_abdm, active, created_by_account_id)
             VALUES (?, ?, ?, ?, ?, 1, ?)
             ON CONFLICT (facility_id) DO UPDATE SET facility_name = excluded.facility_name, hip_name = COALESCE(excluded.hip_name, hip_facilities.hip_name),
               linked_with_abdm = MAX(hip_facilities.linked_with_abdm, excluded.linked_with_abdm), active = 1, updated_at = datetime('now')`,
        )
        .bind(id, clinicId, String(facilityName || '').trim(), hipName ? String(hipName).trim() : null, linked ? 1 : 0, accountId ?? null)
        .run();
    const row = await db.prepare('SELECT * FROM hip_facilities WHERE facility_id = ?').bind(id).first();
    return c.json({ success: true, facility: facilityRow(row, getAbdmConfig(c.env).phrBaseUrl) }, 201);
});

scanShareRoutes.delete('/facilities/:facilityId', async (c) => {
    const { clinicId } = c.get('user');
    await c.env.DB.prepare(`UPDATE hip_facilities SET active = 0, updated_at = datetime('now') WHERE facility_id = ? AND clinic_id = ?`).bind(c.req.param('facilityId'), clinicId).run();
    return c.json({ success: true });
});

scanShareRoutes.get('/queue', async (c) => {
    const { clinicId } = c.get('user');
    const { facilityId, context } = c.req.query();
    const db = c.env.DB;
    await forgetOldProfiles(db);
    const where = ['clinic_id = ?', 'share_date = ?'];
    const args = [clinicId, shareDate()];
    if (facilityId) { where.push('hip_id = ?'); args.push(facilityId); }
    if (context) { where.push('context = ?'); args.push(context); }
    const { results } = await db.prepare(`SELECT * FROM scan_share_requests WHERE ${where.join(' AND ')} ORDER BY token_number`).bind(...args).all();
    const shares = results.map((r) => {
        const p = r.profile_json ? JSON.parse(r.profile_json) : {};
        return {
            id: r.id, facilityId: r.hip_id, context: r.context, tokenNumber: r.token_number, status: r.status,
            name: r.display_name, gender: r.gender, yearOfBirth: r.year_of_birth, abhaAddress: r.abha_address,
            abhaNumber: r.abha_number ? masked(r.abha_number) : '', phone: masked(p.phoneNumber),
            acknowledged: !!r.acknowledged, ackError: r.ack_error, at: r.created_at, claimedAt: r.claimed_at, calledAt: r.called_at,
        };
    });
    const counters = {};
    for (const s of shares) if (!(s.context in counters)) counters[s.context] = await runningToken(db, s.facilityId, s.context);
    return c.json({ success: true, date: shareDate(), shares, counters });
});

scanShareRoutes.post('/queue/:id/claim', async (c) => {
    const { clinicId, accountId } = c.get('user');
    const db = c.env.DB;
    const row = await db.prepare('SELECT * FROM scan_share_requests WHERE id = ? AND clinic_id = ?').bind(c.req.param('id'), clinicId).first();
    if (!row) return c.json({ success: false, error: 'No such share.' }, 404);
    if (row.status !== 'waiting' || !row.profile_json) return c.json({ success: false, error: 'This share was already taken up, or has expired.' }, 409);
    // Only the first claim gets the profile: the row moves to claimed and the profile is cleared.
    const res = await db
        .prepare(`UPDATE scan_share_requests SET status = 'claimed', claimed_by_account_id = ?, claimed_at = datetime('now'), profile_json = NULL WHERE id = ? AND status = 'waiting'`)
        .bind(accountId ?? null, row.id)
        .run();
    if (res?.meta && res.meta.changes === 0) return c.json({ success: false, error: 'This share was already taken up.' }, 409);
    return c.json({ success: true, share: { id: row.id, facilityId: row.hip_id, context: row.context, tokenNumber: row.token_number, patient: JSON.parse(row.profile_json) } });
});

scanShareRoutes.post('/queue/:id/dismiss', async (c) => {
    const { clinicId } = c.get('user');
    await c.env.DB.prepare(`UPDATE scan_share_requests SET status = 'dismissed', profile_json = NULL WHERE id = ? AND clinic_id = ?`).bind(c.req.param('id'), clinicId).run();
    return c.json({ success: true });
});

/** A UPI id: handle@bank. */
export const validVpa = (v) => /^[A-Za-z0-9._-]{2,256}@[A-Za-z][A-Za-z0-9.]{1,63}$/.test(String(v || '').trim());

// What else the facility does on ABDM: receive records (HIU, M3) and Scan & Pay. Turning either on
// links it on ABDM's side too (HFR's bridge API for the HIU role; scanPay/updateVersion for Pay),
// unless `linkWithAbdm` is false because it was done on the HFR portal.
scanShareRoutes.patch('/facilities/:facilityId', async (c) => {
    const { clinicId } = c.get('user');
    const db = c.env.DB;
    const row = await db.prepare('SELECT * FROM hip_facilities WHERE facility_id = ? AND clinic_id = ? AND active = 1').bind(c.req.param('facilityId'), clinicId).first();
    if (!row) return c.json({ success: false, error: 'Register this facility for Scan & Share first.' }, 404);
    const body = await c.req.json().catch(() => ({}));
    const hiuEnabled = body.hiuEnabled === undefined ? !!row.hiu_enabled : !!body.hiuEnabled;
    const scanPayEnabled = body.scanPayEnabled === undefined ? !!row.scan_pay_enabled : !!body.scanPayEnabled;
    const upiVpa = body.upiVpa === undefined ? row.upi_vpa : String(body.upiVpa || '').trim() || null;
    if (upiVpa && !validVpa(upiVpa)) return c.json({ success: false, error: 'That is not a UPI id (like clinic@okbank).' }, 400);
    const payeeName = body.payeeName === undefined ? row.payee_name : String(body.payeeName || '').trim().slice(0, 60) || null;
    const linkWithAbdm = body.linkWithAbdm !== false;
    const config = getAbdmConfig(c.env);
    if (linkWithAbdm && hiuEnabled && !row.hiu_enabled) {
        if (!validHipName(row.hip_name || '')) return c.json({ success: false, error: 'Give the facility a name for ABHA apps first (at most 15 letters, digits or spaces).' }, 400);
        // Same HFR API and host as the HIP link above; refusals come back in a 200.
        const linked = await callAbdm({
            url: `${config.hprHfrBaseUrl}/v1/bridges/MutipleHRPAddUpdateServices`, xCmId: config.xCmId, accessToken: await getAccessToken(c.env), maxAttempts: 1,
            body: { facilityId: row.facility_id, facilityName: row.facility_name, HRP: [{ bridgeId: config.clientId, hipName: row.hip_name, type: 'HIU', active: true }] },
        });
        const failure = linkFailure(linked, config.clientId);
        if (failure) return c.json({ success: false, error: failure }, 502);
    }
    if (linkWithAbdm && scanPayEnabled !== !!row.scan_pay_enabled) {
        await callAbdm({
            url: `${config.gatewayBaseUrl}/scanPay/updateVersion`, method: 'PATCH', xCmId: config.xCmId, accessToken: await getAccessToken(c.env), maxAttempts: 1,
            body: { recordShareEnabled: true, scanPayEnabled, scanPayVersion: 'V3', serviceId: [row.facility_id] },
        });
    }
    await db
        .prepare(`UPDATE hip_facilities SET hiu_enabled = ?, scan_pay_enabled = ?, upi_vpa = ?, payee_name = ?, updated_at = datetime('now') WHERE facility_id = ?`)
        .bind(hiuEnabled ? 1 : 0, scanPayEnabled ? 1 : 0, upiVpa, payeeName, row.facility_id)
        .run();
    return c.json({ success: true, facility: facilityRow(await db.prepare('SELECT * FROM hip_facilities WHERE facility_id = ?').bind(row.facility_id).first(), config.phrBaseUrl) });
});

scanShareRoutes.get('/counters', async (c) => {
    const { clinicId } = c.get('user');
    const { facilityId } = c.req.query();
    const args = [clinicId, shareDate()];
    const { results } = await c.env.DB.prepare(`SELECT * FROM counter_tokens WHERE clinic_id = ? AND token_date = ?${facilityId ? ' AND hip_id = ?' : ''}`).bind(...args, ...(facilityId ? [facilityId] : [])).all();
    const counters = [];
    for (const r of results) counters.push({ facilityId: r.hip_id, context: r.context, ...(await runningToken(c.env.DB, r.hip_id, r.context)) });
    return c.json({ success: true, counters });
});

// "Call next": the lowest token at this counter above the one being served that is still in the queue.
scanShareRoutes.post('/counters/call-next', async (c) => {
    const { clinicId } = c.get('user');
    const { facilityId, context } = await c.req.json().catch(() => ({}));
    const hipId = String(facilityId || '').trim();
    const ctx = String(context ?? '').trim();
    const db = c.env.DB;
    const owner = await db.prepare('SELECT clinic_id FROM hip_facilities WHERE facility_id = ? AND active = 1').bind(hipId).first();
    if (!owner || owner.clinic_id !== clinicId) return c.json({ success: false, error: 'Unknown facility.' }, 404);
    const date = shareDate();
    const current = await db.prepare('SELECT running_token FROM counter_tokens WHERE hip_id = ? AND context = ? AND token_date = ?').bind(hipId, ctx, date).first();
    const next = await db
        .prepare(`SELECT id, token_number FROM scan_share_requests WHERE hip_id = ? AND context = ? AND share_date = ? AND status != 'dismissed' AND token_number > ? ORDER BY token_number LIMIT 1`)
        .bind(hipId, ctx, date, current?.running_token || 0)
        .first();
    if (!next) return c.json({ success: false, error: 'Nobody else is waiting at this counter.' }, 409);
    const at = new Date().toISOString();
    await db
        .prepare(
            `INSERT INTO counter_tokens (hip_id, context, token_date, clinic_id, running_token, calls, first_called_at, last_called_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
             ON CONFLICT (hip_id, context, token_date) DO UPDATE SET running_token = excluded.running_token, calls = counter_tokens.calls + 1, last_called_at = excluded.last_called_at, updated_at = datetime('now')`,
        )
        .bind(hipId, ctx, date, clinicId, next.token_number, at, at)
        .run();
    await db.prepare('UPDATE scan_share_requests SET called_at = ? WHERE id = ?').bind(at, next.id).run();
    return c.json({ success: true, facilityId: hipId, context: ctx, ...(await runningToken(db, hipId, ctx)) });
});
