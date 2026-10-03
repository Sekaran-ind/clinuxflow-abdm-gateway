// Scan & Pay (NHA Scan & Pay doc v1.0, 11-08-2025, "ABDM Milestone 2"). The patient scans the
// facility's counter QR (the same share-profile QR as Scan & Share; the ABHA app offers Pay when
// the facility has Scan & Pay on) and sees what they owe; they pick the items and pay; the HIP
// tells ABDM how the payment went.
//
//   <- {bridge}/v3/patient/share/open-order      the patient's profile -> on-share/open-order with
//                                                the bills staff published for them at Checkout
//                                                (or, if none, once staff add one from the queue)
//   <- {bridge}/v3/patient/selection             what they chose -> on-selection with an order
//                                                number, amount and this gateway's pay page URL
//   GET  /pay/:token                             the pay page (UPI intent to the facility's UPI id)
//   POST /hie/scan-pay/orders/:id/payment        staff: received / failed / refunded -> scan-pay/notify
//   <- {bridge}/v3/patient/scan-pay/on-notify    ABDM's acknowledgement
//   <- {bridge}/v3/patient/scan-pay/order-status -> on-order-status with the current state
//
// There is no card/netbanking gateway contract behind this: the pay page hands the amount to the
// patient's UPI app (upi://pay to the facility's own UPI id), and staff confirm receipt — the same
// as a UPI QR at the counter, but itemised and recorded on ABDM. A real payment gateway can
// replace confirmPayment()'s caller (its webhook) without touching the ABDM side.
//
// Unlike every other HIE-CM callback, Scan & Pay's paths have no /api prefix ({callback_url}/v3/…);
// they are registered both ways.
import { Hono } from 'hono';
import { AbdmApiError } from '../lib/abdmClient.js';
import { getAbdmConfig } from '../lib/config.js';
import { abdmCallbackAuth, abdmErrorText, answerLater, facilityOwner, hiecm, publicOrigin, requestIdOf, staffAbdmErrorHandler } from '../lib/abdmCallback.js';
import { abhaAddressOf, abhaNumberDigits } from './hip.js';

export const CATEGORIES = ['OPD consultation', 'Laboratory and Diagnostics', 'Pharmacy', 'Miscellaneous/Other'];
export const PAYMENT_STATUSES = ['SUCCESS', 'CANCELED', 'PENDING', 'FAIL', 'REFUND_INITIATED', 'REFUND_SUCCESS'];
// ABDM-2407 "Please follow the logical status flow": what each status may move to.
export const NEXT_STATUS = {
    PENDING: ['SUCCESS', 'FAIL', 'CANCELED'],
    SUCCESS: ['REFUND_INITIATED'],
    REFUND_INITIATED: ['REFUND_SUCCESS'],
    FAIL: [],
    CANCELED: [],
    REFUND_SUCCESS: [],
};
const nowIso = () => new Date().toISOString();
const money = (n) => Math.round(Number(n) * 100) / 100;

/** Procedures in ABDM's shape, validated: [{ category, services: [{ serviceId, name, description, amount }] }]. */
export function normaliseProcedures(list) {
    if (!Array.isArray(list) || !list.length) throw new Error('At least one item is needed');
    return list.map((p) => {
        const category = CATEGORIES.find((c) => c.toLowerCase() === String(p?.category || '').toLowerCase()) || 'Miscellaneous/Other';
        const services = (p?.services || []).map((s) => {
            const amount = money(s?.amount);
            if (!(amount > 0)) throw new Error('Every item needs an amount above zero');
            const name = String(s?.name || '').trim();
            if (!name) throw new Error('Every item needs a name');
            return { serviceId: String(s?.serviceId || crypto.randomUUID()).slice(0, 64), name: name.slice(0, 120), description: String(s?.description || name).slice(0, 200), amount };
        });
        if (!services.length) throw new Error('A category needs at least one item');
        return { category, services };
    });
}

export const totalOf = (procedures) => money(procedures.flatMap((p) => p.services).reduce((sum, s) => sum + s.amount, 0));

/** Merges procedure lists, combining services of the same category. */
function mergeProcedures(lists) {
    const byCategory = new Map();
    for (const p of lists.flat()) {
        if (!byCategory.has(p.category)) byCategory.set(p.category, { category: p.category, services: [] });
        byCategory.get(p.category).services.push(...p.services);
    }
    return [...byCategory.values()];
}

/** Only what was offered can be chosen (matched by serviceId), and at the offered amount. */
export function selectedFrom(offered, chosen) {
    const offeredById = new Map(offered.flatMap((p) => p.services.map((s) => [s.serviceId, { ...s, category: p.category }])));
    const picked = (chosen || []).flatMap((p) => (p.services || []).map((s) => offeredById.get(String(s.serviceId)))).filter(Boolean);
    if (!picked.length) throw new Error('None of the chosen items were offered');
    return mergeProcedures(picked.map(({ category, ...s }) => [{ category, services: [s] }]));
}

const newOrderNumber = () => `CF${Date.now().toString(36).toUpperCase()}${String(crypto.getRandomValues(new Uint32Array(1))[0] % 1e6).padStart(6, '0')}`;
const newToken = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function offerBills(env, db, order) {
    const { results: bills } = await db
        .prepare(`SELECT * FROM scan_pay_bills WHERE hip_id = ? AND status = 'open' AND ((abha_address IS NOT NULL AND abha_address = ?) OR (abha_number IS NOT NULL AND abha_number = ?)) ORDER BY created_at`)
        .bind(order.hip_id, order.abha_address || '', order.abha_number || '')
        .all();
    if (!bills.length) return false;
    await sendOffer(env, db, order, bills);
    return true;
}

async function sendOffer(env, db, order, bills) {
    const procedures = mergeProcedures(bills.map((b) => JSON.parse(b.procedures_json)));
    const ids = bills.map((b) => b.id);
    await db.prepare(`UPDATE scan_pay_bills SET status = 'offered', updated_at = datetime('now') WHERE id IN (${ids.map(() => '?').join(',')})`).bind(...ids).run();
    await db
        .prepare(`UPDATE scan_pay_orders SET offered_json = ?, bill_ids_json = ?, status = 'bill_sent', error = NULL, updated_at = datetime('now') WHERE open_order_request_id = ?`)
        .bind(JSON.stringify(procedures), JSON.stringify(ids), order.open_order_request_id)
        .run();
    await hiecm(env, '/scan-gateway/v3/patient/on-share/open-order', {
        intent: 'OPEN_PAYMENT_ORDER',
        abhaAddress: order.abha_address,
        patientUid: order.abha_number || order.abha_address,
        procedures,
        response: { requestId: order.open_order_request_id },
    }, { hipId: order.hip_id });
}

const acknowledgement = (o) => ({
    status: o.payment_status || 'PENDING',
    abhaAddress: o.abha_address,
    transactionId: o.transaction_id || o.order_number,
    orderNumber: o.order_number,
    openOrderRequestId: o.open_order_request_id,
    paymentDate: o.payment_date || o.updated_at,
    paymentReceiptLink: o.receiptUrl,
});

/** Moves an order's payment to `status` and tells ABDM (scan-pay/notify). */
export async function confirmPayment(env, db, order, { status, method, transactionId, origin }) {
    status = String(status || '').toUpperCase();
    const from = order.payment_status || 'PENDING';
    if (!(NEXT_STATUS[from] || []).includes(status)) throw Object.assign(new Error(`A ${from.toLowerCase()} payment cannot become ${status.toLowerCase()}.`), { status: 409 });
    const paymentDate = nowIso();
    await db
        .prepare(
            `UPDATE scan_pay_orders SET payment_status = ?, payment_method = COALESCE(?, payment_method), transaction_id = COALESCE(?, transaction_id, order_number),
               payment_date = ?, notify_acknowledged = 0, status = CASE WHEN ? IN ('SUCCESS','FAIL','CANCELED','REFUND_SUCCESS') THEN 'closed' ELSE status END, updated_at = datetime('now')
             WHERE open_order_request_id = ?`,
        )
        .bind(status, method || null, transactionId || null, paymentDate, status, order.open_order_request_id)
        .run();
    if (status === 'SUCCESS') {
        const ids = JSON.parse(order.bill_ids_json || '[]');
        if (ids.length) await db.prepare(`UPDATE scan_pay_bills SET status = 'paid', updated_at = datetime('now') WHERE id IN (${ids.map(() => '?').join(',')})`).bind(...ids).run();
    }
    const updated = await db.prepare('SELECT * FROM scan_pay_orders WHERE open_order_request_id = ?').bind(order.open_order_request_id).first();
    await hiecm(env, '/scan-gateway/v3/patient/scan-pay/notify', { acknowledgement: acknowledgement({ ...updated, receiptUrl: `${origin}/pay/${updated.payment_token}/receipt` }) }, { hipId: order.hip_id });
    return updated;
}

// ── ABDM -> gateway ─────────────────────────────────────────────────────────────────────────
export const scanPayCallbacks = new Hono();
const signed = abdmCallbackAuth();
const both = (path, handler) => {
    scanPayCallbacks.post(path, signed, handler);
    scanPayCallbacks.post(`/api${path}`, signed, handler);
};

both('/v3/patient/share/open-order', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const requestId = requestIdOf(c);
    const hipId = String(body?.metadata?.hipId || c.req.header('X-HIP-ID') || '').trim();
    return answerLater(c, 'scan-pay open-order', async () => {
        const db = c.env.DB;
        const fail = (message) => hiecm(c.env, '/scan-gateway/v3/patient/on-share/open-order', { error: { code: 'ABDM-2500', message }, response: { requestId } }, { hipId: hipId || undefined });
        if (body.intent && body.intent !== 'OPEN_PAYMENT_ORDER') return fail('The Intent Type provided is invalid.');
        const facility = await facilityOwner(db, hipId);
        if (!facility || !facility.scan_pay_enabled) return fail('The HIP ID is invalid.');
        const p = body?.profile?.patient || {};
        const abhaAddress = abhaAddressOf(p.abhaAddress);
        if (!abhaAddress) return fail('The ABHA Address provided is invalid.');
        await db
            .prepare(
                `INSERT OR IGNORE INTO scan_pay_orders (open_order_request_id, clinic_id, hip_id, counter_id, abha_address, abha_number, patient_name, profile_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .bind(requestId, facility.clinic_id, hipId, String(body?.metadata?.counterId || ''), abhaAddress, abhaNumberDigits(p.abhaNumber), p.name || null, JSON.stringify(p))
            .run();
        const order = await db.prepare('SELECT * FROM scan_pay_orders WHERE open_order_request_id = ?').bind(requestId).first();
        // Bills already published at Checkout answer at once; otherwise the order waits in the staff queue.
        await offerBills(c.env, db, order);
    });
});

both('/v3/patient/selection', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const requestId = requestIdOf(c);
    const origin = publicOrigin(c, getAbdmConfig(c.env));
    return answerLater(c, 'scan-pay selection', async () => {
        const db = c.env.DB;
        const order = await db.prepare('SELECT * FROM scan_pay_orders WHERE open_order_request_id = ?').bind(body.openOrderRequestId || '').first();
        const reply = (payload) => hiecm(c.env, '/scan-gateway/v3/patient/on-selection', { ...payload, response: { requestId } }, { hipId: order?.hip_id });
        if (!order || !order.offered_json) return reply({ error: { code: 'ABDM-2500', message: 'The Open Order Request ID is invalid.' } });
        if (abhaAddressOf(body.abhaAddress) !== order.abha_address) return reply({ error: { code: 'ABDM-2502', message: 'The ABHA address does not match the Open Order Request ID.' } });
        if (order.payment_status && order.payment_status !== 'PENDING') return reply({ error: { code: 'ABDM-2406', message: 'This order is already settled.' } });
        let selected;
        try {
            selected = selectedFrom(JSON.parse(order.offered_json), body.procedures);
        } catch (err) {
            return reply({ error: { code: 'ABDM-2500', message: err.message } });
        }
        const facility = await facilityOwner(db, order.hip_id);
        const orderNumber = order.order_number || newOrderNumber();
        const token = order.payment_token || newToken();
        const amount = totalOf(selected);
        await db
            .prepare(
                `UPDATE scan_pay_orders SET selected_json = ?, order_number = ?, payment_token = ?, amount = ?, status = 'payment_requested', payment_status = 'PENDING', updated_at = datetime('now')
                 WHERE open_order_request_id = ?`,
            )
            .bind(JSON.stringify(selected), orderNumber, token, amount, order.open_order_request_id)
            .run();
        await reply({
            intent: 'PAYMENT_ORDER',
            openOrderRequestId: order.open_order_request_id,
            abhaAddress: order.abha_address,
            procedures: selected,
            paymentBundle: {
                paymentMode: 'GATEWAY',
                paymentUrl: `${origin}/pay/${token}`,
                orderNumber,
                amount,
                merchantId: facility?.upi_vpa || order.hip_id,
                description: `${facility?.hip_name || facility?.facility_name || 'Clinic'} — ${selected.flatMap((p) => p.services).length} item(s)`,
            },
        });
    });
});

both('/v3/patient/scan-pay/on-notify', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const ack = body.acknowledgement || {};
    if (body.error) console.warn('[scan-pay] on-notify error:', JSON.stringify(body.error));
    else if (ack.openOrderRequestId) await c.env.DB.prepare(`UPDATE scan_pay_orders SET notify_acknowledged = 1 WHERE open_order_request_id = ?`).bind(ack.openOrderRequestId).run();
    return c.json({}, 200);
});

both('/v3/patient/scan-pay/order-status', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const requestId = requestIdOf(c);
    const origin = publicOrigin(c, getAbdmConfig(c.env));
    return answerLater(c, 'scan-pay order-status', async () => {
        const q = body.queryStatus || {};
        const order = await c.env.DB.prepare('SELECT * FROM scan_pay_orders WHERE open_order_request_id = ?').bind(q.openOrderRequestId || '').first();
        const reply = (payload) => hiecm(c.env, '/scan-gateway/v3/patient/scan-pay/on-order-status', { ...payload, response: { requestId } }, { hipId: order?.hip_id });
        if (!order) return reply({ error: { code: 'ABDM-2500', message: 'The Open Order Request ID is invalid.' } });
        if (q.orderNumber && q.orderNumber !== order.order_number) return reply({ error: { code: 'ABDM-2502', message: 'The Order Number does not match the Open Order Request ID.' } });
        await reply({ acknowledgement: acknowledgement({ ...order, receiptUrl: order.payment_token ? `${origin}/pay/${order.payment_token}/receipt` : undefined }) });
    });
});

// ── The patient's pay page (public; the token is the secret) ────────────────────────────────
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
const page = (title, inner) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>body{font-family:system-ui,sans-serif;margin:0;background:#f4f6f8;color:#111}main{max-width:28rem;margin:0 auto;padding:1.25rem}h1{font-size:1.2rem}table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px}td{padding:.55rem .7rem;border-bottom:1px solid #eee;font-size:.92rem}td.r{text-align:right;white-space:nowrap}.total td{font-weight:700}.btn{display:block;text-align:center;background:#0f766e;color:#fff;padding:.85rem;border-radius:8px;text-decoration:none;font-weight:600;margin:1rem 0}.muted{color:#555;font-size:.85rem}.ok{background:#dcfce7;color:#166534;padding:.75rem;border-radius:8px}.warn{background:#fef3c7;color:#92400e;padding:.75rem;border-radius:8px}</style></head><body><main>${inner}</main></body></html>`;

export const payRoutes = new Hono();

async function orderByToken(c) {
    const token = c.req.param('token');
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(token)) return null;
    return c.env.DB.prepare('SELECT * FROM scan_pay_orders WHERE payment_token = ?').bind(token).first();
}

const rowsOf = (o) => JSON.parse(o.selected_json || '[]').flatMap((p) => p.services.map((s) => `<tr><td>${esc(s.name)}<div class="muted">${esc(p.category)}</div></td><td class="r">₹ ${s.amount.toFixed(2)}</td></tr>`)).join('');

payRoutes.get('/:token', async (c) => {
    const o = await orderByToken(c);
    if (!o) return c.html(page('Not found', '<h1>This payment link is not valid.</h1>'), 404);
    const f = await facilityOwner(c.env.DB, o.hip_id);
    const name = f?.payee_name || f?.hip_name || f?.facility_name || 'the clinic';
    const head = `<h1>${esc(name)}</h1><p class="muted">Order ${esc(o.order_number)} · ${esc(o.patient_name || o.abha_address)}</p><table>${rowsOf(o)}<tr class="total"><td>Total</td><td class="r">₹ ${Number(o.amount).toFixed(2)}</td></tr></table>`;
    if (o.payment_status === 'SUCCESS') return c.html(page('Paid', `${head}<p class="ok">Paid. <a href="/pay/${esc(c.req.param('token'))}/receipt">Receipt</a></p>`));
    if (o.payment_status && o.payment_status !== 'PENDING') return c.html(page('Payment', `${head}<p class="warn">This order is ${esc(o.payment_status.toLowerCase().replace('_', ' '))}.</p>`));
    const upi = f?.upi_vpa
        ? `upi://pay?${new URLSearchParams({ pa: f.upi_vpa, pn: name, am: Number(o.amount).toFixed(2), cu: 'INR', tn: `Order ${o.order_number}`, tr: o.order_number })}`
        : null;
    return c.html(page('Pay', `${head}${upi
        ? `<a class="btn" href="${esc(upi)}">Pay ₹ ${Number(o.amount).toFixed(2)} with a UPI app</a><p class="muted">Paying to ${esc(f.upi_vpa)}. Show the payment confirmation at the counter; the clinic marks it received and your ABHA app is updated.</p>`
        : '<p class="warn">Please pay at the counter. The clinic will mark it received and your ABHA app will be updated.</p>'}`));
});

payRoutes.get('/:token/receipt', async (c) => {
    const o = await orderByToken(c);
    if (!o || o.payment_status !== 'SUCCESS') return c.html(page('Receipt', '<h1>No receipt for this link.</h1>'), 404);
    const f = await facilityOwner(c.env.DB, o.hip_id);
    return c.html(page(`Receipt ${o.order_number}`, `<h1>Receipt</h1><p><strong>${esc(f?.payee_name || f?.facility_name || '')}</strong><br><span class="muted">HFR ${esc(o.hip_id)}</span></p>
<p class="muted">Order ${esc(o.order_number)} · Transaction ${esc(o.transaction_id || o.order_number)}<br>Paid ${esc(new Date(o.payment_date).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }))}${o.payment_method ? ` · ${esc(o.payment_method)}` : ''}<br>${esc(o.patient_name || '')} (${esc(o.abha_address)})</p>
<table>${rowsOf(o)}<tr class="total"><td>Total paid</td><td class="r">₹ ${Number(o.amount).toFixed(2)}</td></tr></table>`));
});

// ── Staff (behind the session gate of /hie/*) ───────────────────────────────────────────────
export const scanPayStaffRoutes = new Hono();
scanPayStaffRoutes.onError((err, c) => (err.status === 409 ? c.json({ success: false, error: err.message }, 409) : staffAbdmErrorHandler('scan-pay', AbdmApiError)(err, c)));

const orderView = (o, origin) => ({
    id: o.open_order_request_id, facilityId: o.hip_id, counterId: o.counter_id, abhaAddress: o.abha_address, name: o.patient_name, status: o.status,
    offered: JSON.parse(o.offered_json || 'null'), selected: JSON.parse(o.selected_json || 'null'), orderNumber: o.order_number, amount: o.amount,
    paymentStatus: o.payment_status, paymentMethod: o.payment_method, paymentDate: o.payment_date, notifyAcknowledged: !!o.notify_acknowledged, error: o.error,
    payUrl: o.payment_token ? `${origin}/pay/${o.payment_token}` : null, createdAt: o.created_at, updatedAt: o.updated_at,
});

// Publishes a bill (from Checkout) for the patient to pay from their ABHA app.
scanPayStaffRoutes.post('/bills', async (c) => {
    const { clinicId, accountId } = c.get('user');
    const body = await c.req.json().catch(() => ({}));
    const facility = await facilityOwner(c.env.DB, String(body.facilityId || '').toUpperCase());
    if (!facility || facility.clinic_id !== clinicId) return c.json({ success: false, error: 'Unknown facility.' }, 400);
    if (!facility.scan_pay_enabled) return c.json({ success: false, error: 'Turn on Scan & Pay for this facility first.' }, 400);
    const abhaAddress = abhaAddressOf(body.abhaAddress);
    if (!abhaAddress) return c.json({ success: false, error: 'The patient’s ABHA address is needed to send them the bill.' }, 400);
    let procedures;
    try { procedures = normaliseProcedures(body.procedures); } catch (err) { return c.json({ success: false, error: err.message }, 400); }
    const id = crypto.randomUUID();
    const encounter = body.encounterReference ? String(body.encounterReference).slice(0, 100) : null;
    // One open bill per visit: publishing again replaces it.
    if (encounter) await c.env.DB.prepare(`UPDATE scan_pay_bills SET status = 'cancelled', updated_at = datetime('now') WHERE clinic_id = ? AND encounter_reference = ? AND status = 'open'`).bind(clinicId, encounter).run();
    await c.env.DB
        .prepare(`INSERT INTO scan_pay_bills (id, clinic_id, hip_id, abha_address, abha_number, patient_name, encounter_reference, procedures_json, amount, created_by_account_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(id, clinicId, facility.facility_id, abhaAddress, abhaNumberDigits(body.abhaNumber), body.patientName ? String(body.patientName).slice(0, 120) : null, encounter, JSON.stringify(procedures), totalOf(procedures), accountId ?? null)
        .run();
    // The patient may already have scanned: answer their waiting order now.
    const waiting = await c.env.DB.prepare(`SELECT * FROM scan_pay_orders WHERE hip_id = ? AND abha_address = ? AND status = 'awaiting_bill' ORDER BY created_at DESC`).bind(facility.facility_id, abhaAddress).first();
    if (waiting) await offerBills(c.env, c.env.DB, waiting);
    return c.json({ success: true, id, amount: totalOf(procedures), offeredToWaitingOrder: !!waiting }, 201);
});

scanPayStaffRoutes.get('/bills', async (c) => {
    const { clinicId } = c.get('user');
    const enc = c.req.query('encounterReference');
    const { results } = enc
        ? await c.env.DB.prepare('SELECT * FROM scan_pay_bills WHERE clinic_id = ? AND encounter_reference = ? ORDER BY created_at DESC').bind(clinicId, enc).all()
        : await c.env.DB.prepare(`SELECT * FROM scan_pay_bills WHERE clinic_id = ? AND status IN ('open','offered') ORDER BY created_at DESC LIMIT 100`).bind(clinicId).all();
    return c.json({ success: true, bills: results.map((b) => ({ id: b.id, facilityId: b.hip_id, abhaAddress: b.abha_address, name: b.patient_name, encounterReference: b.encounter_reference, amount: b.amount, status: b.status, procedures: JSON.parse(b.procedures_json), createdAt: b.created_at })) });
});

scanPayStaffRoutes.get('/orders', async (c) => {
    const { clinicId } = c.get('user');
    const db = c.env.DB;
    await db.prepare(`UPDATE scan_pay_orders SET profile_json = NULL WHERE profile_json IS NOT NULL AND created_at < datetime('now', '-1 day')`).run();
    const { results } = await db.prepare(`SELECT * FROM scan_pay_orders WHERE clinic_id = ? AND created_at > datetime('now', '-7 day') ORDER BY created_at DESC LIMIT 200`).bind(clinicId).all();
    const origin = publicOrigin(c, getAbdmConfig(c.env));
    return c.json({ success: true, orders: results.map((o) => orderView(o, origin)) });
});

// Staff answer an order that arrived before any bill was published: the items, typed at the counter.
scanPayStaffRoutes.post('/orders/:id/bill', async (c) => {
    const { clinicId, accountId } = c.get('user');
    const db = c.env.DB;
    const order = await db.prepare('SELECT * FROM scan_pay_orders WHERE open_order_request_id = ? AND clinic_id = ?').bind(c.req.param('id'), clinicId).first();
    if (!order) return c.json({ success: false, error: 'No such order.' }, 404);
    if (order.status !== 'awaiting_bill') return c.json({ success: false, error: 'This order already has a bill.' }, 409);
    let procedures;
    try { procedures = normaliseProcedures((await c.req.json().catch(() => ({}))).procedures); } catch (err) { return c.json({ success: false, error: err.message }, 400); }
    const id = crypto.randomUUID();
    await db
        .prepare(`INSERT INTO scan_pay_bills (id, clinic_id, hip_id, abha_address, abha_number, patient_name, procedures_json, amount, created_by_account_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(id, clinicId, order.hip_id, order.abha_address, order.abha_number, order.patient_name, JSON.stringify(procedures), totalOf(procedures), accountId ?? null)
        .run();
    await sendOffer(c.env, db, order, [await db.prepare('SELECT * FROM scan_pay_bills WHERE id = ?').bind(id).first()]);
    return c.json({ success: true, order: orderView(await db.prepare('SELECT * FROM scan_pay_orders WHERE open_order_request_id = ?').bind(order.open_order_request_id).first(), publicOrigin(c, getAbdmConfig(c.env))) });
});

scanPayStaffRoutes.post('/orders/:id/payment', async (c) => {
    const { clinicId } = c.get('user');
    const db = c.env.DB;
    const order = await db.prepare('SELECT * FROM scan_pay_orders WHERE open_order_request_id = ? AND clinic_id = ?').bind(c.req.param('id'), clinicId).first();
    if (!order) return c.json({ success: false, error: 'No such order.' }, 404);
    if (!order.order_number) return c.json({ success: false, error: 'The patient has not chosen what to pay for yet.' }, 409);
    const { status, method, transactionId } = await c.req.json().catch(() => ({}));
    if (!PAYMENT_STATUSES.includes(String(status || '').toUpperCase())) return c.json({ success: false, error: `status must be one of ${PAYMENT_STATUSES.join(', ')}` }, 400);
    const origin = publicOrigin(c, getAbdmConfig(c.env));
    try {
        const updated = await confirmPayment(c.env, db, order, { status, method, transactionId: transactionId ? String(transactionId).slice(0, 64) : null, origin });
        return c.json({ success: true, order: orderView(updated, origin) });
    } catch (err) {
        if (err instanceof AbdmApiError) {
            // Recorded here even though ABDM refused the notify: say so; the patient's app may lag.
            const now = await db.prepare('SELECT * FROM scan_pay_orders WHERE open_order_request_id = ?').bind(order.open_order_request_id).first();
            await db.prepare('UPDATE scan_pay_orders SET error = ? WHERE open_order_request_id = ?').bind(abdmErrorText(err), order.open_order_request_id).run();
            return c.json({ success: true, order: orderView(now, origin), warning: `Recorded, but ABDM did not take the update: ${abdmErrorText(err)}` });
        }
        throw err;
    }
});
