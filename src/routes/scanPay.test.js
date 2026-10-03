import { afterEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import { scanPayCallbacks, scanPayStaffRoutes, payRoutes, normaliseProcedures, selectedFrom, totalOf } from './scanPay.js';
import { hipCallbackRoutes, scanShareRoutes } from './scanShare.js';
import { asStaff, fakeAbdm } from '../testing/abdmFake.js';

afterEach(() => vi.unstubAllGlobals());

const HIP = 'IN3310002300';
const app = new Hono().route('/', scanPayCallbacks).route('/pay', payRoutes).route('/api/v3/hip', hipCallbackRoutes);
const openOrder = (abhaAddress = 'asha@sbx') => ({
    intent: 'OPEN_PAYMENT_ORDER',
    metadata: { hipId: HIP, counterId: '1' },
    profile: { patient: { abhaNumber: 91123456789012, abhaAddress, name: 'Asha Rao', gender: 'F', yearOfBirth: '1994', phoneNumber: '98765*****' } },
});
const bill = { facilityId: HIP, abhaAddress: 'asha@sbx', patientName: 'Asha Rao', encounterReference: 'visit-1', procedures: [
    { category: 'OPD consultation', services: [{ serviceId: 'consult', name: 'Consultation', amount: 500 }] },
    { category: 'pharmacy', services: [{ serviceId: 'rx', name: 'Medicines', amount: 129.5 }] },
] };

describe('procedures', () => {
    it('validates items and totals them, and only lets offered items be chosen at the offered price', () => {
        const p = normaliseProcedures(bill.procedures);
        expect(p[1].category).toBe('Pharmacy');
        expect(totalOf(p)).toBe(629.5);
        expect(() => normaliseProcedures([{ category: 'x', services: [{ name: 'Free', amount: 0 }] }])).toThrow(/above zero/);
        const chosen = selectedFrom(p, [{ category: 'Pharmacy', services: [{ serviceId: 'rx', amount: 1 }] }, { category: 'X', services: [{ serviceId: 'not-offered', amount: 1 }] }]);
        expect(chosen).toEqual([{ category: 'Pharmacy', services: [{ serviceId: 'rx', name: 'Medicines', description: 'Medicines', amount: 129.5 }] }]);
        expect(() => selectedFrom(p, [])).toThrow();
    });
});

describe('Scan & Pay', () => {
    it('offers the published bill, takes the selection, serves the pay page, and reports the payment', async () => {
        const abdm = fakeAbdm();
        abdm.own(HIP, 'clinic-1', { pay: true, upi: 'ashaclinic@okhdfc' });
        const staff = asStaff(scanPayStaffRoutes, abdm.env);
        expect((await staff('/bills', { method: 'POST', body: bill })).status).toBe(201);

        await abdm.callback(app, '/v3/patient/share/open-order', openOrder(), { 'REQUEST-ID': 'oo-1', 'X-HIP-ID': HIP });
        const offer = abdm.last('/scan-gateway/v3/patient/on-share/open-order');
        expect(offer.headers['X-HIP-ID']).toBe(HIP);
        expect(offer.body).toMatchObject({ intent: 'OPEN_PAYMENT_ORDER', abhaAddress: 'asha@sbx', response: { requestId: 'oo-1' } });
        expect(offer.body.procedures.map((p) => p.category)).toEqual(['OPD consultation', 'Pharmacy']);

        await abdm.callback(app, '/v3/patient/selection', { intent: 'PAYMENT_ORDER', openOrderRequestId: 'oo-1', abhaAddress: 'asha@sbx', procedures: offer.body.procedures }, { 'REQUEST-ID': 'sel-1' });
        const sel = abdm.last('/scan-gateway/v3/patient/on-selection').body;
        expect(sel).toMatchObject({ intent: 'PAYMENT_ORDER', openOrderRequestId: 'oo-1', response: { requestId: 'sel-1' } });
        expect(sel.paymentBundle).toMatchObject({ paymentMode: 'GATEWAY', amount: 629.5, merchantId: 'ashaclinic@okhdfc' });
        expect(sel.paymentBundle.paymentUrl).toMatch(/^https:\/\/gw\.example\/pay\//);

        const pay = await app.request(new URL(sel.paymentBundle.paymentUrl).pathname, {}, abdm.env);
        const html = await pay.text();
        expect(html).toContain('upi://pay?pa=ashaclinic%40okhdfc');
        expect(html).toContain('am=629.50');
        expect(html).toContain('Medicines');

        const [order] = (await staff('/orders')).json.orders;
        expect(order).toMatchObject({ status: 'payment_requested', paymentStatus: 'PENDING', amount: 629.5 });
        const paid = await staff(`/orders/${order.id}/payment`, { method: 'POST', body: { status: 'SUCCESS', method: 'UPI', transactionId: 'UPI123' } });
        expect(paid.json.order.paymentStatus).toBe('SUCCESS');
        const notify = abdm.last('/scan-gateway/v3/patient/scan-pay/notify').body.acknowledgement;
        expect(notify).toMatchObject({ status: 'SUCCESS', abhaAddress: 'asha@sbx', transactionId: 'UPI123', orderNumber: sel.paymentBundle.orderNumber, openOrderRequestId: 'oo-1' });
        expect(notify.paymentReceiptLink).toMatch(/\/receipt$/);
        expect(await (await app.request(new URL(notify.paymentReceiptLink).pathname, {}, abdm.env)).text()).toContain('Total paid');

        // ABDM's order-status query gets the same state; a paid order can't go back to failed.
        await abdm.callback(app, '/v3/patient/scan-pay/order-status', { queryStatus: { orderNumber: sel.paymentBundle.orderNumber, abhaAddress: 'asha@sbx', openOrderRequestId: 'oo-1' } }, { 'REQUEST-ID': 'st-1' });
        expect(abdm.last('/scan-gateway/v3/patient/scan-pay/on-order-status').body).toMatchObject({ acknowledgement: { status: 'SUCCESS' }, response: { requestId: 'st-1' } });
        expect((await staff(`/orders/${order.id}/payment`, { method: 'POST', body: { status: 'FAIL' } })).status).toBe(409);
        expect((await staff('/bills?encounterReference=visit-1')).json.bills[0].status).toBe('paid');
    });

    it('holds an order with no bill for staff to answer, and refuses a selection of unoffered items', async () => {
        const abdm = fakeAbdm();
        abdm.own(HIP, 'clinic-1', { pay: true });
        const staff = asStaff(scanPayStaffRoutes, abdm.env);
        await abdm.callback(app, '/api/v3/patient/share/open-order', openOrder(), { 'REQUEST-ID': 'oo-2' });
        expect(abdm.last('/scan-gateway/v3/patient/on-share/open-order')).toBeUndefined();
        expect((await staff('/orders')).json.orders[0].status).toBe('awaiting_bill');
        await staff('/orders/oo-2/bill', { method: 'POST', body: { procedures: [{ category: 'Laboratory and Diagnostics', services: [{ serviceId: 'cbc', name: 'CBC', amount: 300 }] }] } });
        expect(abdm.last('/scan-gateway/v3/patient/on-share/open-order').body.procedures[0].services[0].name).toBe('CBC');

        await abdm.callback(app, '/v3/patient/selection', { openOrderRequestId: 'oo-2', abhaAddress: 'asha@sbx', procedures: [{ services: [{ serviceId: 'free-mri' }] }] });
        expect(abdm.last('/scan-gateway/v3/patient/on-selection').body.error.code).toBe('ABDM-2500');
        await abdm.callback(app, '/v3/patient/selection', { openOrderRequestId: 'oo-2', abhaAddress: 'ravi@sbx', procedures: [{ services: [{ serviceId: 'cbc' }] }] });
        expect(abdm.last('/scan-gateway/v3/patient/on-selection').body.error.code).toBe('ABDM-2502');
    });

    it('refuses a facility without Scan & Pay', async () => {
        const abdm = fakeAbdm();
        abdm.own(HIP);
        await abdm.callback(app, '/v3/patient/share/open-order', openOrder());
        expect(abdm.last('/scan-gateway/v3/patient/on-share/open-order').body.error.message).toBe('The HIP ID is invalid.');
        expect((await asStaff(scanPayStaffRoutes, abdm.env)('/bills', { method: 'POST', body: bill })).status).toBe(400);
    });
});

describe('Running Token Status', () => {
    it('answers with the token staff last called at that counter, and the average service time', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        try {
            const abdm = fakeAbdm();
            abdm.own(HIP);
            const staff = asStaff(scanShareRoutes, abdm.env);
            const share = (abhaAddress, context = '1') => abdm.callback(app, '/api/v3/hip/patient/share', { intent: 'PROFILE_SHARE', metaData: { hipId: HIP, context }, profile: { patient: { abhaAddress, name: abhaAddress } } });
            await share('a@sbx'); await share('b@sbx'); await share('c@sbx');

            await abdm.callback(app, '/api/v3/hip/patient/running-token/status', { hipId: HIP, context: '1' }, { 'REQUEST-ID': 'rt-0' });
            expect(abdm.last('/patient-share/v3/running-token/on-status').body).toMatchObject({ error: { code: 'ABDM-1031' }, response: { requestId: 'rt-0' } });

            expect((await staff('/counters/call-next', { method: 'POST', body: { facilityId: HIP, context: '1' } })).json.runningToken).toBe(1);
            vi.advanceTimersByTime(6 * 60000);
            await staff('/counters/call-next', { method: 'POST', body: { facilityId: HIP, context: '1' } });
            vi.advanceTimersByTime(4 * 60000);
            const third = await staff('/counters/call-next', { method: 'POST', body: { facilityId: HIP, context: '1' } });
            expect(third.json).toMatchObject({ runningToken: 3, averageMinutes: 5 });
            expect((await staff('/counters/call-next', { method: 'POST', body: { facilityId: HIP, context: '1' } })).status).toBe(409);

            await abdm.callback(app, '/api/v3/hip/patient/running-token/status', { hipId: HIP, context: '1' }, { 'REQUEST-ID': 'rt-1' });
            expect(abdm.last('/patient-share/v3/running-token/on-status').body).toEqual({ token: { hipId: HIP, context: '1', runningTokenNumber: '3', averageTokenServiceTimeInMinutes: 5 }, response: { requestId: 'rt-1' } });
            expect((await staff(`/queue?facilityId=${HIP}`)).json.counters['1']).toEqual({ runningToken: 3, averageMinutes: 5 });
        } finally {
            vi.useRealTimers();
        }
    });
});

describe('facility settings', () => {
    it('links the HIU role and turns Scan & Pay on with ABDM, and checks the UPI id', async () => {
        const abdm = fakeAbdm({ respond: (path) => (path.includes('MutipleHRP') ? Response.json({ message: 'ok' }) : undefined) });
        abdm.own(HIP);
        const staff = asStaff(scanShareRoutes, abdm.env);
        expect((await staff(`/facilities/${HIP}`, { method: 'PATCH', body: { upiVpa: 'not a vpa' } })).status).toBe(400);
        const res = await staff(`/facilities/${HIP}`, { method: 'PATCH', body: { hiuEnabled: true, scanPayEnabled: true, upiVpa: 'ashaclinic@okhdfc', payeeName: 'Asha Clinic' } });
        expect(res.json.facility).toMatchObject({ hiuEnabled: true, scanPayEnabled: true, upiVpa: 'ashaclinic@okhdfc' });
        expect(abdm.last('/v1/bridges/MutipleHRPAddUpdateServices').body.HRP).toEqual([{ bridgeId: 'SBX_1', hipName: 'Asha Clinic', type: 'HIU', active: true }]);
        const version = abdm.last('/gateway/v3/scanPay/updateVersion');
        expect(version).toMatchObject({ method: 'PATCH', body: { recordShareEnabled: true, scanPayEnabled: true, scanPayVersion: 'V3', serviceId: [HIP] } });
        expect((await asStaff(scanShareRoutes, abdm.env, 'clinic-2')(`/facilities/${HIP}`, { method: 'PATCH', body: { hiuEnabled: false } })).status).toBe(404);
    });
});
