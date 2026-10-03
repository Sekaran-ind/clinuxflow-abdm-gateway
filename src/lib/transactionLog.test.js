import { describe, expect, it } from 'vitest';
import { Hono } from 'hono';
import { recordAbdmTransactions, failureOf } from './transactionLog.js';

/** A fake D1 recording INSERT bindings. */
function fakeDb() {
    const rows = [];
    return {
        rows,
        prepare: () => ({ bind: (...args) => ({ run: async () => { rows.push(args); return { success: true }; } }) }),
    };
}

/** A tiny app: a fake session middleware, the logger, and two routes. */
function appWith(user) {
    const app = new Hono();
    app.use('/hpr/*', async (c, next) => { if (user) c.set('user', user); await next(); }, recordAbdmTransactions('hpr'));
    app.get('/hpr/master/districts/:stateId', (c) => c.json({ success: true, data: [] }));
    app.post('/hpr/registration/aadhaar-link', (c) =>
        c.json({ success: false, error: 'ABDM request failed', abdmStatus: 422, abdmRequestId: 'req-123', abdmBody: { message: 'Invalid Aadhaar link' } }, 502));
    return app;
}

const columns = ([id, clinicId, accountId, service, operation, httpStatus, ok, abdmStatus, requestId, error, duration]) =>
    ({ id, clinicId, accountId, service, operation, httpStatus, ok, abdmStatus, requestId, error, duration });

describe('ABDM transaction log', () => {
    it('records the route pattern, never the concrete path', async () => {
        const DB = fakeDb();
        const res = await appWith({ accountId: 'acc-1', clinicId: 'clinic-1' }).request('/hpr/master/districts/27?x=secret', {}, { DB });
        expect(res.status).toBe(200);
        const row = columns(DB.rows[0]);
        expect(row).toMatchObject({ clinicId: 'clinic-1', accountId: 'acc-1', service: 'hpr', operation: 'GET /hpr/master/districts/:stateId', httpStatus: 200, ok: 1, abdmStatus: null, error: null });
        // The row's own random id and duration can contain "27" by chance (that made this flaky).
        const { id, duration, ...logged } = row;
        expect(JSON.stringify(logged)).not.toContain('27');
        expect(JSON.stringify(DB.rows)).not.toContain('secret');
    });

    it('keeps ABDM’s status, REQUEST-ID and a short message on failure — not the body', async () => {
        const DB = fakeDb();
        await appWith({ accountId: 'acc-1', clinicId: 'clinic-1' }).request('/hpr/registration/aadhaar-link', { method: 'POST' }, { DB });
        expect(columns(DB.rows[0])).toMatchObject({ operation: 'POST /hpr/registration/aadhaar-link', httpStatus: 502, ok: 0, abdmStatus: 422, requestId: 'req-123', error: 'ABDM request failed: Invalid Aadhaar link' });
    });

    it('logs nothing without a session or without a database', async () => {
        const DB = fakeDb();
        await appWith(null).request('/hpr/master/districts/27', {}, { DB });
        expect(DB.rows).toEqual([]);
        const res = await appWith({ accountId: 'a', clinicId: 'c' }).request('/hpr/master/districts/27', {}, {});
        expect(res.status).toBe(200);
    });

    it('a failing insert never fails the request', async () => {
        const DB = { prepare: () => { throw new Error('D1 down'); } };
        const res = await appWith({ accountId: 'a', clinicId: 'c' }).request('/hpr/master/districts/27', {}, { DB });
        expect(res.status).toBe(200);
    });

    it('reads nothing from a successful response', async () => {
        expect(await failureOf(new Response('{}', { status: 200 }))).toEqual({});
    });
});
