// EUA (End User Application) routes, mounted at /uhi/eua.
//
// Network-facing callbacks: POST /on_search /on_select /on_init /on_confirm /on_status
// /on_cancel /on_update /on_message. Sent by HSPAs, or by the NHA gateway on on_search's first
// hop (X-Gateway-Authorization); authenticated only by the UHI message signature.
//
// Operator (ClinuxFlow session required, mounted by src/routes/uhi.js): a signed-in ClinuxFlow
// user starts a search and drives the booking on a patient's behalf:
//   POST /internal/search                               starts a transaction
//   POST /internal/select|init|confirm|status|cancel    { transactionId, order }
//   GET  /internal/transactions/:id
// Transactions belong to the clinic that started them; other clinics get 404.

import { Hono } from 'hono';
import { ackResponse, buildContext } from '../protocol.js';
import { signedPost } from '../client.js';
import { recordKeys } from '../records.js';
import { runInBackground } from '../hspa/routes.js';

const ORDER_CALLBACKS = ['on_select', 'on_init', 'on_confirm', 'on_status', 'on_cancel'];
const PUSHES = ['on_update', 'on_message'];
const ORDER_ACTIONS = ['select', 'init', 'confirm', 'status', 'cancel'];

function requireEua(getDeps) {
    return async (c, next) => {
        const deps = getDeps(c);
        if (!deps) return c.json({ error: 'UHI EUA is not configured on this gateway' }, 503);
        c.set('eua', deps);
        return next();
    };
}

export function buildEuaPublicRoutes(getDeps) {
    const app = new Hono();
    app.use('*', requireEua(getDeps));

    const record = (c, op, args) => {
        const body = c.get('uhiBody');
        const transactionId = body?.context?.transaction_id;
        if (!transactionId) return;
        runInBackground(
            c,
            c.get('eua').store.apply(recordKeys.euaTransaction(transactionId), op, { transactionId, ...args }).then((next) => {
                if (!next) console.warn(`[uhi eua] dropped ${op} for unknown transaction ${transactionId}`);
            }),
        );
    };

    app.post('/on_search', (c) => {
        const body = c.get('uhiBody');
        if (body.message?.catalog) {
            record(c, 'eua.catalog', { catalog: body.message.catalog, providerId: body.context.provider_id, providerUri: body.context.provider_uri });
        }
        if (body.error) record(c, 'eua.error', { error: body.error });
        return c.json(ackResponse());
    });

    for (const action of ORDER_CALLBACKS) {
        app.post(`/${action}`, (c) => {
            const body = c.get('uhiBody');
            if (body.message?.order) {
                record(c, 'eua.order', { order: body.message.order, providerId: body.context.provider_id, providerUri: body.context.provider_uri });
            }
            if (body.error) record(c, 'eua.error', { error: body.error });
            return c.json(ackResponse());
        });
    }

    for (const action of PUSHES) {
        app.post(`/${action}`, (c) => {
            record(c, 'eua.push', { action, message: c.get('uhiBody').message ?? {} });
            return c.json(ackResponse());
        });
    }

    return app;
}

function hspaActionUrl(providerUri, action) {
    return `${providerUri.replace(/\/+$/, '')}/${action}`;
}

export function buildEuaInternalRoutes(getDeps) {
    const app = new Hono();
    app.use('*', requireEua(getDeps));

    /** The caller's own transaction, or null (another clinic's transaction looks like a miss). */
    async function ownTransaction(c, transactionId) {
        if (!transactionId) return null;
        const record = await c.get('eua').store.get(recordKeys.euaTransaction(transactionId));
        return record && record.clinicId === c.get('user').clinicId ? record : null;
    }

    app.post('/search', async (c) => {
        const deps = c.get('eua');
        const user = c.get('user');
        const input = await c.req.json().catch(() => ({}));
        const transactionId = crypto.randomUUID();
        await deps.store.apply(recordKeys.euaTransaction(transactionId), 'eua.begin', {
            transactionId,
            clinicId: user.clinicId,
            accountId: user.accountId,
        });

        const context = buildContext({
            domain: deps.config.domain,
            action: 'search',
            city: deps.config.city,
            country: deps.config.country,
            consumerId: deps.identity.subscriberId,
            consumerUri: deps.baseUrl,
            transactionId,
        });
        // local: this gateway's own HSPA. sandbox: the NHA gateway's broadcast entry point
        // (/api/v1/uhi/search, confirmed on the live sandbox; the older /api/v1/search 404s).
        const targetUrl =
            deps.config.mode === 'local' ? hspaActionUrl(deps.localHspaUrl, 'search') : `${deps.config.gatewayBaseUrl}/api/v1/uhi/search`;

        try {
            await signedPost(targetUrl, { context, message: { intent: input?.intent ?? {} } }, deps.identity, { fetchImpl: deps.fetchImpl });
            return c.json({ transactionId }, 202);
        } catch (err) {
            return c.json({ transactionId, error: String(err) }, 502);
        }
    });

    for (const action of ORDER_ACTIONS) {
        app.post(`/${action}`, async (c) => {
            const deps = c.get('eua');
            const { transactionId, order } = await c.req.json().catch(() => ({}));
            const record = await ownTransaction(c, transactionId);
            if (!record?.providerUri) {
                return c.json({ error: 'unknown transaction, or no provider discovered yet via search' }, 409);
            }
            const context = buildContext({
                domain: deps.config.domain,
                action,
                city: deps.config.city,
                country: deps.config.country,
                consumerId: deps.identity.subscriberId,
                consumerUri: deps.baseUrl,
                providerId: record.providerId,
                providerUri: record.providerUri,
                transactionId,
            });
            try {
                await signedPost(hspaActionUrl(record.providerUri, action), { context, message: { order } }, deps.identity, { fetchImpl: deps.fetchImpl });
                return c.json({ transactionId }, 202);
            } catch (err) {
                return c.json({ transactionId, error: String(err) }, 502);
            }
        });
    }

    app.get('/transactions/:id', async (c) => {
        const record = await ownTransaction(c, c.req.param('id'));
        return record ? c.json(record) : c.json({ error: 'not found' }, 404);
    });

    return app;
}
