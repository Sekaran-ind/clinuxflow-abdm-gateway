// HSPA (Health Service Provider Application) routes, mounted at /uhi/hspa.
//
// Network-facing: POST /search /select /init /confirm /status /cancel. Called by the NHA UHI
// gateway or by EUAs; authenticated only by the UHI message signature. Each answers ACK
// immediately and sends the matching on_* callback asynchronously (c.executionCtx.waitUntil, so
// the Worker stays alive until it is delivered).
//
// Operator (ClinuxFlow session required, mounted by src/routes/uhi.js):
//   POST /internal/push-update, /internal/push-message   provider-initiated pushes
//   GET  /internal/orders/:orderId
//   GET  /internal/catalog, PUT /internal/catalog         the catalog served on on_search

import { Hono } from 'hono';
import { ERROR_CODES, ackResponse, buildCallbackContext } from '../protocol.js';
import { signedPost } from '../client.js';
import { recordKeys } from '../records.js';
import { CATALOG_KEY, findItem, loadCatalog, parseCatalog, searchCatalog } from './catalog.js';

/** Runs `promise` after the response is sent (Workers), or just lets it run (tests). */
export function runInBackground(c, promise) {
    const guarded = promise.catch((err) => console.error('[uhi] background task failed:', err));
    try {
        c.executionCtx.waitUntil(guarded);
    } catch {
        // no ExecutionContext (unit tests calling app.request without one); the promise still runs
    }
}

async function sendCallback(deps, requesterContext, callbackAction, message, error) {
    const context = buildCallbackContext(requesterContext, callbackAction);
    // Appended as a path segment under consumer_uri (Beckn convention), not resolved as a
    // relative URL, which would replace consumer_uri's last segment.
    const url = `${requesterContext.consumer_uri.replace(/\/+$/, '')}/${callbackAction}`;
    try {
        await signedPost(url, { context, message, error }, deps.identity, { fetchImpl: deps.fetchImpl });
    } catch (err) {
        console.error(`[uhi hspa] failed to deliver ${callbackAction} to ${url}:`, err);
    }
}

/**
 * @param {(c) => { identity: object, baseUrl: string, store: object, fetchImpl?: typeof fetch } | null} getDeps
 *   returns null when the HSPA role isn't configured.
 */
export function buildHspaPublicRoutes(getDeps) {
    const app = new Hono();

    app.use('*', async (c, next) => {
        const deps = getDeps(c);
        if (!deps) return c.json({ error: 'UHI HSPA is not configured on this gateway' }, 503);
        c.set('hspa', deps);
        return next();
    });

    app.post('/search', (c) => {
        const deps = c.get('hspa');
        const body = c.get('uhiBody');
        runInBackground(
            c,
            (async () => {
                const catalog = searchCatalog(
                    await loadCatalog(deps.store),
                    body.message?.intent?.item?.descriptor?.code,
                    body.message?.intent?.category?.descriptor?.code,
                );
                // The initiating search has no provider_id/provider_uri; stamp ours so the EUA
                // knows who replied and where to send select/init/confirm/status/cancel.
                const requesterContext = { ...body.context, provider_id: deps.identity.subscriberId, provider_uri: deps.baseUrl };
                await sendCallback(deps, requesterContext, 'on_search', { catalog });
            })(),
        );
        return c.json(ackResponse());
    });

    // `select` is unused by the current doctor-search flow per the spec; implemented minimally:
    // echo the item back as a draft order with its quote.
    app.post('/select', (c) => {
        const deps = c.get('hspa');
        const body = c.get('uhiBody');
        runInBackground(
            c,
            (async () => {
                const itemId = body.message?.order?.item?.id;
                const found = itemId ? findItem(await loadCatalog(deps.store), itemId) : undefined;
                if (!found) {
                    await sendCallback(deps, body.context, 'on_select', {}, { code: ERROR_CODES.ITEM_NOT_FOUND, message: `No such item: ${itemId ?? '(none given)'}` });
                    return;
                }
                await sendCallback(deps, body.context, 'on_select', { order: { item: found.item, quote: { price: found.item.price } } });
            })(),
        );
        return c.json(ackResponse());
    });

    app.post('/init', (c) => {
        const deps = c.get('hspa');
        const body = c.get('uhiBody');
        runInBackground(
            c,
            (async () => {
                const itemId = body.message?.order?.item?.id;
                const found = itemId ? findItem(await loadCatalog(deps.store), itemId) : undefined;
                if (!found) {
                    await sendCallback(deps, body.context, 'on_init', {}, { code: ERROR_CODES.ITEM_NOT_FOUND, message: `No such item: ${itemId ?? '(none given)'}` });
                    return;
                }
                const orderId = crypto.randomUUID();
                const now = new Date().toISOString();
                const record = {
                    orderId,
                    transactionId: body.context.transaction_id,
                    state: 'INITIALIZED',
                    requesterContext: body.context,
                    order: {
                        id: orderId,
                        state: 'INITIALIZED',
                        provider: { id: found.provider.id },
                        item: found.item,
                        quote: { price: found.item.price, breakup: [{ title: found.item.descriptor?.name, price: found.item.price }] },
                        created_at: now,
                        updated_at: now,
                    },
                };
                await deps.store.put(recordKeys.hspaOrder(orderId), record);
                await deps.store.put(recordKeys.hspaTransaction(body.context.transaction_id), { orderId });
                await sendCallback(deps, body.context, 'on_init', { order: record.order });
            })(),
        );
        return c.json(ackResponse());
    });

    const orderAction = (action, callbackAction, newState) =>
        app.post(`/${action}`, (c) => {
            const deps = c.get('hspa');
            const body = c.get('uhiBody');
            runInBackground(
                c,
                (async () => {
                    const orderId = body.message?.order?.id;
                    let record = orderId ? await deps.store.get(recordKeys.hspaOrder(orderId)) : null;
                    // An order may only be driven by the transaction that created it.
                    if (record && record.transactionId !== body.context.transaction_id) record = null;
                    if (record && newState) record = await deps.store.apply(recordKeys.hspaOrder(orderId), 'hspa.state', { state: newState });
                    if (!record) {
                        await sendCallback(deps, body.context, callbackAction, {}, { code: ERROR_CODES.ORDER_NOT_FOUND, message: `No such order: ${orderId ?? '(none given)'}` });
                        return;
                    }
                    await sendCallback(deps, body.context, callbackAction, { order: record.order });
                })(),
            );
            return c.json(ackResponse());
        });

    orderAction('confirm', 'on_confirm', 'CONFIRMED');
    orderAction('status', 'on_status', null);
    orderAction('cancel', 'on_cancel', 'CANCELLED');

    return app;
}

export function buildHspaInternalRoutes(getDeps) {
    const app = new Hono();

    app.use('*', async (c, next) => {
        const deps = getDeps(c);
        if (!deps) return c.json({ error: 'UHI HSPA is not configured on this gateway' }, 503);
        c.set('hspa', deps);
        return next();
    });

    // on_update / on_message payload shapes are a known spec gap (see protocol.js); the caller
    // supplies `message` directly, most plausibly { order: {...} } for on_update.
    const push = (path, action) =>
        app.post(path, async (c) => {
            const deps = c.get('hspa');
            const { transactionId, message } = await c.req.json();
            const index = transactionId ? await deps.store.get(recordKeys.hspaTransaction(transactionId)) : null;
            const record = index ? await deps.store.get(recordKeys.hspaOrder(index.orderId)) : null;
            if (!record) return c.json({ error: 'unknown transactionId' }, 404);
            runInBackground(c, sendCallback(deps, record.requesterContext, action, message ?? {}));
            return c.json({ status: 'queued' }, 202);
        });
    push('/push-update', 'on_update');
    push('/push-message', 'on_message');

    app.get('/orders/:orderId', async (c) => {
        const record = await c.get('hspa').store.get(recordKeys.hspaOrder(c.req.param('orderId')));
        return record ? c.json(record) : c.json({ error: 'not found' }, 404);
    });

    app.get('/catalog', async (c) => c.json(await loadCatalog(c.get('hspa').store)));

    app.put('/catalog', async (c) => {
        let catalog;
        try {
            catalog = parseCatalog(await c.req.json());
        } catch (err) {
            return c.json({ error: 'Invalid catalog', details: err.errors ?? err.message }, 400);
        }
        await c.get('hspa').store.put(CATALOG_KEY, catalog);
        return c.json({ success: true, providers: catalog.providers?.length ?? 0 });
    });

    return app;
}
