// ClinuxFlow's ABDM Integration Gateway. This Worker is the ONLY thing in the ClinuxFlow stack
// that holds ABDM credentials or talks to ABDM directly — clinuxflow-api and clinuxflow-web call
// this service's own API instead. See docs/clinuxflow-abdm-integration-approach.md for the
// overall design rationale.
//
// Durable Objects (SessionTokenManager, RegistrationTransaction) and the MASTER_DATA_CACHE KV
// namespace are declared in wrangler.toml and exported below, per Workers' requirement that DO
// classes be exported from the entrypoint module.

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { hprRoutes } from './routes/hpr.js';
import { hfrRoutes } from './routes/hfr.js';
import { abhaRoutes } from './routes/abha.js';

export { SessionTokenManager } from './durable-objects/SessionTokenManager.js';
export { RegistrationTransaction } from './durable-objects/RegistrationTransaction.js';

const app = new Hono();

// TODO: tighten before production — restrict to clinuxflow-web's actual origin(s) rather than
// wildcarding, since this Worker sits in front of Aadhaar-adjacent PII flows.
app.use('/*', cors());

app.get('/health', (c) => c.json({ status: 'ok', service: 'clinuxflow-abdm-gateway' }));

app.route('/hpr', hprRoutes);
app.route('/hfr', hfrRoutes);
app.route('/abha', abhaRoutes);

app.notFound((c) => c.json({ success: false, error: 'Not found' }, 404));

app.onError((err, c) => {
    console.error('[clinuxflow-abdm-gateway] unhandled error:', err);
    return c.json({ success: false, error: 'Internal error' }, 500);
});

export default app;
