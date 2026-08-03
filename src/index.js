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

// Locked down to clinux-frontend's real origins — this Worker sits in front of Aadhaar-adjacent
// PII flows (OTP generation against a caller-supplied Aadhaar/mobile number), so a wildcard
// origin would let any webpage's JS relay requests through it using our ABDM credentials.
const ALLOWED_ORIGINS = [
    'https://clinux.yaxb.ai',
    'http://localhost:5173',
    'capacitor://localhost',
    'http://localhost',
];
app.use('/*', cors({ origin: ALLOWED_ORIGINS }));

app.get('/health', (c) => c.json({ status: 'ok', service: 'clinuxflow-abdm-gateway' }));

// Shared-secret gate: clinux-frontend is the only intended caller of everything below. CORS
// alone only stops browser-originated cross-origin requests — it does nothing against a script
// or curl hitting this Worker's URL directly, which is the actual risk here (an open relay in
// front of real ABDM OTP-triggering APIs). Fails closed if SERVICE_KEY isn't configured.
app.use('/*', async (c, next) => {
    if (c.req.path === '/health') return next();
    const key = c.req.header('X-Service-Key');
    if (!c.env.SERVICE_KEY || key !== c.env.SERVICE_KEY) {
        return c.json({ success: false, error: 'Unauthorized' }, 401);
    }
    return next();
});

app.route('/hpr', hprRoutes);
app.route('/hfr', hfrRoutes);
app.route('/abha', abhaRoutes);

app.notFound((c) => c.json({ success: false, error: 'Not found' }, 404));

app.onError((err, c) => {
    console.error('[clinuxflow-abdm-gateway] unhandled error:', err);
    return c.json({ success: false, error: 'Internal error' }, 500);
});

export default app;
