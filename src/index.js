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
import { serviceKeyAuth } from './lib/serviceAuth.js';

export { SessionTokenManager } from './durable-objects/SessionTokenManager.js';
export { RegistrationTransaction } from './durable-objects/RegistrationTransaction.js';

const app = new Hono();

// Locked down to clinux-frontend's real origins — this Worker sits in front of Aadhaar-adjacent
// PII flows (OTP generation against a caller-supplied Aadhaar/mobile number), so a wildcard
// origin would let any webpage's JS relay requests through it using our ABDM credentials.
const ALLOWED_ORIGINS = [
    'https://clinux.yaxb.ai',
    'http://localhost:5173',
    // Capacitor's two platforms default to two DIFFERENT origins when no `server.androidScheme`
    // override is set in capacitor.config.json (confirmed against the actual config -- there is
    // none): iOS uses capacitor://localhost, Android uses https://localhost. Both are needed --
    // this isn't one scheme with two names, it's a real platform difference. http://localhost
    // (no port) is kept too for whatever local testing originally added it.
    'capacitor://localhost',
    'https://localhost',
    'http://localhost',
];
app.use('/*', cors({ origin: ALLOWED_ORIGINS }));

app.get('/health', (c) => c.json({ status: 'ok', service: 'clinuxflow-abdm-gateway' }));

// See src/lib/serviceAuth.js for what/why — unit tested there.
app.use('/*', serviceKeyAuth({ exemptPaths: ['/health'] }));

app.route('/hpr', hprRoutes);
app.route('/hfr', hfrRoutes);
app.route('/abha', abhaRoutes);

app.notFound((c) => c.json({ success: false, error: 'Not found' }, 404));

app.onError((err, c) => {
    console.error('[clinuxflow-abdm-gateway] unhandled error:', err);
    return c.json({ success: false, error: 'Internal error' }, 500);
});

export default app;
