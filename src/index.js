// ClinuxFlow's NHA integration gateway. This Worker is the ONLY thing in the ClinuxFlow stack
// that holds ABDM or UHI credentials or talks to NHA systems directly:
//
//   /hpr, /hfr, /abha   ABDM registries (HPR, HFR, ABHA). Outbound; driven by ClinuxFlow users.
//   /api/v3/…, /v3/…   ABDM HIE-CM callbacks to this gateway: as a HIP (Scan & Share, Running
//                       Token, Scan & Pay, M2 linking and data flow) and as a HIU (M3 consent and
//                       data flow). Inbound; each checked against HIE-CM's signature.
//   /hiu/data-push/:id  HIPs pushing encrypted records for an M3 data request (Fidelius-encrypted
//                       for that request; the id is single-use and unguessable).
//   /pay/:token         the Scan & Pay page a patient's ABHA app opens.
//   /hie/*              staff: care contexts, consents, records, Scan & Pay orders.
//   /uhi/hspa, /uhi/eua UHI network participation (provider and consumer roles), merged in from
//                       the former clinux-uhi-gateway repo. See src/routes/uhi.js.
//
// Authentication, by caller:
//   ClinuxFlow users (ABDM routes, UHI operator routes): X-Service-Key (a bot filter only; its
//     value ships in the frontend bundle) + a verified ClinuxFlow session JWT + per-account rate
//     limits, with a tighter limit on every route that makes ABDM send an OTP.
//   UHI network participants (UHI network-facing routes): the UHI message signature only.
//   Citizens (cubo-diary, /citizen/*): no session. ABHA login with the person's own OTP, and
//     anonymous UHI search; fixed request shapes and per-IP / per-target rate limits.
//
// Durable Objects are declared in wrangler.toml and exported below, per Workers' requirement
// that DO classes be exported from the entrypoint module.

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { hprRoutes } from './routes/hpr.js';
import { hfrRoutes } from './routes/hfr.js';
import { abhaRoutes } from './routes/abha.js';
import { uhiRoutes } from './routes/uhi.js';
import { citizenRoutes } from './routes/citizen.js';
import { hipCallbackRoutes, scanShareRoutes } from './routes/scanShare.js';
import { hipCallbacks, hipStaffRoutes } from './routes/hip.js';
import { dataPushRoutes, hiuCallbacks, hiuStaffRoutes } from './routes/hiu.js';
import { payRoutes, scanPayCallbacks, scanPayStaffRoutes } from './routes/scanPay.js';
import { serviceKeyAuth } from './lib/serviceAuth.js';
import { requireClinuxSession } from './lib/userSession.js';
import { recordAbdmTransactions } from './lib/transactionLog.js';
import { OTP_SENDING_PATHS, rateLimit } from './lib/rateLimit.js';

export { SessionTokenManager } from './durable-objects/SessionTokenManager.js';
export { RegistrationTransaction } from './durable-objects/RegistrationTransaction.js';
export { UhiRecordStore } from './durable-objects/UhiRecordStore.js';
export { RateLimiter } from './durable-objects/RateLimiter.js';

const app = new Hono();

// Locked down to clinux-frontend's real origins — this Worker sits in front of Aadhaar-adjacent
// PII flows (OTP generation against a caller-supplied Aadhaar/mobile number), so a wildcard
// origin would let any webpage's JS relay requests through it. (UHI network calls are
// server-to-server, where CORS doesn't apply.)
const ALLOWED_ORIGINS = [
    'https://clinux.yaxb.ai',
    'http://localhost:5173',
    // clinux-cubo (the provider workspace) in development. Its HPR/HFR/UHI journeys call this
    // Worker with the same session JWT and service key as clinux-frontend.
    'http://localhost:5174',
    // cubo-diary (citizens) in development: ABHA sign-in and anonymous UHI search, /citizen/*.
    'http://localhost:5175',
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

// ABDM routes: user-driven. Order matters: session must be verified before rate limiting, which
// counts per account.
const userGate = [
    serviceKeyAuth(),
    requireClinuxSession(),
    rateLimit({ bucket: 'abdm', limit: 120, windowSeconds: 60 }),
];
// After the session gate, so every logged ABDM operation is attributed (src/lib/transactionLog.js).
for (const prefix of ['/hpr/*', '/hfr/*', '/abha/*', '/hie/*']) app.use(prefix, ...userGate, recordAbdmTransactions(prefix.slice(1, -2)));
for (const path of OTP_SENDING_PATHS) app.use(path, rateLimit({ bucket: 'abdm-otp', limit: 10, windowSeconds: 600 }));

app.route('/hpr', hprRoutes);
app.route('/hfr', hfrRoutes);
app.route('/abha/scan-share', scanShareRoutes);
app.route('/abha', abhaRoutes);
app.route('/uhi', uhiRoutes);
// Citizens (cubo-diary): no ClinuxFlow session; see src/routes/citizen.js for what protects them.
app.route('/citizen', citizenRoutes);
// ABDM's HIE-CM calling this gateway as a HIP (Scan & Share). No ClinuxFlow session: ABDM's own
// signed JWT is checked in src/routes/scanShare.js. The path is fixed by ABDM: {bridge url}/api/v3/hip/...
app.route('/api/v3/hip', hipCallbackRoutes);
app.route('/', hipCallbacks);
app.route('/', hiuCallbacks);
app.route('/', scanPayCallbacks);
app.route('/hiu/data-push', dataPushRoutes);
app.route('/pay', payRoutes);
app.route('/hie/hip', hipStaffRoutes);
app.route('/hie/hiu', hiuStaffRoutes);
app.route('/hie/scan-pay', scanPayStaffRoutes);

app.notFound((c) => c.json({ success: false, error: 'Not found' }, 404));

app.onError((err, c) => {
    console.error('[clinuxflow-abdm-gateway] unhandled error:', err);
    return c.json({ success: false, error: 'Internal error' }, 500);
});

export default app;
