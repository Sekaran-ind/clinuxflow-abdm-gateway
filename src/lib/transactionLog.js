// ABDM transaction log: one row per ABDM operation a ClinuxFlow user drives through this gateway
// (HPR, HFR, ABHA, UHI operator routes), written to the shared `clinuxflow` D1 database's
// abdm_transactions table (clinuxflow-api migrations/0016, which owns the schema) and shown in
// clinux-frontend's Operations → ABDM transactions screen, read through clinuxflow-api.
//
// Metadata only, by construction: the operation is the route PATTERN (e.g.
// "GET /hpr/master/districts/:stateId"), never the concrete path or query, so no txnId, ABHA
// number or other identifier from a URL lands in the log; no request or response body is stored,
// only the status codes, ABDM's REQUEST-ID when an ABDM error carried one, and a short error
// message. Registered after requireClinuxSession, so every row is attributed to a clinic and an
// account; an anonymous request (no session) is never logged.
//
// Never blocks or fails the request: the insert runs after the response is built, through
// waitUntil when there is an execution context, and any failure is only logged.
import { matchedRoutes } from 'hono/route';

const MAX_ERROR = 200;
let missingTableWarned = false;

/** The handler's own route pattern ("POST /hpr/registration/aadhaar-link"), not a middleware's "/hpr/*". */
export function operationOf(c) {
    try {
        const routes = matchedRoutes(c).filter((r) => r.method !== 'ALL');
        const route = routes.at(-1);
        if (route?.path) return `${c.req.method} ${route.path}`;
    } catch { /* fall through */ }
    return `${c.req.method} ${c.req.path.split('/').slice(0, 3).join('/')}/…`;
}

/** What a gateway error body says: { error, abdmStatus, abdmRequestId } (see each route file's error handler). */
export async function failureOf(res) {
    if (res.status < 400) return {};
    const body = await res.clone().json().catch(() => null);
    const abdmMessage = body?.abdmBody?.message || body?.abdmBody?.error?.message || body?.abdmBody?.details?.[0]?.message;
    const error = [body?.error, abdmMessage].filter(Boolean).join(': ') || `HTTP ${res.status}`;
    return {
        abdmStatus: Number.isInteger(body?.abdmStatus) ? body.abdmStatus : null,
        abdmRequestId: body?.abdmRequestId ? String(body.abdmRequestId).slice(0, 64) : null,
        error: error.slice(0, MAX_ERROR),
    };
}

export function recordAbdmTransactions(service) {
    return async (c, next) => {
        const started = Date.now();
        await next();
        const user = c.get('user');
        if (!user?.clinicId || !c.env.DB) return;
        const write = (async () => {
            try {
                const f = await failureOf(c.res);
                await c.env.DB
                    .prepare(
                        `INSERT INTO abdm_transactions (id, clinic_id, account_id, service, operation, http_status, ok, abdm_status, abdm_request_id, error, duration_ms)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    )
                    .bind(
                        crypto.randomUUID(), user.clinicId, user.accountId ?? null, service, operationOf(c), c.res.status,
                        c.res.status < 400 ? 1 : 0, f.abdmStatus ?? null, f.abdmRequestId ?? null, f.error ?? null, Date.now() - started,
                    )
                    .run();
            } catch (err) {
                // The usual local cause: the gateway running on its own local database, which has no
                // clinuxflow-api migrations. Say so once, plainly, instead of one line per call.
                if (/no such table/i.test(err.message)) {
                    if (!missingTableWarned) {
                        missingTableWarned = true;
                        console.error('[transactionLog] abdm_transactions does not exist in this database, so Operations → ABDM transactions stays empty. Locally, run the gateway with `npm run dev` (it shares clinuxflow-api\'s local D1) and apply clinuxflow-api\'s migrations.');
                    }
                } else {
                    console.error('[transactionLog] could not record', service, err.message);
                }
            }
        })();
        try {
            c.executionCtx.waitUntil(write);
        } catch {
            await write; // no execution context (tests, some local runs)
        }
    };
}
