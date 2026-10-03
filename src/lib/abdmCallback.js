// What every inbound HIE-CM callback and every outbound HIE-CM call share.
//
// Inbound: ABDM's HIE-CM calls this gateway's bridge URL for Scan & Share, Scan & Pay, Running
// Token (M1/M2), care-context linking and data flow (M2, as a HIP) and consent and data flow
// (M3, as a HIU). Each call carries a JWT signed with a key HIE-CM publishes; abdmCallbackAuth()
// refuses anything else. ABDM expects a quick 202, and the real answer later through the matching
// "on-…" API: answerLater() replies at once and keeps the Worker alive for the work.
//
// Outbound: hiecm() calls a HIE-CM API with the gateway's session token, the X-HIP-ID / X-HIU-ID
// header ABDM routes on, and (when ABDM will answer by callback) a REQUEST-ID chosen by the caller,
// so the callback's response.requestId can be matched back.
import { callAbdm } from './abdmClient.js';
import { getAbdmConfig } from './config.js';
import { getAccessToken } from './sessionToken.js';
import { verifyAbdmJwt } from './abdmJwt.js';

/** Hono middleware: the request must carry a valid HIE-CM signature. ABDM_CALLBACK_AUTH=off is for local testing only. */
export function abdmCallbackAuth() {
    return async (c, next) => {
        if (c.env.ABDM_CALLBACK_AUTH === 'off') return next();
        const config = getAbdmConfig(c.env);
        const token = (c.req.header('Authorization') || '').replace(/^Bearer\s+/i, '');
        try {
            c.set('abdmClaims', await verifyAbdmJwt(token, { certsUrl: `${config.hiecmBaseUrl}/gateway/v3/certs`, xCmId: config.xCmId }));
        } catch (err) {
            console.warn(`[abdm-callback] ${c.req.path} refused:`, err.message);
            return c.json({ error: { code: 'ABDM-1017', message: 'Invalid authorization' } }, 401);
        }
        return next();
    };
}

/** Replies 202 to ABDM now and finishes `work` in the background (awaited where there is no execution context: tests, Node). */
export async function answerLater(c, tag, work) {
    const run = Promise.resolve().then(work).catch((err) => console.error(`[${tag}]`, err));
    try {
        c.executionCtx.waitUntil(run);
    } catch {
        await run;
    }
    return c.json({}, 202);
}

/** The REQUEST-ID of an inbound callback (ABDM echoes ours back in response.requestId). */
export const requestIdOf = (c) => c.req.header('REQUEST-ID') || c.req.header('request-id') || crypto.randomUUID();

/** Calls HIE-CM (`path` under ABDM_HIECM_BASE_URL, e.g. '/hip/v3/link/carecontext'). */
export async function hiecm(env, path, body, { hipId, hiuId, requestId, method = 'POST', maxAttempts = 2, extraHeaders = {} } = {}) {
    const config = getAbdmConfig(env);
    const accessToken = await getAccessToken(env);
    return callAbdm({
        url: `${config.hiecmBaseUrl}${path}`,
        method,
        xCmId: config.xCmId,
        accessToken,
        body,
        maxAttempts,
        ...(requestId ? { requestId } : {}),
        extraHeaders: { ...(hipId ? { 'X-HIP-ID': hipId } : {}), ...(hiuId ? { 'X-HIU-ID': hiuId } : {}), ...extraHeaders },
    });
}

/** Decodes a JWT's payload WITHOUT verifying it — only for reading a claim off a token whose carrier is already verified. */
export function unverifiedClaims(token) {
    try {
        const part = String(token || '').replace(/^Bearer\s+/i, '').split('.')[1];
        return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(part.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(part.length / 4) * 4, '=')), (ch) => ch.charCodeAt(0))));
    } catch {
        return {};
    }
}

/** The clinic a HIP/HIU id (an HFR facility id) belongs to, if it is registered here and active. */
export async function facilityOwner(db, facilityId) {
    if (!facilityId) return null;
    return db.prepare('SELECT * FROM hip_facilities WHERE facility_id = ? AND active = 1').bind(String(facilityId).trim()).first();
}

/** Today in India (token numbers restart each day per counter). */
export const istDate = (now = Date.now()) => new Date(now + 5.5 * 3600 * 1000).toISOString().slice(0, 10);

/** ABDM's own message out of an AbdmApiError body ({ error: { code, message } }, { code, message }, or a list of those). */
export function abdmErrorText(err) {
    const body = err?.body;
    const first = Array.isArray(body) ? body[0] : body?.error || body;
    const text = first && typeof first === 'object' ? [first.code, first.message].filter(Boolean).join(' ') : typeof body === 'string' ? body : '';
    return (text || err?.message || 'ABDM request failed').slice(0, 300);
}

/** This gateway's public origin: configured, or the one ABDM (or the patient) reached it on. */
export const publicOrigin = (c, config) => config.publicBaseUrl || new URL(c.req.url).origin;

/** The gateway's answer to a staff route when ABDM itself refused (the error handler of every /hie router). */
export function staffAbdmErrorHandler(tag, AbdmApiError) {
    return (err, c) => {
        if (err instanceof AbdmApiError) {
            console.error(`[${tag}] ABDM error ${err.status}:`, JSON.stringify(err.body));
            return c.json({ success: false, error: abdmErrorText(err), abdmStatus: err.status, abdmBody: err.body, abdmRequestId: err.requestId }, 502);
        }
        console.error(`[${tag}] unexpected error:`, err);
        return c.json({ success: false, error: err.message }, 500);
    };
}
