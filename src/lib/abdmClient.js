// Low-level HTTP client for calling ABDM APIs. Every HPR/HFR route funnels through here so the
// mandatory correlation headers, retry/backoff behaviour, and error shape are consistent in one
// place instead of re-implemented per route.

/**
 * Thrown for any non-2xx response from ABDM. Carries the status and parsed body so callers can
 * decide how to surface it (e.g. map ABDM's error to a clean 4xx for our own API consumers).
 */
export class AbdmApiError extends Error {
    constructor(status, body, requestId) {
        super(`ABDM API responded ${status}${requestId ? ` (REQUEST-ID ${requestId})` : ''}`);
        this.name = 'AbdmApiError';
        this.status = status;
        this.body = body;
        this.requestId = requestId;
    }
}

/**
 * Builds the headers ABDM requires on essentially every call: a fresh REQUEST-ID (used as our
 * idempotency key across retries of the *same* logical call), an ISO-8601 TIMESTAMP, and
 * X-CM-ID (sbx in sandbox, abdm in production). Bearer auth is added by callAbdm.
 */
function buildAbdmHeaders({ requestId, xCmId, extra }) {
    return {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'REQUEST-ID': requestId,
        TIMESTAMP: new Date().toISOString(),
        'X-CM-ID': xCmId,
        ...extra,
    };
}

/**
 * Calls an ABDM endpoint with retry/backoff on transient failures (network errors and 5xx —
 * ABDM's sandbox in particular is known to be flaky). 4xx responses are NOT retried since
 * they're almost always a client-side validation issue that retrying won't fix.
 *
 * @param {object} params
 * @param {string} params.url - full URL to call.
 * @param {'GET'|'POST'} [params.method='POST']
 * @param {object} [params.body] - JSON body (omitted for GET).
 * @param {string} params.xCmId
 * @param {string} [params.accessToken] - ABDM gateway session token (Authorization: Bearer ...).
 * @param {object} [params.extraHeaders] - e.g. { 'x-hprid-auth': token } for HFR facility writes.
 * @param {number} [params.maxAttempts=3]
 * @returns {Promise<any>} parsed JSON response body.
 */
export async function callAbdm({
    url,
    method = 'POST',
    body,
    xCmId,
    accessToken,
    extraHeaders = {},
    maxAttempts = 3,
}) {
    // Same REQUEST-ID reused across retries of one logical call — if ABDM treats REQUEST-ID as
    // an idempotency key on their side, retried attempts won't be double-processed.
    const requestId = crypto.randomUUID();
    const headers = buildAbdmHeaders({
        requestId,
        xCmId,
        extra: {
            ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
            ...extraHeaders,
        },
    });

    let lastError;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            const response = await fetch(url, {
                method,
                headers,
                body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
            });

            const text = await response.text();
            const parsed = text ? safeJsonParse(text) : null;

            if (response.ok) {
                return parsed;
            }

            // Don't retry client errors — surface immediately.
            if (response.status >= 400 && response.status < 500) {
                throw new AbdmApiError(response.status, parsed ?? text, requestId);
            }

            // 5xx: fall through to retry logic below.
            lastError = new AbdmApiError(response.status, parsed ?? text, requestId);
        } catch (err) {
            if (err instanceof AbdmApiError && err.status < 500) throw err;
            lastError = err;
        }

        if (attempt < maxAttempts) {
            const backoffMs = 250 * 2 ** (attempt - 1); // 250ms, 500ms, ...
            await new Promise((resolve) => setTimeout(resolve, backoffMs));
            console.warn(
                `[abdmClient] retrying ${method} ${url} (attempt ${attempt + 1}/${maxAttempts}) ` +
                `REQUEST-ID=${requestId} after: ${lastError.message}`
            );
        }
    }

    console.error(`[abdmClient] ${method} ${url} failed after ${maxAttempts} attempts REQUEST-ID=${requestId}`);
    throw lastError;
}

function safeJsonParse(text) {
    try {
        return JSON.parse(text);
    } catch {
        return text;
    }
}
