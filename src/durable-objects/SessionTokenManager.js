// Durable Object that owns the single ABDM client-credential access token for this whole
// Worker. Workers are stateless per-request, but ABDM's session token is valid for ~10 hours
// (sandbox) — re-authenticating on every incoming request would be slow and needlessly hammers
// ABDM's /sessions endpoint. We always talk to the SAME instance of this DO (see
// getSessionTokenStub in src/lib/sessionToken.js, which uses idFromName('global')), so it acts
// as a single source of truth and naturally serializes concurrent refreshes: Durable Objects
// process one request at a time, so two Workers requesting a token at the same moment don't
// race to mint two tokens.

import { callAbdm, AbdmApiError } from '../lib/abdmClient.js';
import { getAbdmConfig } from '../lib/config.js';

// Refresh this many seconds before actual expiry, so a request never gets handed a token that
// dies mid-flight to ABDM.
const SAFETY_MARGIN_SECONDS = 5 * 60;

export class SessionTokenManager {
    constructor(state, env) {
        this.state = state;
        this.env = env;
    }

    async fetch(request) {
        const url = new URL(request.url);

        if (url.pathname === '/token' && request.method === 'GET') {
            // A thrown error crosses the stub.fetch() boundary back to the caller as a plain
            // Error with the same .message but NOT the same prototype chain — the calling
            // Worker's `err instanceof AbdmApiError` would always be false otherwise, even
            // though the message text looks right. getValidToken() never throws (see below) —
            // it resolves to a { ok, ... } result instead — so we serialize its error branch
            // here and let getAccessToken() (src/lib/sessionToken.js) reconstruct a real
            // AbdmApiError instance in the caller's own realm.
            const result = await this.getValidToken();
            if (result.ok) {
                return Response.json({ accessToken: result.accessToken });
            }
            const err = result.error;
            if (err instanceof AbdmApiError) {
                return Response.json({ error: err.message, abdmStatus: err.status, abdmBody: err.body }, { status: 502 });
            }
            return Response.json({ error: err.message }, { status: 500 });
        }

        if (url.pathname === '/invalidate' && request.method === 'POST') {
            await this.state.storage.delete('session');
            return Response.json({ ok: true });
        }

        return new Response('Not found', { status: 404 });
    }

    // Resolves to { ok: true, accessToken } or { ok: false, error } — deliberately never
    // throws/rejects. A rejected blockConcurrencyWhile callback does not reliably propagate as a
    // normal caught exception to its awaiter in this runtime (confirmed empirically: a try/catch
    // wrapping the blockConcurrencyWhile call never ran for a rejection originating inside it) —
    // wrapping refreshToken()'s own throw in a try/catch *inside* the callback, before it ever
    // returns/rejects, sidesteps that entirely.
    async getValidToken() {
        const stored = await this.state.storage.get('session');
        const now = Date.now();

        if (stored && stored.expiresAt - SAFETY_MARGIN_SECONDS * 1000 > now) {
            return { ok: true, accessToken: stored.accessToken };
        }

        // No valid cached token — mint a new one. this.state.blockConcurrencyWhile ensures that
        // if a second request arrives mid-refresh, it waits for this one to finish rather than
        // kicking off its own duplicate /sessions call.
        return this.state.blockConcurrencyWhile(async () => {
            // Re-check inside the lock: another caller may have just refreshed while we were
            // waiting for the lock itself.
            const recheck = await this.state.storage.get('session');
            if (recheck && recheck.expiresAt - SAFETY_MARGIN_SECONDS * 1000 > Date.now()) {
                return { ok: true, accessToken: recheck.accessToken };
            }
            try {
                const accessToken = await this.refreshToken();
                return { ok: true, accessToken };
            } catch (error) {
                return { ok: false, error };
            }
        });
    }

    async refreshToken() {
        const config = getAbdmConfig(this.env);

        const response = await callAbdm({
            url: `${config.gatewayBaseUrl}/sessions`,
            method: 'POST',
            xCmId: config.xCmId,
            body: {
                clientId: config.clientId,
                clientSecret: config.clientSecret,
                grantType: 'client_credentials',
            },
        });

        const expiresAt = Date.now() + response.expiresIn * 1000;
        await this.state.storage.put('session', {
            accessToken: response.accessToken,
            refreshToken: response.refreshToken,
            expiresAt,
        });

        console.log(`[SessionTokenManager] refreshed ABDM session token, expires ${new Date(expiresAt).toISOString()}`);
        return response.accessToken;
    }
}
