// Thin accessors over the Durable Object stubs so route handlers just call
// `getAccessToken(env)` / `getTransactionState(env, txnId)` without knowing about DO plumbing.

import { AbdmApiError } from './abdmClient.js';

/**
 * @returns {Promise<string>} a valid ABDM client-credential access token, refreshing if needed.
 */
export async function getAccessToken(env) {
    const id = env.SESSION_TOKEN.idFromName('global');
    const stub = env.SESSION_TOKEN.get(id);
    const response = await stub.fetch('https://session-token/token');
    const data = await response.json();

    // Re-hydrate an AbdmApiError in this (the caller's) realm — see SessionTokenManager.js's
    // /token handler for why a thrown error can't just cross the DO boundary directly and still
    // pass `instanceof AbdmApiError` on this side.
    if (!response.ok) {
        if (data.abdmStatus !== undefined) throw new AbdmApiError(data.abdmStatus, data.abdmBody);
        throw new Error(data.error || 'Failed to obtain ABDM access token');
    }

    return data.accessToken;
}

function txnStub(env, txnId) {
    const id = env.REGISTRATION_TXN.idFromName(txnId);
    return env.REGISTRATION_TXN.get(id);
}

export async function getTransactionState(env, txnId) {
    const stub = txnStub(env, txnId);
    const response = await stub.fetch('https://registration-txn/state');
    if (response.status === 404) return null;
    return response.json();
}

export async function putTransactionState(env, txnId, patch) {
    const stub = txnStub(env, txnId);
    const response = await stub.fetch('https://registration-txn/state', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
    });
    return response.json();
}

/**
 * Call before accepting an OTP verification attempt. Returns { allowed: false } once
 * MAX_OTP_ATTEMPTS is exceeded for this txnId, so a route can reject further guesses instead of
 * proxying them to ABDM (both a UX and an abuse-prevention concern).
 */
export async function recordOtpAttempt(env, txnId) {
    const stub = txnStub(env, txnId);
    const response = await stub.fetch('https://registration-txn/record-otp-attempt', { method: 'POST' });
    return response.json();
}

export async function clearTransactionState(env, txnId) {
    const stub = txnStub(env, txnId);
    await stub.fetch('https://registration-txn/state', { method: 'DELETE' });
}
