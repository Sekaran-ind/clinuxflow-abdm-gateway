// Durable Object that holds per-txnId state for ABDM's multi-step OTP flows (HPR aadhaar
// registration, HFR facility-manager auth, and any future ABHA flow reusing the same pattern).
// Each flow is a sequence like: generate OTP -> verify OTP -> check account -> mobile OTP ->
// create record, spread across several separate HTTP requests from the ClinuxFlow frontend as
// the user progresses through a form. Since Workers don't retain state between invocations, this
// DO (one instance per txnId, see getTransactionStub in src/lib/sessionToken.js) is where that
// in-progress state lives.
//
// Transactions expire on their own via a Durable Object alarm — abandoned OTP flows (user closed
// the tab mid-registration) shouldn't linger indefinitely.

const TRANSACTION_TTL_MS = 15 * 60 * 1000; // 15 minutes — generous for an OTP flow, short enough to bound abuse.
const MAX_OTP_ATTEMPTS = 5;

export class RegistrationTransaction {
    constructor(state, env) {
        this.state = state;
        this.env = env;
    }

    async fetch(request) {
        const url = new URL(request.url);

        if (url.pathname === '/state' && request.method === 'GET') {
            const record = await this.state.storage.get('record');
            if (!record) return new Response('Transaction not found or expired', { status: 404 });
            return Response.json(record);
        }

        if (url.pathname === '/state' && request.method === 'PUT') {
            const patch = await request.json();
            const existing = (await this.state.storage.get('record')) || {
                createdAt: Date.now(),
                otpAttempts: 0,
            };
            const record = { ...existing, ...patch, updatedAt: Date.now() };
            await this.state.storage.put('record', record);
            await this.state.storage.setAlarm(Date.now() + TRANSACTION_TTL_MS);
            return Response.json(record);
        }

        if (url.pathname === '/record-otp-attempt' && request.method === 'POST') {
            const existing = (await this.state.storage.get('record')) || { createdAt: Date.now(), otpAttempts: 0 };
            existing.otpAttempts = (existing.otpAttempts || 0) + 1;
            await this.state.storage.put('record', existing);
            const allowed = existing.otpAttempts <= MAX_OTP_ATTEMPTS;
            return Response.json({ allowed, attempts: existing.otpAttempts, maxAttempts: MAX_OTP_ATTEMPTS });
        }

        if (url.pathname === '/state' && request.method === 'DELETE') {
            await this.state.storage.deleteAll();
            return Response.json({ ok: true });
        }

        return new Response('Not found', { status: 404 });
    }

    // Cleans up expired/abandoned transactions so this DO instance (and its storage) doesn't
    // linger forever after a user drops off mid-flow.
    async alarm() {
        await this.state.storage.deleteAll();
    }
}
