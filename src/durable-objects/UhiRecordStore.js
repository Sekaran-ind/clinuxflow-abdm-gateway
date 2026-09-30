// Durable Object holding one UHI record (an EUA transaction, an HSPA order, or an HSPA
// transaction→order index entry), one instance per record key (see src/uhi/stores.js).
//
// A single instance per key serializes concurrent writes to that record — several on_search
// callbacks for the same transaction may arrive at once — and survives restarts, unlike the
// in-process Maps the standalone clinux-uhi-gateway used.

import { applyRecordOp } from '../uhi/records.js';

// UHI transactions are short-lived booking flows; keep records long enough to cover a booking
// and its follow-up status/cancel/update traffic, then let them expire.
const RECORD_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export class UhiRecordStore {
    constructor(state, env) {
        this.state = state;
        this.env = env;
    }

    async fetch(request) {
        const url = new URL(request.url);

        if (url.pathname === '/record' && request.method === 'GET') {
            const record = await this.state.storage.get('record');
            return Response.json({ record: record ?? null });
        }

        if (url.pathname === '/record' && request.method === 'PUT') {
            const { record } = await request.json();
            await this.state.storage.put('record', record);
            await this.state.storage.setAlarm(Date.now() + RECORD_TTL_MS);
            return Response.json({ record });
        }

        if (url.pathname === '/apply' && request.method === 'POST') {
            const { op, args } = await request.json();
            const existing = (await this.state.storage.get('record')) ?? null;
            let next;
            try {
                next = applyRecordOp(existing, op, args);
            } catch (err) {
                return Response.json({ error: err.message }, { status: 400 });
            }
            if (next) {
                await this.state.storage.put('record', next);
                await this.state.storage.setAlarm(Date.now() + RECORD_TTL_MS);
            }
            return Response.json({ record: next });
        }

        return new Response('Not found', { status: 404 });
    }

    async alarm() {
        await this.state.storage.deleteAll();
    }
}
