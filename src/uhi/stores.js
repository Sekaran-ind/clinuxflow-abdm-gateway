// Record store for UHI state. Production uses the UHI_RECORDS Durable Object namespace (one
// instance per record key). When that binding is absent (unit tests running under plain Node),
// an in-memory store runs the same pure operations from records.js.

import { applyRecordOp } from './records.js';

export function createMemoryRecordStore() {
    const records = new Map();
    return {
        async get(key) {
            return records.get(key) ?? null;
        },
        async put(key, record) {
            records.set(key, record);
            return record;
        },
        async apply(key, op, args) {
            const next = applyRecordOp(records.get(key) ?? null, op, args);
            if (next) records.set(key, next);
            return next;
        },
    };
}

export function createDurableObjectRecordStore(namespace) {
    const stub = (key) => namespace.get(namespace.idFromName(key));
    const call = async (key, path, init) => {
        const res = await stub(key).fetch(`https://uhi-record${path}`, init);
        const json = await res.json();
        if (!res.ok) throw new Error(json.error || `UHI record store error (${res.status})`);
        return json.record ?? null;
    };
    return {
        get: (key) => call(key, '/record', { method: 'GET' }),
        put: (key, record) =>
            call(key, '/record', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ record }) }),
        apply: (key, op, args) =>
            call(key, '/apply', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ op, args }) }),
    };
}

const memoryStores = new WeakMap();

/** Returns the store for this environment. The in-memory fallback is cached per env object so
 * a test's requests share state, while separate test envs stay isolated. */
export function getRecordStore(env) {
    if (env.UHI_RECORDS) return createDurableObjectRecordStore(env.UHI_RECORDS);
    let store = memoryStores.get(env);
    if (!store) {
        store = createMemoryRecordStore();
        memoryStores.set(env, store);
    }
    return store;
}
