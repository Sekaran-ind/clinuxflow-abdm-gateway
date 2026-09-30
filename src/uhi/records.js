// Pure record operations for UHI state: EUA transactions and HSPA orders.
//
// Kept pure (record in, record out) so the in-memory store used by tests and the Durable Object
// store used in production run exactly the same logic. The original clinux-uhi-gateway kept
// these in process-local Maps, which lose everything on restart; here each record lives in its
// own Durable Object instance, which also serializes concurrent callbacks for one transaction
// (several on_search responses can arrive at once).

/** Applies `op` to `record` (which may be null) and returns the new record, or null to mean
 * "no such record" for ops that require one to exist. */
export function applyRecordOp(record, op, args = {}) {
    const now = args.at ?? new Date().toISOString();
    switch (op) {
        // --- EUA transactions: keyed `eua-txn:<transactionId>` ---
        case 'eua.begin':
            return record ?? newEuaTransaction(args.transactionId, args.clinicId, args.accountId, args.readKeyHash);
        // eua.catalog/order/error/push: only transactions this gateway started (eua.begin) are
        // recorded; a callback for an unknown transaction is dropped (null), never creating an
        // ownerless record.
        case 'eua.catalog': {
            if (!record) return null;
            const next = { ...record, catalogs: [...record.catalogs, args.catalog] };
            if (!next.providerId && args.providerId) {
                next.providerId = args.providerId;
                next.providerUri = args.providerUri;
            }
            return next;
        }
        case 'eua.order': {
            if (!record) return null;
            const next = { ...record, order: args.order };
            if (args.providerId) {
                next.providerId = args.providerId;
                next.providerUri = args.providerUri;
            }
            return next;
        }
        // A citizen booking: who (by a hash of their ABHA) asked for the hold.
        case 'eua.customer': {
            if (!record) return null;
            return { ...record, customerHash: args.customerHash };
        }
        case 'eua.error': {
            if (!record) return null;
            return { ...record, lastError: args.error };
        }
        case 'eua.push': {
            if (!record) return null;
            return { ...record, pushes: [...record.pushes, { action: args.action, message: args.message, receivedAt: now }] };
        }

        // --- HSPA orders: keyed `hspa-order:<orderId>` ---
        case 'hspa.state': {
            if (!record) return null;
            return { ...record, state: args.state, order: { ...record.order, state: args.state, updated_at: now } };
        }

        default:
            throw new Error(`Unknown UHI record op: ${op}`);
    }
}

function newEuaTransaction(transactionId, clinicId, accountId, readKeyHash = null) {
    // clinicId/accountId: the ClinuxFlow user who started the transaction. Reads and follow-up
    // actions are restricted to that clinic (the lesson of finding S1: never look up by id alone).
    // A citizen search (cubo-diary, no account) has no clinic: it carries readKeyHash instead, the
    // SHA-256 of a random key only the searcher was given.
    return { transactionId, clinicId: clinicId ?? null, accountId: accountId ?? null, ...(readKeyHash ? { readKeyHash } : {}), createdAt: new Date().toISOString(), catalogs: [], pushes: [] };
}

export const recordKeys = {
    euaTransaction: (transactionId) => `eua-txn:${transactionId}`,
    hspaOrder: (orderId) => `hspa-order:${orderId}`,
    /** index: transactionId -> { orderId } */
    hspaTransaction: (transactionId) => `hspa-txn:${transactionId}`,
};
