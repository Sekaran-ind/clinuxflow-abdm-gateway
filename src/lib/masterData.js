// ABDM's HPR/HFR reference data (states, districts, facility types, medical councils, ownership
// types, LGD codes, ...) changes rarely. Hitting ABDM for it on every form render is wasteful and
// adds latency to the wrong path — this wraps any ABDM master-data call with a KV cache.

const DEFAULT_TTL_SECONDS = 60 * 60 * 24; // 24h — reference data doesn't move fast enough to need less.

/**
 * @param {KVNamespace} kv - env.MASTER_DATA_CACHE
 * @param {string} cacheKey - stable key, e.g. "hfr:facility-types" or "hpr:states"
 * @param {() => Promise<any>} fetchFn - called on cache miss to fetch from ABDM
 * @param {number} [ttlSeconds]
 */
export async function getCachedMasterData(kv, cacheKey, fetchFn, ttlSeconds = DEFAULT_TTL_SECONDS) {
    const cached = await kv.get(cacheKey, 'json');
    if (cached !== null) return cached;

    const fresh = await fetchFn();
    // Fire-and-forget from the caller's perspective is tempting, but awaiting keeps behaviour
    // predictable under Workers' request lifecycle (no risk of the put being cancelled).
    await kv.put(cacheKey, JSON.stringify(fresh), { expirationTtl: ttlSeconds });
    return fresh;
}

/**
 * Manual invalidation hook — wire to an admin route later if ABDM reference data needs a forced
 * refresh before the TTL naturally expires (e.g. NHA adds a new facility type mid-cycle).
 */
export async function invalidateMasterData(kv, cacheKey) {
    await kv.delete(cacheKey);
}
