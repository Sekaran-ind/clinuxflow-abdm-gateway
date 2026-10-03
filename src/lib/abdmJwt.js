// Verifies the Authorization token ABDM's HIE-CM puts on the callbacks it makes to this gateway
// (Scan & Share's /api/v3/hip/patient/share): an RS256/RS512 JWT signed with a key published at
// {hiecm}/gateway/v3/certs (Scan & Share doc §3.2.2-3.2.3). Without this check, anyone who knew
// the callback URL could post fake patient profiles into a clinic's queue.
//
// Keys are cached per isolate for an hour, and refetched once when a token names a key id the
// cache doesn't have (ABDM rotating its keys).
const KEY_TTL_MS = 60 * 60 * 1000;
const ALGS = { RS256: 'SHA-256', RS512: 'SHA-512' };
let cache = { at: 0, keys: [] };

export function resetJwksCache() {
    cache = { at: 0, keys: [] };
}

const b64urlBytes = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), (ch) => ch.charCodeAt(0));
const b64urlJson = (s) => JSON.parse(new TextDecoder().decode(b64urlBytes(s)));

async function loadKeys(certsUrl, xCmId, fetchImpl, force) {
    if (!force && cache.keys.length && Date.now() - cache.at < KEY_TTL_MS) return cache.keys;
    // X-CM-ID is required: without it the sandbox answers 401 (seen live 2026-10-02).
    const res = await fetchImpl(certsUrl, { headers: { 'REQUEST-ID': crypto.randomUUID(), TIMESTAMP: new Date().toISOString(), 'X-CM-ID': xCmId } });
    if (!res.ok) throw new Error(`ABDM signing keys unavailable (HTTP ${res.status})`);
    const body = await res.json();
    cache = { at: Date.now(), keys: body.keys || [] };
    return cache.keys;
}

/**
 * @returns {Promise<object>} the token's payload, when the signature and expiry check out.
 * @throws when the token is missing, malformed, signed with an unknown key, or expired.
 */
export async function verifyAbdmJwt(token, { certsUrl, xCmId = 'sbx', fetchImpl = fetch, now = Date.now() } = {}) {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) throw new Error('Not a JWT');
    const header = b64urlJson(parts[0]);
    const hash = ALGS[header.alg];
    if (!hash) throw new Error(`Unsupported algorithm ${header.alg}`);

    let keys = await loadKeys(certsUrl, xCmId, fetchImpl, false);
    let jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) {
        keys = await loadKeys(certsUrl, xCmId, fetchImpl, true);
        jwk = keys.find((k) => k.kid === header.kid);
    }
    if (!jwk) throw new Error('Signed with an unknown key');

    const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e }, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlBytes(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    if (!ok) throw new Error('Bad signature');
    const payload = b64urlJson(parts[1]);
    if (payload.exp && payload.exp * 1000 < now) throw new Error('Expired');
    return payload;
}
