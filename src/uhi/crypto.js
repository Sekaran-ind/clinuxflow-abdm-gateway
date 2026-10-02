// UHI request signing and verification (Ed25519 over a BLAKE2b-512 digest).
//
// Ported from clinux-uhi-gateway's packages/uhi-crypto. Implements the scheme in
// docs/UHI/Signing UHI APIs_Final.pdf (clinux-docs), cross-checked against the NHA-ABDM/UHI
// reference Crypt.java.
//
// The non-obvious step: the "(created) (expires) digest" signing string is itself
// BLAKE2b-512 hashed before being Ed25519-signed. Signing the raw string, as the PDF prose
// suggests, does not reproduce the PDF's own worked example; the double hash does
// (pinned by uhi-crypto.test.js).
//
// Workers note: workerd's node:crypto has no BLAKE2b ("Digest method not supported", verified
// against a local workerd), so BLAKE2b comes from @noble/hashes. Ed25519 sign/verify via
// node:crypto works under nodejs_compat.

import { blake2b } from '@noble/hashes/blake2b';
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from 'node:crypto';

export const SIGNING_ALGORITHM = 'ed25519';
export const SIGNED_HEADERS = '(created) (expires) digest';

/** base64(BLAKE2b-512(payload)), the PDF's "BLAKE-512" digest. */
export function blake512Base64(payload) {
    const bytes = blake2b(new TextEncoder().encode(payload), { dkLen: 64 });
    return Buffer.from(bytes).toString('base64');
}

export function digestBody(body) {
    return blake512Base64(body);
}

export function buildSigningString(created, expires, digest) {
    return `(created): ${created} (expires): ${expires} digest: BLAKE-512=${digest}`;
}

/** @returns {{ publicKeyDer: string, privateKeyDer: string }} base64 SPKI / PKCS8 DER */
export function generateKeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    return {
        publicKeyDer: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
        privateKeyDer: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    };
}

export function buildKeyId(subscriberId, pubKeyId, algorithm = SIGNING_ALGORITHM) {
    return `${subscriberId}|${pubKeyId}|${algorithm}`;
}

export function parseKeyId(keyId) {
    const parts = String(keyId).split('|');
    if (parts.length !== 3) return undefined;
    const [subscriberId, pubKeyId, algorithm] = parts;
    if (!subscriberId || !pubKeyId || !algorithm) return undefined;
    return { subscriberId, pubKeyId, algorithm };
}

/** Ed25519 signature (base64) over the UTF-8 bytes of `text`. */
export function signText(text, privateKeyDer) {
    const privateKey = createPrivateKey({ key: Buffer.from(privateKeyDer, 'base64'), format: 'der', type: 'pkcs8' });
    return edSign(null, Buffer.from(text, 'utf8'), privateKey).toString('base64');
}

/**
 * Builds the JSON string sent as the Authorization / X-Gateway-Authorization header value.
 * @param {{ subscriberId: string, pubKeyId: string, privateKeyDer: string, body: string,
 *           ttlSeconds?: number, createdAt?: number }} params
 */
export function buildAuthorizationHeader(params) {
    const created = params.createdAt ?? Math.floor(Date.now() / 1000);
    const expires = created + (params.ttlSeconds ?? 10);
    const toSign = blake512Base64(buildSigningString(created, expires, digestBody(params.body)));
    return JSON.stringify({
        headers: SIGNED_HEADERS,
        expires: String(expires),
        signature: signText(toSign, params.privateKeyDer),
        created: String(created),
        keyId: buildKeyId(params.subscriberId, params.pubKeyId),
        algorithm: SIGNING_ALGORITHM,
    });
}

/**
 * Verifies an inbound Authorization / X-Gateway-Authorization header against the raw body.
 * @param {{ header: string, body: string, now?: number,
 *           resolvePublicKey: (subscriberId: string, pubKeyId: string) => Promise<string|undefined> }} params
 * @returns {Promise<{ valid: true, subscriberId: string } | { valid: false, reason: string }>}
 */
export async function verifyAuthorizationHeader(params) {
    let parsed;
    try {
        parsed = JSON.parse(params.header);
    } catch {
        return { valid: false, reason: 'malformed-header' };
    }
    if (!parsed || !parsed.keyId || !parsed.signature || !parsed.created || !parsed.expires || !parsed.algorithm) {
        return { valid: false, reason: 'malformed-header' };
    }
    const keyId = parseKeyId(parsed.keyId);
    if (!keyId) return { valid: false, reason: 'malformed-header' };
    if (keyId.algorithm !== parsed.algorithm || parsed.algorithm !== SIGNING_ALGORITHM) {
        return { valid: false, reason: 'algorithm-mismatch' };
    }

    const now = params.now ?? Math.floor(Date.now() / 1000);
    const created = Number(parsed.created);
    const expires = Number(parsed.expires);
    if (!Number.isFinite(created) || !Number.isFinite(expires)) return { valid: false, reason: 'malformed-header' };
    if (created > now) return { valid: false, reason: 'not-yet-valid' };
    if (expires < now) return { valid: false, reason: 'expired' };

    const publicKeyDer = await params.resolvePublicKey(keyId.subscriberId, keyId.pubKeyId);
    if (!publicKeyDer) return { valid: false, reason: 'key-not-found' };

    const toSign = blake512Base64(buildSigningString(created, expires, digestBody(params.body)));
    let ok = false;
    try {
        const publicKey = createPublicKey({ key: Buffer.from(publicKeyDer, 'base64'), format: 'der', type: 'spki' });
        ok = edVerify(null, Buffer.from(toSign, 'utf8'), publicKey, Buffer.from(parsed.signature, 'base64'));
    } catch {
        ok = false;
    }
    return ok ? { valid: true, subscriberId: keyId.subscriberId } : { valid: false, reason: 'signature-mismatch' };
}
