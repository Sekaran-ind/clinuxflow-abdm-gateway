// Fidelius: the end-to-end encryption ABDM uses for health records moving from a HIP to a HIU
// (M2 data push, M3 data receipt). Byte-compatible with NHA's reference, mgrmtech/fidelius-cli
// (Java + BouncyCastle), whose README test vectors are in fidelius.test.js:
//
//   - ECDH on BouncyCastle's "curve25519": Curve25519 in short Weierstrass form, NOT X25519. Public
//     keys travel as a 65-byte uncompressed point (0x04 || x || y; 88 base64 characters) or as an
//     X.509 SubjectPublicKeyInfo with explicit curve parameters (~412 characters). The shared
//     secret is the shared point's x coordinate, 32 bytes big-endian.
//   - xor = senderNonce XOR requesterNonce (32 random bytes each); salt = xor[0..20), iv = xor[20..32).
//   - key = HKDF-SHA256(ikm = shared secret, salt, no info, 32 bytes); AES-256-GCM, 128-bit tag,
//     output base64(ciphertext || tag).
//
// The sender (HIP) encrypts with its private key and the requester's (HIU's) public key; the
// requester decrypts with its private key and the sender's public key. Each side makes a fresh
// key pair and nonce per data transfer.
import { weierstrassN } from '@noble/curves/abstract/weierstrass';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

// BouncyCastle CustomNamedCurves "curve25519" (= Curve25519 mapped to y² = x³ + ax + b).
export const CURVE = {
    p: 2n ** 255n - 19n,
    a: 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144n,
    b: 0x7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864n,
    Gx: 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245an,
    Gy: 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9n,
    n: 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn,
    h: 8n,
};
const Point = weierstrassN(CURVE);

// What ABDM's keyMaterial says about these keys (data-flow request / data push).
export const KEY_MATERIAL = { cryptoAlg: 'ECDH', curve: 'Curve25519', parameters: 'Curve25519/32byte random key' };

export function toBase64(bytes) {
    let s = '';
    // In chunks: spreading a whole FHIR bundle's bytes into one call overflows the stack.
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s);
}
export const fromBase64 = (s) => Uint8Array.from(atob(String(s).trim()), (ch) => ch.charCodeAt(0));

const toBigInt = (bytes) => bytes.reduce((acc, b) => (acc << 8n) | BigInt(b), 0n);
function toBytes(n, length = 32) {
    const out = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--, n >>= 8n) out[i] = Number(n & 0xffn);
    return out;
}

/** A public key from either encoding ABDM uses: the raw uncompressed point, or X.509 (its point is the trailing BIT STRING). */
export function decodePublicKey(base64) {
    const bytes = fromBase64(base64);
    const raw = bytes.length === 65 ? bytes : bytes.slice(-65);
    if (raw.length !== 65 || raw[0] !== 0x04) throw new Error('Not a Curve25519 public key');
    const point = Point.fromBytes(raw); // throws if the point is not on the curve
    point.assertValidity();
    return point;
}

/** Fidelius private keys are a BigInteger's bytes (Java's toByteArray: big-endian, maybe a leading 0). */
export const decodePrivateKey = (base64) => {
    const d = toBigInt(fromBase64(base64));
    if (d <= 0n || d >= CURVE.n) throw new Error('Not a Curve25519 private key');
    return d;
};

// Everything an X.509 SubjectPublicKeyInfo for this curve holds before the 65-byte point: the
// algorithm, the explicit curve parameters and the BIT STRING header (from NHA's example key).
const X509_PREFIX = fromBase64('MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAA==');

/**
 * A fresh key pair and nonce, as fidelius-cli's generate-key-material makes them. The X.509 form
 * is what NHA's own ABDM wrapper sends as keyMaterial.dhPublicKey.keyValue (ECPublicKey.getEncoded()).
 */
export function generateKeyMaterial() {
    let d = 0n;
    while (d <= 0n || d >= CURVE.n) d = toBigInt(crypto.getRandomValues(new Uint8Array(32))) % CURVE.n;
    const point = Point.BASE.multiply(d).toBytes(false);
    const x509 = new Uint8Array(X509_PREFIX.length + point.length);
    x509.set(X509_PREFIX);
    x509.set(point, X509_PREFIX.length);
    return {
        privateKey: toBase64(toBytes(d)),
        publicKey: toBase64(point),
        x509PublicKey: toBase64(x509),
        nonce: toBase64(crypto.getRandomValues(new Uint8Array(32))),
    };
}

function sharedSecret(privateKeyB64, publicKeyB64) {
    const shared = decodePublicKey(publicKeyB64).multiply(decodePrivateKey(privateKeyB64)).toAffine();
    return toBytes(shared.x);
}

async function aesKey(privateKeyB64, publicKeyB64, senderNonce, requesterNonce, usage) {
    const a = fromBase64(senderNonce);
    const b = fromBase64(requesterNonce);
    if (a.length !== 32 || b.length !== 32) throw new Error('Fidelius nonces are 32 bytes');
    const xor = a.map((v, i) => v ^ b[i]);
    const key = hkdf(sha256, sharedSecret(privateKeyB64, publicKeyB64), xor.slice(0, 20), undefined, 32);
    return { iv: xor.slice(20), key: await crypto.subtle.importKey('raw', key, 'AES-GCM', false, [usage]) };
}

/** HIP side: encrypts a string (a FHIR bundle's JSON) for the requester. */
export async function encrypt({ plaintext, senderNonce, requesterNonce, senderPrivateKey, requesterPublicKey }) {
    const { iv, key } = await aesKey(senderPrivateKey, requesterPublicKey, senderNonce, requesterNonce, 'encrypt');
    const out = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, new TextEncoder().encode(plaintext));
    return toBase64(new Uint8Array(out));
}

/** HIU side: decrypts what a HIP pushed. Throws when the data or keys don't match (GCM tag check). */
export async function decrypt({ encryptedData, requesterNonce, senderNonce, requesterPrivateKey, senderPublicKey }) {
    const { iv, key } = await aesKey(requesterPrivateKey, senderPublicKey, senderNonce, requesterNonce, 'decrypt');
    const out = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, fromBase64(encryptedData));
    return new TextDecoder().decode(out);
}
