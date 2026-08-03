// ABDM requires several fields (Aadhaar number, mobile number, OTP, password) to be RSA-encrypted
// client-side (i.e. by us, server-side in this Worker — never in the browser) before they're sent.
//
// IMPORTANT — there are TWO different padding schemes depending on which API family you're
// calling, per the supplied docs:
//   - ABHA-style enrolment APIs (and by extension anything following the same "V3 enrollment"
//     pattern): RSA/ECB/OAEPWithSHA-1AndMGF1Padding, public key from
//     {abhaBaseUrl}/profile/public/certificate.
//   - HPR registration/auth APIs (generateOtp, verifyOTP, createHprIdWithPreVerified, etc.):
//     RSA/ECB/PKCS1Padding, public key from {hprHfrBaseUrl}/api/v1/auth/cert.
// Mixing these up produces ciphertext ABDM can't decrypt — always check which family the target
// endpoint belongs to. This file exposes one function per scheme so callers can't default to
// the wrong one silently.
//
// TODO verify: the supplied HPR doc didn't include a sample JSON response body for
// /api/v1/auth/cert (unlike ABHA's /profile/public/certificate, which does). We assume the same
// `{ "publicKey": "<base64 DER SPKI>" }` shape — confirm against the sandbox response the first
// time this runs for real and adjust fetchPublicKey's field name if needed.

import { publicEncrypt, constants, createPublicKey } from 'node:crypto';

/**
 * Fetches a fresh RSA public key from ABDM. ABDM expects a NEW key fetch per encryption
 * operation rather than a long-lived cache — do not cache this beyond a single transaction.
 * @returns {Promise<string>} base64-encoded DER (SPKI) public key.
 */
export async function fetchPublicKey(url) {
    const response = await fetch(url, { method: 'GET', headers: { Accept: 'application/json' } });
    if (!response.ok) {
        throw new Error(`Failed to fetch ABDM public key from ${url}: HTTP ${response.status}`);
    }
    const body = await response.json();
    const key = body.publicKey || body.public_key;
    if (!key) {
        throw new Error(`ABDM public key response from ${url} did not contain a "publicKey" field`);
    }
    return key;
}

/**
 * Encrypts plaintext (Aadhaar number, mobile number, OTP, ...) using RSA-OAEP/SHA-1, as required
 * by ABHA-style enrolment/login APIs. Uses Workers' native crypto.subtle — no compat flag needed.
 * @param {string} base64PublicKey - DER (SPKI) public key, base64-encoded, as returned by ABDM.
 * @param {string} plaintext
 * @returns {Promise<string>} base64-encoded ciphertext.
 */
export async function encryptOaepSha1(base64PublicKey, plaintext) {
    const keyData = base64ToArrayBuffer(base64PublicKey);
    const cryptoKey = await crypto.subtle.importKey(
        'spki',
        keyData,
        { name: 'RSA-OAEP', hash: 'SHA-1' },
        false,
        ['encrypt']
    );
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, cryptoKey, encoded);
    return arrayBufferToBase64(ciphertext);
}

/**
 * Encrypts plaintext using RSA/ECB/PKCS1Padding, as required by HPR registration/auth APIs.
 * WebCrypto does not implement PKCS1v1.5 *encryption* (only PKCS1v1.5 *signing*), so this goes
 * through node:crypto instead — hence the `nodejs_compat` compatibility flag in wrangler.toml.
 * @param {string} base64PublicKey - DER (SPKI) public key, base64-encoded.
 * @param {string} plaintext
 * @returns {string} base64-encoded ciphertext.
 */
export function encryptPkcs1(base64PublicKey, plaintext) {
    const der = Buffer.from(base64PublicKey, 'base64');
    const publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' });
    const ciphertext = publicEncrypt(
        { key: publicKey, padding: constants.RSA_PKCS1_PADDING },
        Buffer.from(plaintext, 'utf-8')
    );
    return ciphertext.toString('base64');
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}
