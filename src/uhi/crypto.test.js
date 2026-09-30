import { describe, expect, it } from 'vitest';
import { createHash, createPrivateKey, sign as edSign } from 'node:crypto';
import {
    blake512Base64,
    buildAuthorizationHeader,
    buildKeyId,
    buildSigningString,
    digestBody,
    generateKeyPair,
    parseKeyId,
    verifyAuthorizationHeader,
} from './crypto.js';

/**
 * Worked example from "Signing UHI APIs_Final.pdf" (clinux-docs/UHI), Example Flow step 1. The
 * PDF gives the body digest directly, so this vector isolates the non-obvious part: signing
 * string -> BLAKE2b-512 -> Ed25519.
 */
const EXAMPLE = {
    privateKeyDer: 'MC4CAQAwBQYDK2VwBCIEIGCioWvsJleY53bW5+8G9vWWqsdGA9y1JMoVvLslaFA7',
    publicKeyDer: 'MCowBQYDK2VwAyEA9AwjtMBySgjkf3cx2pzAYt8pL1qAlhil3WUulCSpFnI=',
    digest: 'W9UFzCRHgPpPoJxDFuGIz9bWqOjpc6f+Tv32bN1X3qSesscMXhUSdMyGsloAgn8+wo95otF2FQDz+YOBVz2hqA==',
    created: 1679652050,
    expires: 1679652060,
    // Transcribed from a scanned PDF: 'l' and 'I' are visually ambiguous in that render, so the
    // comparison below is modulo that swap only.
    signatureApprox: 'EflmhDOjl1SiwwUYKHSmz52u/FYZSggS5B177WaxvQg5OApvCk/OQW/n0nsSdRdm7KM8cXm/T77pdF7jl5G3Bw==',
};

describe('BLAKE2b-512 (@noble/hashes, used because workerd lacks it)', () => {
    it("matches Node's native blake2b512 byte for byte", () => {
        for (const input of ['', 'abc', '(created): 1 (expires): 2 digest: BLAKE-512=x', 'नमस्ते 🙂']) {
            const native = createHash('blake2b512').update(Buffer.from(input, 'utf8')).digest('base64');
            expect(blake512Base64(input)).toBe(native);
        }
    });
});

describe('signing string construction', () => {
    it("matches the PDF's documented format", () => {
        expect(buildSigningString(EXAMPLE.created, EXAMPLE.expires, EXAMPLE.digest)).toBe(
            `(created): ${EXAMPLE.created} (expires): ${EXAMPLE.expires} digest: BLAKE-512=${EXAMPLE.digest}`,
        );
    });
});

describe('worked example from Signing UHI APIs_Final.pdf', () => {
    it('reproduces the documented signature via the double hash', () => {
        const toSign = blake512Base64(buildSigningString(EXAMPLE.created, EXAMPLE.expires, EXAMPLE.digest));
        const privateKey = createPrivateKey({ key: Buffer.from(EXAMPLE.privateKeyDer, 'base64'), format: 'der', type: 'pkcs8' });
        const signature = edSign(null, Buffer.from(toSign, 'utf8'), privateKey).toString('base64');
        const normalize = (s) => s.replace(/[lI]/g, '_');
        expect(normalize(signature)).toBe(normalize(EXAMPLE.signatureApprox));
    });
});

describe('buildAuthorizationHeader / verifyAuthorizationHeader', () => {
    it('round-trips and reports the signing subscriber', async () => {
        const { privateKeyDer, publicKeyDer } = generateKeyPair();
        const body = JSON.stringify({ context: { action: 'search' }, message: { intent: {} } });
        const header = buildAuthorizationHeader({
            subscriberId: 'eua-test.example.com',
            pubKeyId: 'k1',
            privateKeyDer,
            body,
            createdAt: 1_700_000_000,
            ttlSeconds: 10,
        });
        const parsed = JSON.parse(header);
        expect(parsed.keyId).toBe('eua-test.example.com|k1|ed25519');
        expect(parsed.created).toBe('1700000000');
        expect(parsed.expires).toBe('1700000010');

        const result = await verifyAuthorizationHeader({
            header,
            body,
            now: 1_700_000_005,
            resolvePublicKey: async (subscriberId, pubKeyId) => {
                expect([subscriberId, pubKeyId]).toEqual(['eua-test.example.com', 'k1']);
                return publicKeyDer;
            },
        });
        expect(result).toEqual({ valid: true, subscriberId: 'eua-test.example.com' });
    });

    it('rejects a tampered body', async () => {
        const { privateKeyDer, publicKeyDer } = generateKeyPair();
        const header = buildAuthorizationHeader({ subscriberId: 's', pubKeyId: 'k1', privateKeyDer, body: '{"a":1}' });
        const result = await verifyAuthorizationHeader({ header, body: '{"a":2}', resolvePublicKey: async () => publicKeyDer });
        expect(result).toEqual({ valid: false, reason: 'signature-mismatch' });
    });

    it('rejects an expired signature', async () => {
        const { privateKeyDer, publicKeyDer } = generateKeyPair();
        const header = buildAuthorizationHeader({ subscriberId: 's', pubKeyId: 'k1', privateKeyDer, body: 'x', createdAt: 1_700_000_000, ttlSeconds: 10 });
        const result = await verifyAuthorizationHeader({ header, body: 'x', now: 1_700_000_020, resolvePublicKey: async () => publicKeyDer });
        expect(result).toEqual({ valid: false, reason: 'expired' });
    });

    it('rejects a signature from the future', async () => {
        const { privateKeyDer, publicKeyDer } = generateKeyPair();
        const header = buildAuthorizationHeader({ subscriberId: 's', pubKeyId: 'k1', privateKeyDer, body: 'x', createdAt: 1_700_000_100 });
        const result = await verifyAuthorizationHeader({ header, body: 'x', now: 1_700_000_000, resolvePublicKey: async () => publicKeyDer });
        expect(result).toEqual({ valid: false, reason: 'not-yet-valid' });
    });

    it('reports key-not-found when no key resolves', async () => {
        const { privateKeyDer } = generateKeyPair();
        const header = buildAuthorizationHeader({ subscriberId: 's', pubKeyId: 'k1', privateKeyDer, body: 'x' });
        expect(await verifyAuthorizationHeader({ header, body: 'x', resolvePublicKey: async () => undefined })).toEqual({
            valid: false,
            reason: 'key-not-found',
        });
    });

    it('rejects a signature made with a different key than the registered one', async () => {
        const signer = generateKeyPair();
        const registered = generateKeyPair();
        const header = buildAuthorizationHeader({ subscriberId: 's', pubKeyId: 'k1', privateKeyDer: signer.privateKeyDer, body: 'x' });
        const result = await verifyAuthorizationHeader({ header, body: 'x', resolvePublicKey: async () => registered.publicKeyDer });
        expect(result).toEqual({ valid: false, reason: 'signature-mismatch' });
    });

    it('rejects malformed headers', async () => {
        const resolvePublicKey = async () => 'unused';
        expect((await verifyAuthorizationHeader({ header: 'not json', body: 'x', resolvePublicKey })).reason).toBe('malformed-header');
        expect((await verifyAuthorizationHeader({ header: '{"keyId":"a|b|ed25519"}', body: 'x', resolvePublicKey })).reason).toBe('malformed-header');
    });
});

describe('keyId helpers', () => {
    it('round-trips', () => {
        expect(parseKeyId(buildKeyId('hspa-example.org', 'k2'))).toEqual({ subscriberId: 'hspa-example.org', pubKeyId: 'k2', algorithm: 'ed25519' });
    });
    it('rejects malformed keyIds', () => {
        expect(parseKeyId('not-enough-parts')).toBeUndefined();
    });
});

describe('digestBody', () => {
    it('is deterministic', () => {
        expect(digestBody('abc')).toBe(digestBody('abc'));
        expect(digestBody('abc')).not.toBe(digestBody('abd'));
    });
});
