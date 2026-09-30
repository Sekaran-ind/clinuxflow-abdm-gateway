import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';
import { generateKeyPairSync, privateDecrypt, constants } from 'node:crypto';
import { encryptOaepSha1, encryptPkcs1, fetchPublicKey, publicKeyFromBody } from './encryption.js';

// One RSA keypair reused across tests — encryption is deterministic-enough per call that we
// only need this to exercise the actual padding schemes, not to test RSA itself.
let publicKeyBase64;
let privateKey;

beforeAll(() => {
    const { publicKey, privateKey: priv } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    publicKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    privateKey = priv;
});

describe('encryptPkcs1', () => {
    it('produces ciphertext that decrypts back to the original plaintext under PKCS1 padding', () => {
        const plaintext = '999941234567'; // Aadhaar-shaped test value
        const ciphertext = encryptPkcs1(publicKeyBase64, plaintext);
        const decrypted = privateDecrypt(
            { key: privateKey, padding: constants.RSA_PKCS1_PADDING },
            Buffer.from(ciphertext, 'base64')
        );
        expect(decrypted.toString('utf-8')).toBe(plaintext);
    });

    // Pins the exact invariant encryption.js's own header comment warns about: swapping padding
    // schemes must not silently "work" and produce ciphertext ABDM can't decrypt.
    it('is NOT decryptable with OAEP padding (the two schemes must not be interchangeable)', () => {
        const ciphertext = encryptPkcs1(publicKeyBase64, 'some-otp-123456');
        expect(() =>
            privateDecrypt(
                { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
                Buffer.from(ciphertext, 'base64')
            )
        ).toThrow();
    });
});

describe('encryptOaepSha1', () => {
    it('produces ciphertext that decrypts back to the original plaintext under OAEP/SHA-1 padding', async () => {
        const plaintext = '9876543210'; // mobile-number-shaped test value
        const ciphertext = await encryptOaepSha1(publicKeyBase64, plaintext);
        const decrypted = privateDecrypt(
            { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
            Buffer.from(ciphertext, 'base64')
        );
        expect(decrypted.toString('utf-8')).toBe(plaintext);
    });

    it('is NOT decryptable with PKCS1 padding (the two schemes must not be interchangeable)', async () => {
        const plaintext = 'test-otp-654321';
        const ciphertext = await encryptOaepSha1(publicKeyBase64, plaintext);
        // PKCS1v1.5 unpadding is notoriously lenient (the same looseness behind Bleichenbacher-
        // style padding-oracle attacks) — decrypting OAEP ciphertext with PKCS1 padding doesn't
        // reliably throw the way the reverse direction does. Either it throws, or it "succeeds"
        // with garbage that must not equal the real plaintext — both are acceptable proof the
        // schemes aren't interchangeable; silently recovering the correct plaintext is not.
        let decrypted;
        try {
            decrypted = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(ciphertext, 'base64'));
        } catch (err) {
            return; // threw — that's a pass
        }
        expect(decrypted.toString('utf-8')).not.toBe(plaintext);
    });
});

describe('fetchPublicKey', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('returns the key from a "publicKey" field', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            text: async () => JSON.stringify({ publicKey: 'abc123' }),
        }));
        await expect(fetchPublicKey('https://example.test/cert')).resolves.toBe('abc123');
    });

    it('falls back to a "public_key" (snake_case) field', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            text: async () => JSON.stringify({ public_key: 'xyz789' }),
        }));
        await expect(fetchPublicKey('https://example.test/cert')).resolves.toBe('xyz789');
    });

    it('throws when the response has neither field', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
            ok: true,
            text: async () => JSON.stringify({ somethingElse: true }),
        }));
        await expect(fetchPublicKey('https://example.test/cert')).rejects.toThrow(/did not contain/);
    });

    it('throws when the response is not ok', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 503 }));
        await expect(fetchPublicKey('https://example.test/cert')).rejects.toThrow(/HTTP 503/);
    });

    it('sends Authorization: Bearer <accessToken> when one is given — real bug found live: ABHA\'s own /profile/public/certificate 401s without it', async () => {
        const fetchMock = vi.fn().mockResolvedValue({ ok: true, text: async () => JSON.stringify({ publicKey: 'abc123' }) });
        vi.stubGlobal('fetch', fetchMock);
        await fetchPublicKey('https://example.test/cert', 'my-token');
        expect(fetchMock).toHaveBeenCalledWith('https://example.test/cert', expect.objectContaining({
            headers: expect.objectContaining({ Authorization: 'Bearer my-token' }),
        }));
    });

    it('sends REQUEST-ID and TIMESTAMP: ABHA answers 404 "Invalid Timestamp" without them', async () => {
        const fetchMock = vi.fn().mockResolvedValue({ ok: true, text: async () => JSON.stringify({ publicKey: 'abc123' }) });
        vi.stubGlobal('fetch', fetchMock);
        await fetchPublicKey('https://example.test/cert', 'my-token');
        const headers = fetchMock.mock.calls[0][1].headers;
        expect(headers['REQUEST-ID']).toMatch(/^[0-9a-f-]{36}$/);
        expect(new Date(headers.TIMESTAMP).toISOString()).toBe(headers.TIMESTAMP);
    });

    it('includes ABDM\'s error body in the failure', async () => {
        vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404, text: async () => '{"error":{"code":"ABDM-1016: ","message":"Invalid Timestamp"}}' }));
        await expect(fetchPublicKey('https://example.test/cert')).rejects.toThrow(/HTTP 404 .*Invalid Timestamp/);
    });

    it('omits Authorization entirely when no accessToken is given', async () => {
        const fetchMock = vi.fn().mockResolvedValue({ ok: true, text: async () => JSON.stringify({ publicKey: 'abc123' }) });
        vi.stubGlobal('fetch', fetchMock);
        await fetchPublicKey('https://example.test/cert');
        const headers = fetchMock.mock.calls[0][1].headers;
        expect(headers.Authorization).toBeUndefined();
    });
});

describe('publicKeyFromBody', () => {
    it('reads JSON, PEM (what the HPR cert endpoint returns) and bare base64 alike', () => {
        const b64 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAabc/def+ghi=';
        expect(publicKeyFromBody(JSON.stringify({ publicKey: b64 }))).toBe(b64);
        expect(publicKeyFromBody(`-----BEGIN PUBLIC KEY-----\n${b64.slice(0, 20)}\n${b64.slice(20)}\n-----END PUBLIC KEY-----\n`)).toBe(b64);
        expect(publicKeyFromBody(`  ${b64}\n`)).toBe(b64);
    });

    it('refuses what is not a key', () => {
        expect(() => publicKeyFromBody('{"x":1}')).toThrow(/did not contain/);
        expect(() => publicKeyFromBody('<html>error</html>')).toThrow(/not a recognisable key/);
        expect(() => publicKeyFromBody('{oops')).toThrow(/not valid JSON/);
    });
});
