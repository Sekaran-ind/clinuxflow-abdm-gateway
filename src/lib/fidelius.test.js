import { describe, expect, it } from 'vitest';
import { CURVE, decodePublicKey, decrypt, encrypt, fromBase64, generateKeyMaterial } from './fidelius.js';

// NHA's reference implementation's own example (mgrmtech/fidelius-cli README): key material of a
// requester and a sender, and what `fidelius-cli e` / `d` produce from them.
const requester = {
    privateKey: 'DMxHPri8d7IT23KgLk281zZenMfVHSdeamq0RhwlIBk=',
    publicKey: 'BAheD5rUqTy4V5xR4/6HWmYpopu5CO+KO8BECS0udNqUTSNo91TIqIIy1A4Vh+F94c+n9vAcwXU2bGcfsI5f69Y=',
    x509PublicKey: 'MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAAQIXg+a1Kk8uFecUeP+h1pmKaKbuQjvijvARAktLnTalE0jaPdUyKiCMtQOFYfhfeHPp/bwHMF1NmxnH7COX+vW',
    nonce: '6uj1RdDUbcpI3lVMZvijkMC8Te20O4Bcyz0SyivX8Eg=',
};
const sender = {
    privateKey: 'AYhVZpbVeX4KS5Qm/W0+9Ye2q3rnVVGmqRICmseWni4=',
    publicKey: 'BABVt+mpRLMXiQpIfEq6bj8hlXsdtXIxLsspmMgLNI1SR5mHgDVbjHO2A+U4QlMddGzqyEidzm1AkhtSxSO2Ahg=',
    nonce: 'lmXgblZwotx+DfBgKJF0lZXtAXgBEYr5khh79Zytr2Y=',
};
const plaintext = "Wormtail should never have been Potter cottage's secret keeper.";
const encryptedData = 'pzMvVZNNVtJzqPkkxcCbBUWgDEBy/mBXIeT2dJWI16ZAQnnXUb9lI+S4k8XK6mgZSKKSRIHkcNvJpllnBg548wUgavBa0vCRRwdL6kY6Yw==';

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const n32 = (v) => v.toString(16).padStart(64, '0');

describe('Fidelius (ABDM health-record encryption)', () => {
    it('uses the curve whose parameters NHA’s X.509 key spells out', () => {
        // The X.509 key carries the curve explicitly: prime, a, b, G (uncompressed), n, cofactor.
        const der = hex(fromBase64(requester.x509PublicKey));
        for (const v of [CURVE.p, CURVE.a, CURVE.b, CURVE.n]) expect(der).toContain(n32(v));
        expect(der).toContain(`04${n32(CURVE.Gx)}${n32(CURVE.Gy)}`);
        expect(der).toContain('020108'); // INTEGER 8: the cofactor
    });

    it('derives each published public key from its private key', async () => {
        const { weierstrassN } = await import('@noble/curves/abstract/weierstrass');
        const Point = weierstrassN(CURVE);
        for (const k of [requester, sender]) {
            const d = BigInt(`0x${hex(fromBase64(k.privateKey))}`);
            expect(btoa(String.fromCharCode(...Point.BASE.multiply(d).toBytes(false)))).toBe(k.publicKey);
        }
    });

    it('encrypts exactly as fidelius-cli does', async () => {
        const out = await encrypt({ plaintext, senderNonce: sender.nonce, requesterNonce: requester.nonce, senderPrivateKey: sender.privateKey, requesterPublicKey: requester.publicKey });
        expect(out).toBe(encryptedData);
    });

    it('accepts the requester’s key in X.509 form too', async () => {
        expect(decodePublicKey(requester.x509PublicKey).equals(decodePublicKey(requester.publicKey))).toBe(true);
        const out = await encrypt({ plaintext, senderNonce: sender.nonce, requesterNonce: requester.nonce, senderPrivateKey: sender.privateKey, requesterPublicKey: requester.x509PublicKey });
        expect(out).toBe(encryptedData);
    });

    it('decrypts what fidelius-cli encrypted', async () => {
        const out = await decrypt({ encryptedData, requesterNonce: requester.nonce, senderNonce: sender.nonce, requesterPrivateKey: requester.privateKey, senderPublicKey: sender.publicKey });
        expect(out).toBe(plaintext);
    });

    it('round-trips fresh key material, and a large bundle, and fails closed on the wrong key', async () => {
        const hip = generateKeyMaterial();
        const hiu = generateKeyMaterial();
        const bundle = JSON.stringify({ resourceType: 'Bundle', entry: Array.from({ length: 3000 }, (_, i) => ({ fullUrl: `urn:uuid:${i}`, text: 'ठीक है ✓' })) });
        const enc = await encrypt({ plaintext: bundle, senderNonce: hip.nonce, requesterNonce: hiu.nonce, senderPrivateKey: hip.privateKey, requesterPublicKey: hiu.publicKey });
        expect(await decrypt({ encryptedData: enc, requesterNonce: hiu.nonce, senderNonce: hip.nonce, requesterPrivateKey: hiu.privateKey, senderPublicKey: hip.publicKey })).toBe(bundle);
        expect(decodePublicKey(hip.x509PublicKey).equals(decodePublicKey(hip.publicKey))).toBe(true);
        expect(hip.x509PublicKey).toHaveLength(requester.x509PublicKey.length);
        const stranger = generateKeyMaterial();
        await expect(decrypt({ encryptedData: enc, requesterNonce: hiu.nonce, senderNonce: hip.nonce, requesterPrivateKey: stranger.privateKey, senderPublicKey: hip.publicKey })).rejects.toThrow();
    });

    it('refuses a point that is not on the curve', () => {
        const bad = fromBase64(sender.publicKey);
        bad[64] ^= 1;
        expect(() => decodePublicKey(btoa(String.fromCharCode(...bad)))).toThrow();
    });
});
