// ABDM M1 lanes added for the clinic: HPR search (doctor roster), face-auth and driving-licence
// ABHA creation, ABHA-address OTP verification, and the ABHA card with the patient's session.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { constants, generateKeyPairSync, privateDecrypt } from 'node:crypto';
import { Hono } from 'hono';
import { abhaRoutes } from './abha.js';
import { hprRoutes, hprMatch, normaliseHprIdNumber } from './hpr.js';
import { attestHpr, readAttestation } from '../lib/hprAttestation.js';

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKeyB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const namespace = (handler) => ({ idFromName: (n) => n, get: () => ({ fetch: handler }) });
const env = {
    ABDM_CLIENT_ID: 'id', ABDM_CLIENT_SECRET: 'secret', JWT_SECRET: 'shared-secret',
    SESSION_TOKEN: namespace(async () => Response.json({ accessToken: 'gateway-token' })),
    REGISTRATION_TXN: namespace(async () => Response.json({ allowed: true, attempts: 1 })),
};
const decrypt = (v) => privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, Buffer.from(v, 'base64')).toString();
const json = (body) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

/** Stubs fetch: the ABHA certificate, then `answer(url, body)` for everything else; records calls. */
function stub(answer) {
    const calls = [];
    vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
        if (String(url).endsWith('/profile/public/certificate')) return Response.json({ publicKey: publicKeyB64 });
        const body = init.body ? JSON.parse(init.body) : undefined;
        calls.push({ url: String(url), body, headers: init.headers });
        return answer(String(url), body);
    }));
    return calls;
}
afterEach(() => vi.unstubAllGlobals());

const asUser = (routes) => new Hono().use('*', async (c, next) => { c.set('user', { clinicId: 'clinic-1', accountId: 'acc-1' }); await next(); }).route('/', routes);

describe('HPR search', () => {
    it('normalises HPR numbers and hits', () => {
        expect(normaliseHprIdNumber('71028560472578')).toBe('71-0285-6047-2578');
        expect(normaliseHprIdNumber('71-0285')).toBeNull();
        expect(hprMatch({ hpr_id: '71-1', name: 'A', hpr_category: 'nurse', application_status: 'Pending', active: 'true' })).toMatchObject({ hprIdNumber: '71-1', categoryId: '2', applicationStatus: 'Pending', active: true });
    });

    it('looks an address up with searchByHprId and signs what it found for this clinic', async () => {
        const calls = stub(() => Response.json({ hprIdNumber: '71-0285-6047-2578', name: 'Prabu Segaran', hprId: 'prabu.segaran@hpr.abdm', categoryId: '1', subCategoryId: '1' }));
        const res = await asUser(hprRoutes).request('/search', json({ hprId: 'prabu.segaran@hpr.abdm' }), env);
        const { matches } = await res.json();
        expect(calls[0].url).toBe('https://apihspsbx.abdm.gov.in/v4/int/v1/search/searchByHprId/prabu.segaran%40hpr.abdm');
        expect(matches[0]).toMatchObject({ hprIdNumber: '71-0285-6047-2578', name: 'Prabu Segaran', categoryId: '1' });
        const att = await readAttestation('shared-secret', matches[0].attestation);
        expect(att).toMatchObject({ kind: 'hpr-attestation', clinic: 'clinic-1', hprIdNumber: '71-0285-6047-2578', hprId: 'prabu.segaran@hpr.abdm' });
        // Never passes as a session token (which needs sub + clinicId).
        expect(att.sub).toBeUndefined();
        expect(att.clinicId).toBeUndefined();
    });

    it('looks a 14-digit number up with searchByHprId, then fetch-professional-info', async () => {
        const hit = { hprIdNumber: '71-0285-6047-2578', name: 'Prabu', hprId: 'p@hpr.abdm', categoryId: '1' };
        let calls = stub(() => Response.json(hit));
        let { matches } = await (await asUser(hprRoutes).request('/search', json({ hprId: '71 0285 6047 2578' }), env)).json();
        expect(calls[0].url).toMatch(/\/v1\/search\/searchByHprId\/71-0285-6047-2578$/);
        expect(calls).toHaveLength(1);
        expect(matches[0]).toMatchObject({ hprIdNumber: '71-0285-6047-2578', categoryId: '1' });

        calls = stub((url) => (url.includes('searchByHprId')
            ? Response.json({ message: 'not found' }, { status: 404 })
            : Response.json({ practitioners: [[{ hpr_id: '71-0285-6047-2578', name: 'Prabu', hpr_category: 'doctor', application_status: 'Approved', active: 'true' }]] })));
        ({ matches } = await (await asUser(hprRoutes).request('/search', json({ hprId: '71028560472578' }), env)).json());
        expect(calls[1].body).toEqual({ practitioner: { id: '71-0285-6047-2578', name: '', contactNumber: '', state: '', registrationNumber: '' } });
        expect(matches[0]).toMatchObject({ hprIdNumber: '71-0285-6047-2578', categoryId: '1', applicationStatus: 'Approved' });
    });

    it('searches by mobile, and treats HPR’s 4xx as no match', async () => {
        stub(() => Response.json([{ hprIdNumber: '71-1', name: 'A' }, { hprIdNumber: '71-2', name: 'B' }]));
        expect((await (await asUser(hprRoutes).request('/search', json({ mobile: '9876543210' }), env)).json()).matches).toHaveLength(2);
        stub(() => Response.json({ message: 'not found' }, { status: 404 }));
        const res = await asUser(hprRoutes).request('/search', json({ hprId: 'nobody@hpr.abdm' }), env);
        expect(res.status).toBe(200);
        expect((await res.json()).matches).toEqual([]);
        expect((await asUser(hprRoutes).request('/search', json({ mobile: '123' }), env)).status).toBe(400);
    });

    it('rejects an attestation signed with another secret or expired', async () => {
        const t = await attestHpr('shared-secret', 'c', { hprIdNumber: '71-1' }, Date.now() - 2 * 3600 * 1000);
        await expect(readAttestation('shared-secret', t)).rejects.toThrow();
        await expect(readAttestation('other', await attestHpr('shared-secret', 'c', { hprIdNumber: '71-1' }))).rejects.toThrow();
    });
});

describe('ABHA creation by face authentication', () => {
    it('init gives the ABHA-app QR; enrol sends the encrypted Aadhaar with face_auth', async () => {
        const calls = stub((url) => {
            if (url.endsWith('/enrollment/enrol/auth/init')) return Response.json({ txnId: 'tx-face' });
            if (url.endsWith('/enrollment/enrol/capturePID')) return Response.json({ status: 'COMPLETE', txnId: 'tx-face' });
            return Response.json({ txnId: 'tx-face', tokens: { token: 'abha-tok' }, ABHAProfile: { ABHANumber: '91-1', firstName: 'Asha', photo: 'xx' } });
        });
        const init = await (await abhaRoutes.request('/enrollment/face/init', json({}), env)).json();
        expect(init).toMatchObject({ txnId: 'tx-face', qrUrl: 'https://phrsbx.abdm.gov.in/face-auth?txnId=tx-face' });
        expect(calls[0].body).toEqual({ scope: ['abha-enrol', 'face-auth'] });
        expect(await (await abhaRoutes.request('/enrollment/face/status', json({ txnId: 'tx-face' }), env)).json()).toMatchObject({ status: 'COMPLETE' });
        expect(calls[1].body).toEqual({ scope: ['abha-enrol', 'face-verify'], txnId: 'tx-face' });
        const out = await (await abhaRoutes.request('/enrollment/face/enrol', json({ txnId: 'tx-face', aadhaar: '123412341234', mobile: '9876543210' }), env)).json();
        const sent = calls[2].body;
        expect(sent.authData.authMethods).toEqual(['face_auth']);
        expect(decrypt(sent.authData.face.aadhaar)).toBe('123412341234');
        expect(sent.authData.face).toMatchObject({ txnId: 'tx-face', mobile: '9876543210' });
        expect(sent.consent).toEqual({ code: 'abha-enrollment', version: '1.4' });
        expect(out).toMatchObject({ abhaToken: 'abha-tok', profile: { ABHANumber: '91-1' } });
        expect(out.profile.photo).toBeUndefined();
    });
});

describe('ABHA creation by driving licence', () => {
    it('mobile OTP with dl-flow, then the licence', async () => {
        const calls = stub((url) => {
            if (url.endsWith('/enrollment/request/otp')) return Response.json({ txnId: 'tx-dl', message: 'sent' });
            if (url.endsWith('/enrollment/auth/byAbdm')) return Response.json({ txnId: 'tx-dl', authResult: 'success' });
            return Response.json({ EnrolProfile: { enrolmentNumber: '91-6087-5423-0001', enrolmentState: 'VERIFIED', phrAddress: ['91608754230001@sbx'] } });
        });
        await abhaRoutes.request('/enrollment/dl/mobile-otp', json({ mobile: '9876543210' }), env);
        expect(calls[0].body).toMatchObject({ scope: ['abha-enrol', 'mobile-verify', 'dl-flow'], loginHint: 'mobile', otpSystem: 'abdm' });
        expect(decrypt(calls[0].body.loginId)).toBe('9876543210');
        await abhaRoutes.request('/enrollment/dl/verify-mobile-otp', json({ txnId: 'tx-dl', otp: '123456' }), env);
        expect(calls[1].body.scope).toEqual(['abha-enrol', 'mobile-verify', 'dl-flow']);
        expect(calls[1].body.authData.otp.timeStamp).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
        const doc = { txnId: 'tx-dl', documentId: 'MH1320140019054', firstName: 'Anand', lastName: 'S', dob: '1996-07-15', gender: 'M', frontSidePhoto: 'AAA', backSidePhoto: 'BBB', address: 'Pune', state: 'Maharashtra', district: 'Pune', pinCode: '413005' };
        const out = await (await abhaRoutes.request('/enrollment/dl/document', json(doc), env)).json();
        expect(calls[2].body).toMatchObject({ ...doc, documentType: 'DRIVING_LICENCE', middleName: '', consent: { code: 'abha-enrollment', version: '1.4' } });
        expect(out.enrolment.enrolmentNumber).toBe('91-6087-5423-0001');
        expect((await abhaRoutes.request('/enrollment/dl/document', json({ txnId: 'x' }), env)).status).toBe(400);
    });
});

describe('ABHA address verification by OTP, and the ABHA card', () => {
    it('logs in with the address and returns a PHR session', async () => {
        const calls = stub((url) => url.endsWith('/request/otp')
            ? Response.json({ txnId: 'tx-a', message: 'OTP sent' })
            : Response.json({ tokens: { token: 'phr-tok' }, users: [{ abhaAddress: 'asha@sbx', fullName: 'Asha', profilePhoto: 'xx' }] }));
        await abhaRoutes.request('/login/address/request-otp', json({ abhaAddress: 'Asha@SBX' }), env);
        expect(calls[0].url).toMatch(/\/phr\/web\/login\/abha\/request\/otp$/);
        expect(decrypt(calls[0].body.loginId)).toBe('asha@sbx');
        const out = await (await abhaRoutes.request('/login/address/verify-otp', json({ txnId: 'tx-a', otp: '123456' }), env)).json();
        expect(out).toEqual({ success: true, abhaToken: 'phr-tok', tokenKind: 'phr', account: { abhaAddress: 'asha@sbx', fullName: 'Asha' } });
        expect((await abhaRoutes.request('/login/address/request-otp', json({ abhaAddress: 'asha' }), env)).status).toBe(400);
    });

    it('fetches the card with the patient’s token and kind', async () => {
        const calls = stub(() => new Response(new Uint8Array([137, 80, 78, 71]), { headers: { 'content-type': 'image/png' } }));
        const out = await (await abhaRoutes.request('/session/card', { headers: { 'X-ABHA-Token': 'phr-tok', 'X-ABHA-Kind': 'phr' } }, env)).json();
        expect(calls[0].url).toMatch(/\/phr\/web\/login\/profile\/abha\/phr-card$/);
        expect(calls[0].headers['X-token']).toBe('Bearer phr-tok');
        expect(out).toEqual({ success: true, contentType: 'image/png', data: Buffer.from([137, 80, 78, 71]).toString('base64') });
        expect((await abhaRoutes.request('/session/card', {}, env)).status).toBe(400);
    });
});
