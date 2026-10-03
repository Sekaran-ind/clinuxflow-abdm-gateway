import { afterEach, describe, expect, it } from 'vitest';
import { vi } from 'vitest';
import { Hono } from 'hono';
import { hipCallbacks, hipStaffRoutes, discoveryMatch, parseShare } from './hip.js';
import { asStaff, fakeAbdm, fakeToken } from '../testing/abdmFake.js';
import { decrypt, generateKeyMaterial } from '../lib/fidelius.js';

afterEach(() => vi.unstubAllGlobals());

const HIP = 'IN3310002300';
const app = new Hono().route('/', hipCallbacks);
const bundle = { resourceType: 'Bundle', type: 'document', entry: [{ resource: { resourceType: 'Composition', title: 'Consultation' } }] };
const share = (over = {}) => ({
    facilityId: HIP,
    patient: { reference: 'pat-1', name: 'Asha Rao', gender: 'female', yearOfBirth: 1994, abhaAddress: 'asha@sbx', abhaNumber: '91-1234-5678-9012', mobile: '+91 98765 43210' },
    careContext: { reference: 'visit-1', display: 'OP consultation 3 Oct', hiType: 'OPConsultation', date: '2026-10-03T05:00:00Z' },
    bundle,
    ...over,
});

describe('share validation', () => {
    it('normalises gender, ABHA number and mobile, and refuses what ABDM would', () => {
        const { value } = parseShare(share());
        expect(value).toMatchObject({ gender: 'F', abhaNumber: '91123456789012', mobile: '9876543210', hiType: 'OPConsultation', abhaAddress: 'asha@sbx' });
        expect(parseShare(share({ careContext: { reference: 'v', hiType: 'XRay' } })).error).toMatch(/hiType/);
        expect(parseShare(share({ patient: { ...share().patient, yearOfBirth: 1800 } })).error).toMatch(/year of birth/);
        expect(parseShare(share({ patient: { ...share().patient, abhaAddress: 'not an address' } })).error).toMatch(/ABHA address/);
        expect(parseShare(share({ bundle: { resourceType: 'Patient' } })).error).toMatch(/Bundle/);
    });
});

describe('HIP-initiated linking', () => {
    it('gets a link token, links the visit with it, and notifies ABDM', async () => {
        const abdm = fakeAbdm();
        abdm.own(HIP);
        const staff = asStaff(hipStaffRoutes, abdm.env);

        const res = await staff('/care-contexts', { method: 'POST', body: share() });
        expect(res.status).toBe(201);
        expect(res.json.careContext.linkStatus).toBe('awaiting_token');
        const gen = abdm.last('/v3/token/generate-token');
        expect(gen.body).toEqual({ abhaAddress: 'asha@sbx', name: 'Asha Rao', gender: 'F', yearOfBirth: 1994 });
        expect(gen.headers['X-HIP-ID']).toBe(HIP);

        // A second visit before the token arrives waits for the same token (no duplicate request: ABDM-1092).
        await staff('/care-contexts', { method: 'POST', body: share({ careContext: { reference: 'visit-2', hiType: 'Prescription', display: 'Rx' } }) });
        expect(abdm.calls.filter((c) => c.path === '/v3/token/generate-token')).toHaveLength(1);

        const linkToken = fakeToken({ abhaNumber: '91123456789012', exp: Math.floor(Date.now() / 1000) + 3600 });
        expect((await abdm.callback(app, '/api/v3/hip/token/on-generate-token', { abhaAddress: 'asha@sbx', linkToken, response: { requestId: gen.headers['REQUEST-ID'] } }, { 'X-HIP-ID': HIP })).status).toBe(202);
        const link = abdm.last('/hip/v3/link/carecontext');
        expect(link.headers['X-LINK-TOKEN']).toBe(linkToken);
        expect(link.body.abhaNumber).toBe('91123456789012');
        expect(link.body.patient).toEqual([
            { referenceNumber: 'pat-1', display: 'Asha Rao', careContexts: [{ referenceNumber: 'visit-1', display: 'OP consultation 3 Oct' }], hiType: 'OPConsultation', count: 1 },
            { referenceNumber: 'pat-1', display: 'Asha Rao', careContexts: [{ referenceNumber: 'visit-2', display: 'Rx' }], hiType: 'Prescription', count: 1 },
        ]);

        await abdm.callback(app, '/api/v3/link/on_carecontext', { abhaAddress: 'asha@sbx', status: 'Successfully Linked care context', response: { requestId: link.headers['REQUEST-ID'] } });
        const list = await staff('/care-contexts?patientReference=pat-1');
        expect(list.json.careContexts.map((c) => c.linkStatus)).toEqual(['linked', 'linked']);
        const notifies = abdm.calls.filter((c) => c.path === '/hip/v3/link/context/notify');
        expect(notifies.map((n) => n.body.notification.careContext.careContextReference).sort()).toEqual(['visit-1', 'visit-2']);
        expect(notifies[0].body.notification.patient.id).toBe('asha@sbx');

        // The next visit reuses the token at once.
        await staff('/care-contexts', { method: 'POST', body: share({ careContext: { reference: 'visit-3', hiType: 'OPConsultation', display: 'Follow-up' } }) });
        expect(abdm.calls.filter((c) => c.path === '/v3/token/generate-token')).toHaveLength(1);
        expect(abdm.last('/hip/v3/link/carecontext').body.patient[0].careContexts[0].referenceNumber).toBe('visit-3');
    });

    it('marks the visit failed with ABDM’s reason when the token is refused', async () => {
        const abdm = fakeAbdm();
        abdm.own(HIP);
        const staff = asStaff(hipStaffRoutes, abdm.env);
        await staff('/care-contexts', { method: 'POST', body: share() });
        const gen = abdm.last('/v3/token/generate-token');
        await abdm.callback(app, '/api/v3/hip/token/on-generate-token', { abhaAddress: 'asha@sbx', error: { code: 'ABDM-1207', message: 'Demographic details was invalid or doesn\'t exists' }, response: { requestId: gen.headers['REQUEST-ID'] } });
        const [cc] = (await staff('/care-contexts')).json.careContexts;
        expect(cc).toMatchObject({ linkStatus: 'failed', linkError: expect.stringContaining('ABDM-1207') });
    });

    it('refuses another clinic’s facility and keeps one clinic’s records from another', async () => {
        const abdm = fakeAbdm();
        abdm.own(HIP, 'clinic-2');
        expect((await asStaff(hipStaffRoutes, abdm.env)('/care-contexts', { method: 'POST', body: share() })).status).toBe(400);
    });

    it('refuses callbacks without HIE-CM’s signature', async () => {
        const abdm = fakeAbdm();
        const res = await app.request('/api/v3/link/on_carecontext', { method: 'POST', headers: { 'content-type': 'application/json', Authorization: 'Bearer x.y.z' }, body: '{}' }, abdm.env);
        expect(res.status).toBe(401);
    });
});

describe('user-initiated linking', () => {
    const patient = (over = {}) => ({ id: 'asha@sbx', verifiedIdentifiers: [{ type: 'MOBILE', value: '9876543210' }], unverifiedIdentifiers: [], name: 'Asha Rao', gender: 'F', yearOfBirth: 1994, ...over });

    it('matches on ABHA, or on a verified mobile only when demographics agree', () => {
        const rows = [{ id: 'a', abha_address: null, abha_number: null, mobile: '9876543210', gender: 'F', year_of_birth: 1994, patient_name: 'Asha Rao', patient_reference: 'p' }];
        expect(discoveryMatch(rows, patient({ id: 'other@sbx' })).matchedBy).toEqual(['MOBILE']);
        expect(discoveryMatch(rows, patient({ id: 'other@sbx', gender: 'M' })).hits).toEqual([]);
        expect(discoveryMatch(rows, patient({ id: 'other@sbx', name: 'Ravi Rao' })).hits).toEqual([]);
        expect(discoveryMatch(rows, patient({ id: 'other@sbx', yearOfBirth: 1980 })).hits).toEqual([]);
    });

    it('discovers unlinked visits, sends an OTP, and links them when it is confirmed', async () => {
        const abdm = fakeAbdm();
        abdm.own(HIP);
        const staff = asStaff(hipStaffRoutes, abdm.env);
        // Shared without an ABHA address: stays unlinked until the patient finds it.
        await staff('/care-contexts', { method: 'POST', body: share({ patient: { ...share().patient, abhaAddress: undefined, abhaNumber: undefined } }) });

        await abdm.callback(app, '/api/v3/hip/patient/care-context/discover', { transactionId: 'txn-1', patient: patient() }, { 'X-HIP-ID': HIP });
        const disc = abdm.last('/user-initiated-linking/v3/patient/care-context/on-discover');
        expect(disc.body.patient[0].careContexts).toEqual([{ referenceNumber: 'visit-1', display: 'OP consultation 3 Oct' }]);
        expect(disc.body.matchedBy).toEqual(['MOBILE']);

        await abdm.callback(app, '/api/v3/hip/link/care-context/init', { transactionId: 'txn-1', abhaAddress: 'asha@sbx', patient: [{ referenceNumber: 'pat-1', careContexts: [{ referenceNumber: 'visit-1' }], hiType: 'OPConsultation', count: 1 }] }, { 'X-HIP-ID': HIP });
        const init = abdm.last('/user-initiated-linking/v3/link/care-context/on-init');
        expect(init.body.link).toMatchObject({ authenticationType: 'MEDIATE', meta: { communicationMedium: 'MOBILE', communicationHint: 'OTP' } });
        // Sandbox without an SMS provider: staff can read the OTP out.
        const [lr] = (await staff('/link-requests')).json.linkRequests;
        expect(lr.otpDelivery).toBe('sandbox');
        expect(lr.sandboxOtp).toMatch(/^\d{6}$/);

        const wrong = lr.sandboxOtp === '000000' ? '111111' : '000000';
        await abdm.callback(app, '/api/v3/hip/link/care-context/confirm', { confirmation: { linkRefNumber: init.body.link.referenceNumber, token: wrong } }, { 'X-HIP-ID': HIP });
        expect(abdm.last('/user-initiated-linking/v3/link/care-context/on-confirm').body.error.message).toBe('Invalid OTP');
        await abdm.callback(app, '/api/v3/hip/link/care-context/confirm', { confirmation: { linkRefNumber: init.body.link.referenceNumber, token: lr.sandboxOtp } }, { 'X-HIP-ID': HIP });
        const conf = abdm.last('/user-initiated-linking/v3/link/care-context/on-confirm');
        expect(conf.body.patient[0].careContexts[0].referenceNumber).toBe('visit-1');
        expect((await staff('/care-contexts')).json.careContexts[0]).toMatchObject({ linkStatus: 'linked', linkedVia: 'patient', abhaAddress: 'asha@sbx' });

        // Already linked: a second discovery finds nothing new.
        await abdm.callback(app, '/api/v3/hip/patient/care-context/discover', { transactionId: 'txn-2', patient: patient() }, { 'X-HIP-ID': HIP });
        expect(abdm.last('/user-initiated-linking/v3/patient/care-context/on-discover').body.error.code).toBe('ABDM-1010');
    });

    it('sends the OTP through the SMS webhook when one is configured', async () => {
        const sms = [];
        const abdm = fakeAbdm({ external: async (url, init) => { sms.push({ url, body: JSON.parse(init.body) }); return new Response(null, { status: 200 }); } });
        abdm.env.SMS_WEBHOOK_URL = 'https://sms.example/send';
        abdm.own(HIP);
        await asStaff(hipStaffRoutes, abdm.env)('/care-contexts', { method: 'POST', body: share() });
        await abdm.callback(app, '/api/v3/hip/patient/care-context/discover', { transactionId: 't', patient: patient() }, { 'X-HIP-ID': HIP });
        await abdm.callback(app, '/api/v3/hip/link/care-context/init', { transactionId: 't', patient: [{ careContexts: [{ referenceNumber: 'visit-1' }] }] }, { 'X-HIP-ID': HIP });
        expect(sms[0].body.to).toBe('9876543210');
        expect(sms[0].body.message).toMatch(/^\d{6} is your OTP/);
    });
});

describe('consent and data transfer', () => {
    async function linkedVisit(abdm) {
        abdm.own(HIP);
        const staff = asStaff(hipStaffRoutes, abdm.env);
        await staff('/care-contexts', { method: 'POST', body: share() });
        abdm.db.raw.prepare(`UPDATE hip_care_contexts SET link_status = 'linked'`).run();
        return staff;
    }
    const consent = (status = 'GRANTED', over = {}) => ({
        notification: {
            status, consentId: 'consent-1', signature: 'sig', grantAcknowledgement: false,
            consentDetail: {
                schemaVersion: 'v3', consentId: 'consent-1', createdAt: '2026-10-03T00:00:00Z', patient: { id: 'asha@sbx' },
                careContexts: [{ patientReference: 'pat-1', careContextReference: 'visit-1' }],
                purpose: { text: 'Care Management', code: 'CAREMGT', refUri: 'x' }, hip: { id: HIP }, hiu: { id: 'IN9999999999' },
                requester: { name: 'Dr Rao' }, consentManager: { id: 'sbx' }, hiTypes: ['OPCONSULTATION'],
                permission: { accessMode: 'VIEW', dateRange: { from: '2020-01-01T00:00:00Z', to: '2030-01-01T00:00:00Z' }, dataEraseAt: '2099-01-01T00:00:00Z', frequency: { unit: 'HOUR', value: 1, repeats: 0 } },
                ...over,
            },
        },
    });

    it('acknowledges the consent, encrypts the visit for the HIU and reports it delivered', async () => {
        const pushes = [];
        const abdm = fakeAbdm({ external: async (url, init) => { pushes.push({ url, init, body: JSON.parse(init.body) }); return new Response(null, { status: 202 }); } });
        await linkedVisit(abdm);
        await abdm.callback(app, '/api/v3/consent/request/hip/notify', consent(), { 'X-HIP-ID': HIP });
        expect(abdm.last('/consent/v3/request/hip/on-notify').body.acknowledgement).toEqual({ status: 'OK', consentId: 'consent-1' });

        const hiu = generateKeyMaterial();
        const request = { transactionId: 'txn-9', hiRequest: { consent: { id: 'consent-1' }, dateRange: { from: '2026-01-01T00:00:00Z', to: '2026-12-31T00:00:00Z' }, dataPushUrl: 'https://hiu.example/push', keyMaterial: { cryptoAlg: 'ECDH', curve: 'Curve25519', dhPublicKey: { expiry: '2099-01-01T00:00:00Z', parameters: 'Curve25519/32byte random key', keyValue: hiu.x509PublicKey }, nonce: hiu.nonce } } };
        await abdm.callback(app, '/api/v3/hip/health-information/request', request, { 'X-HIP-ID': HIP });
        expect(abdm.last('/data-flow/v3/health-information/hip/on-request').body.hiRequest).toEqual({ transactionId: 'txn-9', sessionStatus: 'ACKNOWLEDGED' });

        expect(pushes).toHaveLength(1);
        expect(pushes[0].init.headers.Authorization).toBeUndefined(); // never this gateway's ABDM token to a HIU's URL
        const push = pushes[0].body;
        expect(push).toMatchObject({ pageNumber: 0, pageCount: 1, transactionId: 'txn-9', keyMaterial: { cryptoAlg: 'ECDH', curve: 'Curve25519' } });
        const plain = await decrypt({ encryptedData: push.entries[0].content, requesterNonce: hiu.nonce, senderNonce: push.keyMaterial.nonce, requesterPrivateKey: hiu.privateKey, senderPublicKey: push.keyMaterial.dhPublicKey.keyValue });
        expect(JSON.parse(plain)).toEqual(bundle);
        expect(push.entries[0]).toMatchObject({ media: 'application/fhir+json', careContextReference: 'visit-1' });

        const notify = abdm.last('/data-flow/v3/health-information/notify').body.notification;
        expect(notify).toMatchObject({ consentId: 'consent-1', transactionId: 'txn-9', notifier: { type: 'HIP', id: HIP } });
        expect(notify.statusNotification).toEqual({ sessionStatus: 'TRANSFERRED', hipId: HIP, statusResponses: [{ careContextReference: 'visit-1', hiStatus: 'DELIVERED', description: 'Delivered' }] });
    });

    it('refuses data requests under a revoked consent, and shares nothing outside it', async () => {
        const pushes = [];
        const abdm = fakeAbdm({ external: async (url, init) => { pushes.push(init); return new Response(null, { status: 202 }); } });
        const staff = await linkedVisit(abdm);
        await abdm.callback(app, '/api/v3/consent/request/hip/notify', consent(), { 'X-HIP-ID': HIP });
        await abdm.callback(app, '/api/v3/consent/request/hip/notify', consent('REVOKED'), { 'X-HIP-ID': HIP });
        const hiu = generateKeyMaterial();
        await abdm.callback(app, '/api/v3/hip/health-information/request', { transactionId: 't', hiRequest: { consent: { id: 'consent-1' }, dataPushUrl: 'https://hiu.example/push', keyMaterial: { dhPublicKey: { keyValue: hiu.publicKey }, nonce: hiu.nonce } } }, { 'X-HIP-ID': HIP });
        expect(abdm.last('/data-flow/v3/health-information/hip/on-request').body.error.message).toBe('Consent is REVOKED');
        expect(pushes).toEqual([]);
        const { json } = await staff('/consents');
        expect(json.consents[0].status).toBe('REVOKED');
        expect(json.transfers[0]).toMatchObject({ status: 'refused', error: 'Consent is REVOKED' });
    });

    it('only shares the record types and dates the consent covers', async () => {
        const pushes = [];
        const abdm = fakeAbdm({ external: async (url, init) => { pushes.push(JSON.parse(init.body)); return new Response(null, { status: 202 }); } });
        await linkedVisit(abdm);
        await abdm.callback(app, '/api/v3/consent/request/hip/notify', consent('GRANTED', { hiTypes: ['Prescription'] }), { 'X-HIP-ID': HIP });
        const hiu = generateKeyMaterial();
        await abdm.callback(app, '/api/v3/hip/health-information/request', { transactionId: 't', hiRequest: { consent: { id: 'consent-1' }, dataPushUrl: 'https://hiu.example/push', keyMaterial: { dhPublicKey: { keyValue: hiu.publicKey }, nonce: hiu.nonce } } }, { 'X-HIP-ID': HIP });
        expect(pushes).toEqual([]);
        expect(abdm.last('/data-flow/v3/health-information/notify').body.notification.statusNotification.sessionStatus).toBe('FAILED');
    });
});
