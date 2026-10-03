import { afterEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import { hiuCallbacks, hiuStaffRoutes, dataPushRoutes, parseConsentRequest, consentInitBody } from './hiu.js';
import { buildDataPush } from './hip.js';
import { asStaff, fakeAbdm } from '../testing/abdmFake.js';

afterEach(() => vi.unstubAllGlobals());

const HIU = 'IN3310002300';
const app = new Hono().route('/', hiuCallbacks).route('/hiu/data-push', dataPushRoutes);
const request = (over = {}) => ({ facilityId: HIU, abhaAddress: 'Asha@sbx', purposeCode: 'CAREMGT', hiTypes: ['OPConsultation', 'prescription'], requester: { name: 'Dr Rao', identifier: { value: '71-0285-6047-2578' } }, ...over });

describe('consent request validation', () => {
    it('builds the consent request ABDM expects', () => {
        const { value } = parseConsentRequest(request(), Date.parse('2026-10-03T00:00:00Z'));
        expect(value.hiTypes).toEqual(['OPConsultation', 'Prescription']);
        const body = consentInitBody(value);
        expect(body.consent).toMatchObject({
            purpose: { code: 'CAREMGT', text: 'Care Management', refUri: 'http://terminology.hl7.org/ValueSet/v3-PurposeOfUse' },
            patient: { id: 'asha@sbx' }, hiu: { id: HIU },
            requester: { name: 'Dr Rao', identifier: { type: 'REGNO', value: '71-0285-6047-2578', system: 'https://www.mciindia.org' } },
            permission: { accessMode: 'VIEW', frequency: { unit: 'HOUR', value: 1, repeats: 0 } },
        });
        expect(parseConsentRequest(request({ purposeCode: 'SPY' })).error).toMatch(/Purpose/);
        expect(parseConsentRequest(request({ abhaAddress: '' })).error).toMatch(/ABHA/);
        expect(parseConsentRequest(request({ from: '2026-01-02', to: '2026-01-01' })).error).toMatch(/start before/);
        expect(parseConsentRequest(request({ requester: {} })).error).toMatch(/requester/);
    });
});

describe('HIU: from consent request to decrypted records', () => {
    it('requests consent, fetches the artefact, asks for data, decrypts the push and notifies', async () => {
        const abdm = fakeAbdm();
        abdm.own(HIU, 'clinic-1', { hiu: true });
        const staff = asStaff(hiuStaffRoutes, abdm.env);

        const created = await staff('/consent-requests', { method: 'POST', body: request() });
        expect(created.status).toBe(201);
        const init = abdm.last('/consent/v3/request/init');
        expect(init.headers['X-HIU-ID']).toBe(HIU);

        await abdm.callback(app, '/api/v3/hiu/consent/request/on-init', { consentRequest: { id: 'cr-1' }, response: { requestId: init.headers['REQUEST-ID'] } });
        await abdm.callback(app, '/api/v3/hiu/consent/request/notify', { notification: { consentRequestId: 'cr-1', status: 'GRANTED', consentArtefacts: [{ id: 'art-1' }] } });
        expect(abdm.last('/consent/v3/request/hiu/on-notify').body.acknowledgement).toEqual([{ status: 'OK', consentId: 'art-1' }]);
        const fetch = abdm.last('/consent/v3/fetch');
        expect(fetch.body).toEqual({ consentId: 'art-1' });

        const detail = {
            consentId: 'art-1', hip: { id: 'IN0000000001' }, hiu: { id: HIU }, patient: { id: 'asha@sbx' }, hiTypes: ['OPConsultation'],
            careContexts: [{ patientReference: 'p', careContextReference: 'cc-1' }],
            permission: { accessMode: 'VIEW', dateRange: { from: '2021-01-01T00:00:00Z', to: '2026-10-03T00:00:00Z' }, dataEraseAt: '2099-01-01T00:00:00Z', frequency: { unit: 'HOUR', value: 1, repeats: 0 } },
        };
        await abdm.callback(app, '/api/v3/hiu/consent/on-fetch', { consent: { status: 'GRANTED', consentDetail: detail, signature: 's' }, response: { requestId: fetch.headers['REQUEST-ID'] } });
        const dataRequest = abdm.last('/data-flow/v3/health-information/request');
        const hi = dataRequest.body.hiRequest;
        expect(hi.consent.id).toBe('art-1');
        expect(hi.dateRange).toEqual(detail.permission.dateRange);
        expect(hi.dataPushUrl).toMatch(/^https:\/\/gw\.example\/hiu\/data-push\/[A-Za-z0-9_-]{32}$/);
        expect(hi.keyMaterial.dhPublicKey.keyValue.length).toBeGreaterThan(400); // X.509, as NHA's wrapper sends

        await abdm.callback(app, '/api/v3/hiu/health-information/on-request', { hiRequest: { transactionId: 'txn-1', sessionStatus: 'REQUESTED' }, response: { requestId: dataRequest.headers['REQUEST-ID'] } });

        // The HIP side of this same gateway encrypts for that key and pushes to that URL.
        const bundle = { resourceType: 'Bundle', type: 'document', entry: [{ resource: { resourceType: 'Composition', title: 'Discharge' } }] };
        const push = await buildDataPush({ transactionId: 'txn-1', records: [{ bundle_json: JSON.stringify(bundle), care_context_reference: 'cc-1' }], keyMaterial: hi.keyMaterial });
        const path = new URL(hi.dataPushUrl).pathname;
        const pushed = await app.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(push) }, abdm.env);
        expect(pushed.status).toBe(202);

        const records = await staff('/records?abhaAddress=asha@sbx');
        expect(records.json.records).toHaveLength(1);
        expect(records.json.records[0]).toMatchObject({ consentId: 'art-1', hipId: 'IN0000000001', careContextReference: 'cc-1', bundle });
        const notify = abdm.last('/data-flow/v3/health-information/notify').body.notification;
        expect(notify).toMatchObject({ consentId: 'art-1', transactionId: 'txn-1', notifier: { type: 'HIU', id: HIU } });
        expect(notify.statusNotification.statusResponses).toEqual([{ careContextReference: 'cc-1', hiStatus: 'OK', description: 'Received' }]);

        // The key is gone: the same URL takes nothing more.
        expect((await app.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(push) }, abdm.env)).status).toBe(404);
        const list = await staff('/consent-requests?abhaAddress=asha@sbx');
        expect(list.json.consentRequests[0]).toMatchObject({ status: 'GRANTED', consentRequestId: 'cr-1', artefacts: [{ consentId: 'art-1', status: 'GRANTED' }] });

        // Revoked: the records are deleted.
        await abdm.callback(app, '/api/v3/hiu/consent/request/notify', { notification: { consentRequestId: 'cr-1', status: 'REVOKED', consentArtefacts: [{ id: 'art-1' }] } });
        expect((await staff('/records?abhaAddress=asha@sbx')).json.records).toEqual([]);
    });

    it('records a push it cannot decrypt as ERRORED, and keeps nothing', async () => {
        const abdm = fakeAbdm();
        abdm.own(HIU, 'clinic-1', { hiu: true });
        abdm.db.raw.prepare(`INSERT INTO hiu_consent_artefacts (consent_id, clinic_id, hiu_id, hip_id, status, data_erase_at) VALUES ('art', 'clinic-1', ?, 'IN0000000001', 'GRANTED', '2099-01-01T00:00:00Z')`).run(HIU);
        const { generateKeyMaterial } = await import('../lib/fidelius.js');
        const mine = generateKeyMaterial();
        abdm.db.raw.prepare(`INSERT INTO hiu_data_requests (id, clinic_id, hiu_id, consent_id, request_id, private_key, nonce) VALUES ('push-id-0123456789abcdefghijklmn', 'clinic-1', ?, 'art', 'r', ?, ?)`).run(HIU, mine.privateKey, mine.nonce);
        const stranger = generateKeyMaterial();
        const push = await buildDataPush({ transactionId: 't', records: [{ bundle_json: '{"resourceType":"Bundle"}', care_context_reference: 'cc' }], keyMaterial: { dhPublicKey: { keyValue: stranger.publicKey }, nonce: stranger.nonce } });
        await app.request('/hiu/data-push/push-id-0123456789abcdefghijklmn', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(push) }, abdm.env);
        expect(abdm.db.raw.prepare('SELECT COUNT(*) AS n FROM hiu_health_records').get().n).toBe(0);
        expect(abdm.last('/data-flow/v3/health-information/notify').body.notification.statusNotification).toMatchObject({ sessionStatus: 'FAILED', statusResponses: [{ careContextReference: 'cc', hiStatus: 'ERRORED' }] });
    });

    it('refuses a facility that does not receive records, and another clinic’s facility', async () => {
        const abdm = fakeAbdm();
        abdm.own(HIU, 'clinic-1');
        expect((await asStaff(hiuStaffRoutes, abdm.env)('/consent-requests', { method: 'POST', body: request() })).json.error).toMatch(/Receive records/);
        expect((await asStaff(hiuStaffRoutes, abdm.env, 'clinic-2')('/consent-requests', { method: 'POST', body: request() })).status).toBe(400);
        expect(abdm.calls.filter((c) => c.path === '/consent/v3/request/init')).toEqual([]);
    });
});
