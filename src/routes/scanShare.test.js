import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync, createSign } from 'node:crypto';
import { hipCallbackRoutes, scanShareRoutes, recordShare, shareDate, shareQrUrl, validHipName } from './scanShare.js';
import { resetJwksCache, verifyAbdmJwt } from '../lib/abdmJwt.js';
import { d1 } from '../testing/d1Sqlite.js';
import { Hono } from 'hono';

const MIGRATIONS = ['0018_add_doctor_roster_and_scan_share.sql'];
const namespace = (handler) => ({ idFromName: (n) => n, get: () => ({ fetch: handler }) });

// ABDM's signing key, as HIE-CM publishes it.
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS512', use: 'sig' };
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function abdmJwt(payload = {}, { kid = 'k1', key = privateKey } = {}) {
    const head = `${b64url({ alg: 'RS512', typ: 'JWT', kid })}.${b64url({ exp: Math.floor(Date.now() / 1000) + 600, clientId: 'ABDM', ...payload })}`;
    return `${head}.${createSign('RSA-SHA512').update(head).sign(key).toString('base64url')}`;
}

const patient = { abhaNumber: 91178386101251, abhaAddress: 'asha@sbx', name: 'Asha Rao', gender: 'F', dayOfBirth: '10', monthOfBirth: '10', yearOfBirth: '1994', address: { line: 'MG Road' }, phoneNumber: '9876543210' };
const share = (hipId = 'IN3310002300', context = '1', p = patient) => ({ intent: 'PROFILE_SHARE', metaData: { hipId, context, hprId: '', latitude: '', longitude: '' }, profile: { patient: p } });

let db, onShares, env;
beforeEach(() => {
    resetJwksCache();
    db = d1(MIGRATIONS);
    onShares = [];
    env = {
        ABDM_CLIENT_ID: 'SBX_1', ABDM_CLIENT_SECRET: 's', DB: db,
        SESSION_TOKEN: namespace(async () => Response.json({ accessToken: 'gateway-token' })),
    };
    vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
        if (String(url).endsWith('/gateway/v3/certs')) return init.headers?.['X-CM-ID'] ? Response.json({ keys: [jwk] }) : new Response('{}', { status: 401 });
        if (String(url).endsWith('/patient-share/v3/on-share')) { onShares.push(JSON.parse(init.body)); return new Response(null, { status: 202 }); }
        if (String(url).includes('MutipleHRPAddUpdateServices')) return Response.json({ message: 'ok' });
        throw new Error(`unexpected fetch ${url}`);
    }));
});
afterEach(() => vi.unstubAllGlobals());

const post = (body, headers = {}) => hipCallbackRoutes.request('/patient/share', { method: 'POST', headers: { 'content-type': 'application/json', 'REQUEST-ID': 'req-1', Authorization: `Bearer ${abdmJwt()}`, ...headers }, body: JSON.stringify(body) }, env);
const own = (clinic = 'clinic-1') => db.raw.prepare(`INSERT INTO hip_facilities (facility_id, clinic_id, facility_name) VALUES ('IN3310002300', ?, 'Asha Clinic')`).run(clinic);

describe('ABDM callback JWT', () => {
    it('accepts a token signed with a published key and refuses others', async () => {
        const certsUrl = 'https://hiecm/gateway/v3/certs';
        await expect(verifyAbdmJwt(abdmJwt({ x: 1 }), { certsUrl })).resolves.toMatchObject({ x: 1 });
        const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
        await expect(verifyAbdmJwt(abdmJwt({}, { key: other }), { certsUrl })).rejects.toThrow('Bad signature');
        await expect(verifyAbdmJwt(abdmJwt({}, { kid: 'nope' }), { certsUrl })).rejects.toThrow('unknown key');
        await expect(verifyAbdmJwt(abdmJwt({ exp: 1 }), { certsUrl })).rejects.toThrow('Expired');
        await expect(verifyAbdmJwt('garbage', { certsUrl })).rejects.toThrow();
    });
});

describe('Scan & Share callback', () => {
    it('refuses a callback without ABDM’s signature', async () => {
        own();
        const res = await post(share(), { Authorization: 'Bearer forged.token.here' });
        expect(res.status).toBe(401);
        expect(onShares).toEqual([]);
    });

    it('gives each share the next token at that counter and acknowledges it', async () => {
        own();
        expect((await post(share())).status).toBe(202);
        expect((await post(share('IN3310002300', '1', { ...patient, abhaAddress: 'ravi@sbx', abhaNumber: 91000000000002, name: 'Ravi' }))).status).toBe(202);
        expect((await post(share('IN3310002300', '2', { ...patient, abhaAddress: 'mala@sbx', abhaNumber: 91000000000003 }))).status).toBe(202);
        expect(onShares.map((o) => o.acknowledgement.profile.tokenNumber)).toEqual(['1', '2', '1']);
        expect(onShares[0]).toEqual({ acknowledgement: { abhaAddress: 'asha@sbx', status: 'success', profile: { context: '1', tokenNumber: '1', expiry: '180' } }, response: { requestId: 'req-1' } });
        const rows = db.raw.prepare('SELECT clinic_id, token_number, acknowledged FROM scan_share_requests ORDER BY created_at').all();
        expect(rows.every((r) => r.clinic_id === 'clinic-1' && r.acknowledged === 1)).toBe(true);
    });

    it('gives the same token when the same ABHA shares again while still waiting', async () => {
        own();
        await post(share());
        await post(share());
        expect(onShares.map((o) => o.acknowledgement.profile.tokenNumber)).toEqual(['1', '1']);
        expect(db.raw.prepare('SELECT COUNT(*) AS n FROM scan_share_requests').get().n).toBe(1);
    });

    it('answers ABDM with an error for a facility no clinic takes shares for', async () => {
        await post(share());
        expect(onShares).toEqual([{ error: { code: 'ABDM-9999', message: 'This facility does not take Scan & Share through ClinuxFlow' }, response: { requestId: 'req-1' } }]);
        expect(db.raw.prepare('SELECT COUNT(*) AS n FROM scan_share_requests').get().n).toBe(0);
    });

    it('keeps the share when on-share fails, with the error', async () => {
        own();
        fetch.mockImplementation(async (url) => (String(url).endsWith('/certs') ? Response.json({ keys: [jwk] }) : Response.json({ error: { message: 'down' } }, { status: 400 })));
        await post(share());
        expect(db.raw.prepare('SELECT acknowledged, ack_error FROM scan_share_requests').get()).toEqual({ acknowledged: 0, ack_error: 'ABDM 400' });
    });
});

describe('Scan & Share queue (staff)', () => {
    const app = (user) => new Hono().use('*', async (c, next) => { c.set('user', user); await next(); }).route('/', scanShareRoutes);
    const asClinic = (clinicId) => app({ clinicId, accountId: 'acc-1' });
    const req = (a, path, init = {}) => a.request(path, { headers: { 'content-type': 'application/json' }, ...init }, env);

    it('registers a facility for the clinic, and refuses one another clinic holds', async () => {
        const res = await req(asClinic('clinic-1'), '/facilities', { method: 'POST', body: JSON.stringify({ facilityId: 'in3310002300', facilityName: 'Asha Clinic', hipName: 'Asha Clinic', linkWithAbdm: true }) });
        expect(res.status).toBe(201);
        expect((await res.json()).facility).toMatchObject({ facilityId: 'IN3310002300', linkedWithAbdm: true });
        const linkCall = fetch.mock.calls.find(([u]) => String(u).includes('MutipleHRP'));
        expect(JSON.parse(linkCall[1].body)).toEqual({ facilityId: 'IN3310002300', facilityName: 'Asha Clinic', HRP: [{ bridgeId: 'SBX_1', hipName: 'Asha Clinic', type: 'HIP', active: true }] });
        expect((await req(asClinic('clinic-2'), '/facilities', { method: 'POST', body: JSON.stringify({ facilityId: 'IN3310002300' }) })).status).toBe(409);
        expect((await req(asClinic('clinic-1'), '/facilities', { method: 'POST', body: JSON.stringify({ facilityId: 'IN331', hipName: 'x' }) })).status).toBe(400);
        expect((await req(asClinic('clinic-1'), '/facilities', { method: 'POST', body: JSON.stringify({ facilityId: 'IN3310002300', hipName: 'A name far too long!', linkWithAbdm: true }) })).status).toBe(400);
    });

    it('lists only the clinic’s shares, masked, and hands a profile over exactly once', async () => {
        own();
        await post(share());
        const other = await req(asClinic('clinic-2'), '/queue');
        expect((await other.json()).shares).toEqual([]);

        const list = await (await req(asClinic('clinic-1'), '/queue?facilityId=IN3310002300')).json();
        expect(list.shares).toHaveLength(1);
        expect(list.shares[0]).toMatchObject({ tokenNumber: 1, name: 'Asha Rao', abhaAddress: 'asha@sbx', abhaNumber: '••••••1251', phone: '••••••3210', status: 'waiting', acknowledged: true });

        const id = list.shares[0].id;
        expect((await req(asClinic('clinic-2'), `/queue/${id}/claim`, { method: 'POST' })).status).toBe(404);
        const claimed = await (await req(asClinic('clinic-1'), `/queue/${id}/claim`, { method: 'POST' })).json();
        expect(claimed.share.patient).toMatchObject({ abhaAddress: 'asha@sbx', phoneNumber: '9876543210' });
        expect((await req(asClinic('clinic-1'), `/queue/${id}/claim`, { method: 'POST' })).status).toBe(409);
        expect(db.raw.prepare('SELECT profile_json, status FROM scan_share_requests').get()).toEqual({ profile_json: null, status: 'claimed' });
    });

    it('forgets shared profiles after a day', async () => {
        own();
        await recordShare(db, { clinicId: 'clinic-1', hipId: 'IN3310002300', context: '1', requestId: 'r', patient });
        db.raw.exec(`UPDATE scan_share_requests SET created_at = datetime('now', '-2 days')`);
        await req(asClinic('clinic-1'), '/queue');
        expect(db.raw.prepare('SELECT profile_json FROM scan_share_requests').get().profile_json).toBeNull();
    });
});

describe('helpers', () => {
    it('builds the facility QR and checks HIP names', () => {
        expect(shareQrUrl('https://phrsbx.abdm.gov.in', 'IN3310002300', '1')).toBe('https://phrsbx.abdm.gov.in/share-profile?hipid=IN3310002300&counterid=1');
        expect(validHipName('Asha Clinic')).toBe(true);
        expect(validHipName('Asha@Clinic')).toBe(false);
        expect(validHipName('x'.repeat(16))).toBe(false);
    });
    it('dates tokens in India time', () => {
        expect(shareDate(Date.parse('2026-10-02T20:00:00Z'))).toBe('2026-10-03');
    });
});
