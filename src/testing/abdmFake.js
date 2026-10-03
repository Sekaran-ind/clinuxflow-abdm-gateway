// Tests only: a stand-in for ABDM's HIE-CM. It signs callbacks the way HIE-CM does (RS512 with a
// key published at /gateway/v3/certs) and records every call the gateway makes to HIE-CM, so a
// test can drive a flow callback by callback and read what the gateway answered.
import { vi } from 'vitest';
import { generateKeyPairSync, createSign } from 'node:crypto';
import { Hono } from 'hono';
import { resetJwksCache } from '../lib/abdmJwt.js';
import { d1 } from './d1Sqlite.js';

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS512', use: 'sig' };
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

export function abdmJwt(payload = {}) {
    const head = `${b64url({ alg: 'RS512', typ: 'JWT', kid: 'k1' })}.${b64url({ exp: Math.floor(Date.now() / 1000) + 600, clientId: 'ABDM', ...payload })}`;
    return `${head}.${createSign('RSA-SHA512').update(head).sign(privateKey).toString('base64url')}`;
}

/** An unsigned JWT-shaped token with these claims (link tokens: the gateway only reads them). */
export const fakeToken = (claims) => `${b64url({ alg: 'none' })}.${b64url(claims)}.sig`;

export const MIGRATIONS = ['0018_add_doctor_roster_and_scan_share.sql', '0019_add_abdm_m2_m3_scan_pay_running_token.sql'];
const namespace = (handler) => ({ idFromName: (n) => n, get: () => ({ fetch: handler }) });

/**
 * @param {object} [opts]
 * @param {(path: string, body: any, init: object) => Response|undefined} [opts.respond] - answer a HIE-CM call (default 202)
 * @param {(url: string, init: object) => Promise<Response>|Response} [opts.external] - any other URL (data push, SMS)
 */
export function fakeAbdm({ respond, external } = {}) {
    resetJwksCache();
    const db = d1(MIGRATIONS);
    const calls = [];
    const env = {
        ABDM_CLIENT_ID: 'SBX_1', ABDM_CLIENT_SECRET: 's', DB: db, ABDM_ENV: 'sandbox',
        ABDM_PUBLIC_BASE_URL: 'https://gw.example',
        SESSION_TOKEN: namespace(async () => Response.json({ accessToken: 'gateway-token' })),
    };
    vi.stubGlobal('fetch', vi.fn(async (url, init = {}) => {
        const u = String(url);
        if (u.endsWith('/gateway/v3/certs')) return Response.json({ keys: [jwk] });
        const hiecm = u.match(/^https:\/\/dev\.abdm\.gov\.in\/api\/hiecm(\/.*)$/) || u.match(/^https:\/\/facilitysbx\.abdm\.gov\.in(\/.*)$/);
        if (hiecm) {
            const body = init.body ? JSON.parse(init.body) : null;
            calls.push({ path: hiecm[1], method: init.method, headers: init.headers, body });
            return respond?.(hiecm[1], body, init) || new Response(null, { status: 202 });
        }
        if (external) return external(u, init);
        throw new Error(`unexpected fetch ${u}`);
    }));
    /** POSTs a signed HIE-CM callback into `app`. */
    const callback = (app, path, body, headers = {}) => app.request(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'REQUEST-ID': crypto.randomUUID(), Authorization: `Bearer ${abdmJwt()}`, ...headers },
        body: JSON.stringify(body),
    }, env);
    const last = (path) => calls.filter((c) => c.path === path).at(-1);
    const own = (facilityId, clinicId = 'clinic-1', extra = {}) => db.raw
        .prepare(`INSERT INTO hip_facilities (facility_id, clinic_id, facility_name, hip_name, hiu_enabled, scan_pay_enabled, upi_vpa) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .run(facilityId, clinicId, 'Asha Clinic', 'Asha Clinic', extra.hiu ? 1 : 0, extra.pay ? 1 : 0, extra.upi || null);
    return { db, env, calls, callback, last, own };
}

/** A staff request through a router, as a signed-in clinic user (what the /hie/* session gate sets). */
export function asStaff(router, env, clinicId = 'clinic-1', accountId = 'acct-1') {
    const app = new Hono();
    app.use('*', async (c, next) => { c.set('user', { clinicId, accountId }); await next(); });
    app.route('/', router);
    return async (path, { method = 'GET', body } = {}) => {
        const res = await app.request(path, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }, env);
        return { status: res.status, json: await res.json().catch(() => null) };
    };
}
