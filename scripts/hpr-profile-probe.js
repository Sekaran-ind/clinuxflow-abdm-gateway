// Finds which part of an HPR professional-profile request HPR's sandbox refuses with its generic
// HIS-500 ("An unexpected error has occurred"), which names no field.
//
//   1. In the HPR journey's review step, "Download the request" saves hpr-profile-request.json
//      (the register-professional-new body, without your token).
//   2. node scripts/hpr-profile-probe.js path/to/hpr-profile-request.json
//
// It signs in with your HPR ID and password (asked here, not stored, sent only to ABDM), then sends
// the request as it is and in variants, one at a time, and asks before each. A variant HPR accepts
// REALLY SUBMITS your profile for verification (sandbox), so it stops at the first success and says
// which change made the difference. Each answer is printed with ABDM's REQUEST-ID for NHA support.
//
// ABDM_CLIENT_ID / ABDM_CLIENT_SECRET come from the environment or this repo's .dev.vars.
import { readFileSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline';

const HOST = process.env.ABDM_HPR_HFR_BASE_URL || 'https://apihspsbx.abdm.gov.in/v4/int';
const SESSIONS = process.env.ABDM_GATEWAY_BASE_URL || 'https://dev.abdm.gov.in/api/hiecm/gateway/v3';
const X_CM_ID = process.env.ABDM_X_CM_ID || 'sbx';

function devVars() {
    const p = new URL('../.dev.vars', import.meta.url);
    if (!existsSync(p)) return {};
    return Object.fromEntries(readFileSync(p, 'utf8').split('\n').map((l) => l.match(/^([A-Z_]+)\s*=\s*"?(.*?)"?\s*$/)).filter(Boolean).map((m) => [m[1], m[2]]));
}
const vars = { ...devVars(), ...process.env };

const file = process.argv[2];
if (!file) {
    console.error('Usage: node scripts/hpr-profile-probe.js hpr-profile-request.json');
    process.exit(1);
}
const original = JSON.parse(readFileSync(file, 'utf8'));
delete original.hprToken;

const rl = createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((r) => rl.question(q, r));
function askHidden(q) {
    return new Promise((resolve) => {
        const write = rl._writeToOutput;
        rl._writeToOutput = (s) => (s.includes(q) ? write.call(rl, s) : write.call(rl, '*'));
        rl.question(q, (a) => { rl._writeToOutput = write; process.stdout.write('\n'); resolve(a); });
    });
}

const headers = (extra = {}) => ({ 'Content-Type': 'application/json', 'REQUEST-ID': crypto.randomUUID(), TIMESTAMP: new Date().toISOString(), 'X-CM-ID': X_CM_ID, ...extra });
async function json(res) {
    const t = await res.text();
    try { return JSON.parse(t); } catch { return t; }
}

// ── Variants, least data removed first ───────────────────────────────────────────────────────
const clone = (o) => JSON.parse(JSON.stringify(o));
const pi = (b) => b.practitioner.personalInformation;
const reg = (b) => b.practitioner.registrationAcademic?.registrationData?.[0] || {};
const dmy = (d) => (/^\d{4}-\d{2}-\d{2}/.test(d || '') ? `${d.slice(8, 10)}-${d.slice(5, 7)}-${d.slice(0, 4)}` : d);
const stripFiles = (b) => {
    const r = reg(b);
    delete r.registrationCertificate;
    r.proofOfNameChangeCertificate = '';
    for (const q of r.qualifications || []) { delete q.degreeCertificate; q.proofOfNameChangeCertificate = ''; }
    if (b.practitioner.currentWorkDetails) b.practitioner.currentWorkDetails.certificateAttachment = '';
};
const VARIANTS = [
    ['as downloaded', () => {}],
    ['date of birth as dd-mm-yyyy', (b) => { pi(b).dateOfBirth = dmy(pi(b).dateOfBirth); }],
    ['date of birth as an ISO date-time', (b) => { if (/^\d{4}-\d{2}-\d{2}$/.test(pi(b).dateOfBirth)) pi(b).dateOfBirth = `${pi(b).dateOfBirth}T00:00:00.000Z`; }],
    ['no date of birth or gender (the 2023 sample sends neither)', (b) => { delete pi(b).dateOfBirth; delete pi(b).gender; }],
    ['no attachments (certificates can be uploaded later)', stripFiles],
    ['no facility declaration', (b) => { delete b.practitioner.currentWorkDetails?.facilityDeclarationData; }],
    ['minimal: all of the above', (b) => { delete pi(b).dateOfBirth; delete pi(b).gender; stripFiles(b); delete b.practitioner.currentWorkDetails?.facilityDeclarationData; }],
];

console.log(`Request: ${file}\nProfessional: ${pi(original).firstName} ${pi(original).lastName || ''} (${original.practitioner.healthProfessionalType})\n`);
const hprId = (await ask('HPR ID (name@hpr.abdm): ')).trim();
const password = await askHidden('HPR password: ');

const session = await fetch(`${SESSIONS}/sessions`, { method: 'POST', headers: headers(), body: JSON.stringify({ clientId: vars.ABDM_CLIENT_ID, clientSecret: vars.ABDM_CLIENT_SECRET, grantType: 'client_credentials' }) });
const { accessToken } = await json(session);
if (!accessToken) throw new Error(`ABDM session failed (HTTP ${session.status})`);
const auth = { Authorization: `Bearer ${accessToken}` };

const login = await fetch(`${HOST}/api/v1/auth/authPassword`, { method: 'POST', headers: headers(auth), body: JSON.stringify({ idType: 'hpr_id', domainName: '@hpr.abdm', hprId, password }) });
const { token: hprToken } = await json(login);
if (!hprToken) { console.error(`HPR sign-in failed (HTTP ${login.status}).`); process.exit(1); }
console.log('Signed in to HPR.\n');

async function send(path, body) {
    const h = headers(auth);
    const res = await fetch(`${HOST}/apis/v1/doctors/${path}`, { method: 'POST', headers: h, body: JSON.stringify({ ...body, hprToken }) });
    const out = await json(res);
    const b = out?.body || out;
    const ok = res.ok && String(b?.status) !== 'false' && !b?.code;
    console.log(`  ${ok ? 'ACCEPTED' : 'refused'} · HTTP ${res.status} · REQUEST-ID ${h['REQUEST-ID']}\n  ${JSON.stringify(out).slice(0, 400)}\n`);
    return ok;
}

for (const path of ['register-professional-new', 'update-professional-new']) {
    console.log(`── ${path} ──`);
    for (const [label, change] of VARIANTS) {
        const body = clone(original);
        change(body);
        const go = (await ask(`Send "${label}"? A success submits the profile. [y/N/q] `)).trim().toLowerCase();
        if (go === 'q') process.exit(0);
        if (go !== 'y') continue;
        if (await send(path, body)) {
            console.log(`HPR accepted "${label}" via ${path}.`);
            process.exit(0);
        }
    }
}
console.log('HPR refused every variant. Send the REQUEST-IDs above to NHA sandbox support.');
rl.close();
