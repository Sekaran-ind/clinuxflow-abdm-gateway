// Sets this ABDM client's bridge URL — the public origin ABDM's HIE-CM calls back (Scan & Share's
// {url}/api/v3/hip/patient/share; Scan & Share doc §3.2.4) — and lists the services (facilities)
// linked to the bridge. One-off, per environment: it changes where ABDM sends callbacks for every
// facility on this client, so it is a script, not an API route.
//
//   ABDM_CLIENT_ID=… ABDM_CLIENT_SECRET=… node scripts/set-bridge-url.js https://<gateway public origin>
//   ABDM_CLIENT_ID=… ABDM_CLIENT_SECRET=… node scripts/set-bridge-url.js --show
//
// ABDM_GATEWAY_BASE_URL and ABDM_X_CM_ID default to the sandbox (as in wrangler.toml).
const base = process.env.ABDM_GATEWAY_BASE_URL || 'https://dev.abdm.gov.in/api/hiecm/gateway/v3';
const xCmId = process.env.ABDM_X_CM_ID || 'sbx';
const { ABDM_CLIENT_ID: clientId, ABDM_CLIENT_SECRET: clientSecret } = process.env;
const arg = process.argv[2];
if (!clientId || !clientSecret || !arg) {
    console.error('Usage: ABDM_CLIENT_ID=… ABDM_CLIENT_SECRET=… node scripts/set-bridge-url.js <https://public-origin> | --show');
    process.exit(1);
}
const headers = (extra = {}) => ({ 'Content-Type': 'application/json', 'REQUEST-ID': crypto.randomUUID(), TIMESTAMP: new Date().toISOString(), 'X-CM-ID': xCmId, ...extra });

const session = await fetch(`${base}/sessions`, { method: 'POST', headers: headers(), body: JSON.stringify({ clientId, clientSecret, grantType: 'client_credentials' }) });
if (!session.ok) throw new Error(`sessions: HTTP ${session.status} ${await session.text()}`);
const { accessToken } = await session.json();
const auth = { Authorization: `Bearer ${accessToken}` };

if (arg !== '--show') {
    if (!/^https:\/\//.test(arg)) throw new Error('The bridge URL must be https:// and reachable from the internet.');
    const res = await fetch(`${base}/bridge/url`, { method: 'PATCH', headers: headers(auth), body: JSON.stringify({ url: arg.replace(/\/$/, '') }) });
    console.log(`PATCH bridge/url -> HTTP ${res.status} ${await res.text()}`);
}
const services = await fetch(`${base}/bridge-services`, { headers: headers(auth) });
console.log(`bridge-services -> HTTP ${services.status}`);
console.log(JSON.stringify(await services.json().catch(() => null), null, 2));
