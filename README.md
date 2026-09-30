# clinuxflow-abdm-gateway

Dedicated Cloudflare Worker that owns all of ClinuxFlow's integration with NHA systems, and is
the only service in the stack that holds ABDM or UHI credentials:

- **ABDM registries**: HPR (Health Professional Registry), HFR (Health Facility Registry) and
  ABHA (patient identity). `clinux-frontend` calls these routes on behalf of signed-in users.
- **UHI** (Unified Health Interface, NHA's Beckn-based protocol for discovering and booking
  health services): both network roles, **HSPA** (provider) and **EUA** (consumer). Merged in
  from the former `clinux-uhi-gateway` repo.

Background: `clinuxflow-abdm-integration-approach.md` and `UHI/` in clinux-docs.

## Authentication: two kinds of caller, never mixed

| Caller | Routes | How it is authenticated |
|---|---|---|
| Signed-in ClinuxFlow users (through clinux-frontend) | `/hpr/*`, `/hfr/*`, `/abha/*`, `/uhi/hspa/internal/*`, `/uhi/eua/internal/*` | `X-Service-Key` (a bot filter only, since its value ships in the frontend bundle) **plus** a verified ClinuxFlow session JWT (`Authorization: Bearer`, HS256, same `JWT_SECRET` as clinuxflow-api) **plus** per-account rate limits: 120/min overall, and 10 per 10 minutes on every route that makes ABDM send an OTP or verification message |
| The NHA UHI gateway and other UHI participants | `/uhi/hspa/{search,select,init,confirm,status,cancel}`, `/uhi/eua/{on_search,…,on_update,on_message}` | The UHI message signature only (Ed25519 over BLAKE2b-512; keys from the UHI network registry, or from config in local mode) |

`/health` is open. HSPA operator routes are further limited to the clinic ids in
`UHI_HSPA_OPERATOR_CLINIC_IDS`, and EUA transactions are visible only to the clinic that started
them.

Known limit: session verification checks signature and expiry only. The gateway can't see
account status in clinuxflow-api's database, so a disabled account's token keeps working until
it expires (clinuxflow-api has the same gap; tracked as S4 in clinux-docs `PENDING-WORK.md`).

## What's here

```
src/
  index.js                     Entrypoint: mounts /hpr, /hfr, /abha, /uhi; auth and rate limits
  lib/
    config.js                  ABDM env vars and secrets
    abdmClient.js              ABDM fetch wrapper: REQUEST-ID/TIMESTAMP/X-CM-ID, retries, AbdmApiError
    encryption.js              RSA-OAEP-SHA1 (ABHA) and RSA/PKCS1 (HPR): NOT interchangeable
    sessionToken.js            Accessors over the ABDM Durable Objects
    masterData.js              KV-cached ABDM reference data
    serviceAuth.js             X-Service-Key check
    userSession.js             ClinuxFlow session JWT check
    rateLimit.js               Per-account fixed-window limits; OTP-sending route list
  routes/
    hpr.js, hfr.js, abha.js    ABDM registry flows
    uhi.js                     UHI mounting and trust boundaries
  uhi/
    crypto.js                  UHI signing: Ed25519 over BLAKE2b-512 (@noble/hashes)
    protocol.js                v2.0.2 envelope: zod schemas, actions, context, ack/nack
    client.js                  Signed POST, network-registry lookup (+KV cache), signature middleware
    config.js                  UHI env vars
    records.js, stores.js      Order and transaction state (pure ops; DO-backed or in-memory)
    hspa/                      Provider role: catalog and routes
    eua/                       Consumer role: routes
  durable-objects/
    SessionTokenManager.js     ABDM client-credential token (one global instance)
    RegistrationTransaction.js ABDM multi-step OTP flow state (one per txnId)
    UhiRecordStore.js          One UHI record per instance (transaction, order, catalog)
    RateLimiter.js             One counter per bucket and account
scripts/
  generate-uhi-keys.js         Ed25519 key pair for a UHI role
```

## Setup

1. `npm install`
2. Copy `.dev.vars.example` to `.dev.vars` and fill in:
   - `ABDM_CLIENT_ID`, `ABDM_CLIENT_SECRET` from the ABDM sandbox portal
   - `SERVICE_KEY`, matching clinux-frontend's `VITE_SERVICE_KEY`
   - `JWT_SECRET`, **the same value clinuxflow-api uses**; without it every user-driven route
     answers 503
   - `UHI_HSPA_PRIVATE_KEY_DER` and `UHI_EUA_PRIVATE_KEY_DER` from
     `npm run uhi:generate-keys -- hspa` and `-- eua` (a role without a key is disabled)
   - `UHI_HSPA_OPERATOR_CLINIC_IDS`, your local clinic id
3. KV namespace for cached reference data (already created for the shared account):
   `npx wrangler kv namespace create MASTER_DATA_CACHE`, then put the id in `wrangler.toml`.
4. `npm run dev` (port 8788). Durable Objects and migrations need no separate provisioning.
5. Deployed environments: `wrangler secret put` each of `ABDM_CLIENT_ID`, `ABDM_CLIENT_SECRET`,
   `SERVICE_KEY`, `JWT_SECRET`, `UHI_HSPA_PRIVATE_KEY_DER`, `UHI_EUA_PRIVATE_KEY_DER`, and set the
   per-environment UHI vars listed in `wrangler.toml`.

`npm test` runs everything under plain Node (in-memory stores stand in for the Durable Objects).

## ABDM notes

### Two-token model
Every ABDM call uses the gateway's own client-credential token, handled by
`SessionTokenManager`. Some endpoints also need a per-user token the gateway never caches:
- HFR facility creation (`basic-information`, `submit`) needs `x-hprid-auth` from
  `POST /hpr/auth/password-login`, passed as `X-HPRID-Auth-Token`.
- ABHA's `email-verification-link`, `get-profile` and `update-mobile` need ABDM's `X-token`
  (returned as `abhaToken`), passed as `X-ABHA-Token`.
- HPR professional routes take `hprToken` in the body.

None of these use the `Authorization` header on the way in, so they never collide with the
ClinuxFlow session token.

### Encryption gotcha
ABHA uses `RSA/ECB/OAEPWithSHA-1AndMGF1Padding`; HPR registration and auth use
`RSA/ECB/PKCS1Padding`, with a different key and certificate endpoint. `encryption.js` has one
function per scheme so they can't be swapped by accident. PKCS1 encryption runs through
`node:crypto` because Workers' `crypto.subtle` doesn't implement it. Which fields get encrypted
differs between HPR endpoints; each route follows the API document's sample exactly.

## UHI notes

### Modes
- `UHI_GATEWAY_MODE=local` (default): the EUA role sends `search` straight to this Worker's own
  HSPA, and both roles trust each other's keys (derived from the configured private keys) plus
  any extras in `UHI_LOCAL_PEERS`. For development.
- `UHI_GATEWAY_MODE=sandbox`: `search` goes to the NHA gateway's broadcast endpoint
  (`/api/v1/uhi/search`), and every inbound signature is checked against keys from the network
  registry (`/api/v1/networkregistry/lookup`, cached in memory and in KV). Needs subscriber ids
  registered with NHA and a public `UHI_PUBLIC_BASE_URL`.

### Flow
Every network-facing request is answered with an ACK immediately; the matching `on_*` callback
is sent afterwards with `waitUntil`. The HSPA serves the catalog published through
`PUT /uhi/hspa/internal/catalog`, or a fixture until one is published. EUA operators start a
search with `POST /uhi/eua/internal/search` and drive the booking with
`/uhi/eua/internal/{select,init,confirm,status,cancel}`.

### Things to know
- **BLAKE2b comes from `@noble/hashes`**: workerd's `node:crypto` doesn't support it. A test
  checks it against Node's native implementation, and another reproduces the signing PDF's
  worked-example signature (UHI signs the BLAKE2b-512 of the signing string, not the string
  itself).
- **Known spec gaps** are marked in `uhi/protocol.js`: the registry's signing-key field name
  (unconfirmed without registered credentials) and the `on_update`/`on_message` payload shapes.
- **Local mode in a deployed Worker** makes the Worker call its own public URL; Cloudflare may
  block a Worker fetching itself on the same hostname. Use local mode under `wrangler dev`; use
  sandbox mode when deployed.

## Not yet built

- Remaining ABHA flows (Driving Licence, demographic and biometric creation, ABHA-address login,
  deactivate/reactivate, Re-KYC, ABHA card, Child ABHA), following the `requestOtp`/`verifyOtp`
  pattern in `routes/abha.js`.
- Remaining HFR endpoints (contact OTP, UWIN lookup, address dedup, HPR-services bridge).
- UHI: deriving the HSPA catalog from the facility's ClinuxFlow data (HFR facility, HPR doctors,
  services, hours); `on_search` payload encryption with `encr_public_key`; sandbox registration.
- A request and response audit log for ABDM and UHI calls.
- Retrying failed ABDM calls through a queue instead of failing the request.
