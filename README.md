# clinuxflow-abdm-gateway

Dedicated Cloudflare Worker that owns ClinuxFlow's ABDM integration — the only service in the
stack that holds ABDM credentials or calls ABDM's APIs directly. `clinuxflow-api` and
`clinuxflow-web` (Alpine.js) call this Worker's own HTTP API instead. Background and rationale:
`docs/clinuxflow-abdm-integration-approach.md` in this repo.

Covers **HPR** (Health Professional Registry), **HFR** (Health Facility Registry), and **ABHA**
(patient identity — Aadhaar-based enrolment, Aadhaar/mobile-OTP login, profile, mobile update).
All three share the same session-token/encryption/transaction infrastructure below rather than
each reimplementing it.

## Why a separate Worker

HPR, HFR, and ABHA share the same session/token mechanics, the same RSA-encryption requirement,
and the same multi-step OTP transaction pattern. Centralizing that in one service means
clinuxflow-api and the Alpine frontend never see an ABDM client secret, and every Aadhaar-adjacent
field gets encrypted exactly once, in exactly one place, instead of re-implemented per feature.

## What's here

```
src/
  index.js                            Hono app entrypoint, mounts /hpr, /hfr, /abha
  lib/
    config.js                         Resolves ABDM env vars/secrets from Worker bindings
    abdmClient.js                     Shared fetch wrapper: REQUEST-ID/TIMESTAMP/X-CM-ID headers,
                                       retry+backoff on 5xx, typed AbdmApiError on 4xx
    encryption.js                     RSA-OAEP-SHA1 (ABHA-style) + RSA/PKCS1 (HPR-style) — see
                                       the big comment at the top, these are NOT interchangeable
    sessionToken.js                   Thin accessors over the two Durable Objects below
    masterData.js                     KV-cached wrapper for ABDM reference-data calls
  durable-objects/
    SessionTokenManager.js            Single global instance holding the ABDM client-credential
                                       access token (~10h TTL), refreshes proactively, serializes
                                       concurrent refresh attempts
    RegistrationTransaction.js        One instance per ABDM txnId — holds progress through the
                                       multi-step OTP flows between separate HTTP requests, with
                                       OTP-attempt limiting and auto-expiry via a DO alarm
  routes/
    hpr.js                            Aadhaar registration flow, password login, professional
                                       lookup, a starter set of cached master-data endpoints
    hfr.js                            Facility search + 4-step onboarding (basic/additional/
                                       detailed/submit), cached master-data endpoints
    abha.js                           Aadhaar enrolment (OTP -> enrol -> mobile verify -> email
                                       link -> address suggestion/creation), generic login
                                       request-otp/verify-otp (Aadhaar-linked ABHA number, raw
                                       Aadhaar, or mobile), get-profile, update-mobile
```

## Setup

1. `npm install`
2. Copy `.dev.vars.example` to `.dev.vars` and fill in the `clientId`/`clientSecret` issued when
   ClinuxFlow registered on the ABDM Sandbox portal.
3. Create the KV namespace this project expects, then paste the printed id into `wrangler.toml`:
   ```
   npx wrangler kv namespace create MASTER_DATA_CACHE
   ```
4. `npm run dev` — Durable Object bindings and the `[[migrations]]` block in `wrangler.toml`
   handle themselves; no separate DO provisioning step is needed locally.
5. For deployed environments, set the two secrets instead of relying on `.dev.vars`:
   ```
   npx wrangler secret put ABDM_CLIENT_ID
   npx wrangler secret put ABDM_CLIENT_SECRET
   ```

This scaffold was generated without network access to npm, so dependencies haven't been
installed or `wrangler dev` smoke-tested yet — do that first before writing more code on top of
it, in case a package version needs bumping.

## Two-token model (important)

Every request needs the gateway's own client-credential token (`Authorization: Bearer ...`) —
this Worker handles that transparently via `SessionTokenManager`, callers never see it.

Several endpoints additionally need a *per-user* token that this gateway does not (and should
not) cache itself, since it's scoped to one human, not the whole Worker — callers pass it through
as a header instead:

- HFR's facility-creation calls (`basic-information`, `submit`) need `x-hprid-auth`, obtained via
  `POST /hpr/auth/password-login` — pass it as `X-HPRID-Auth-Token`.
- ABHA's `email-verification-link`, `get-profile`, and `update-mobile` endpoints need ABDM's
  `X-token`, obtained from a successful `/abha/enrollment/verify-aadhaar-otp` or
  `/abha/login/verify-otp` call (both return it as `abhaToken`) — pass it as `X-ABHA-Token`.

## Encryption gotcha

ABHA-style APIs use `RSA/ECB/OAEPWithSHA-1AndMGF1Padding`; HPR's registration/auth APIs use
`RSA/ECB/PKCS1Padding` — different key, different padding, different endpoint for the public
certificate. `src/lib/encryption.js` has one function per scheme
(`encryptOaepSha1` / `encryptPkcs1`) specifically so they can't be swapped by accident. The PKCS1
path runs through `node:crypto` (via the `nodejs_compat` flag) because Workers' native
`crypto.subtle` doesn't implement PKCS1v1.5 *encryption* (only *signing*).

Also note: which fields get encrypted is inconsistent by design across HPR endpoints (e.g.
`aadhaar` is encrypted in generate-otp, but `mobile` is sent plaintext in generate-mobile-otp,
per the supplied API doc's own sample payloads). Each route follows the doc's sample exactly —
don't assume a pattern and apply it elsewhere without checking.

## Not yet built (natural next slices)

- Remaining ABHA flows: creation via Driving Licence/demographic-auth/biometrics, login via
  ABHA-address+password and biometrics, the multi-account `login/verify/user` disambiguation
  step, delete/deactivate/reactivate, Re-KYC, QR code + ABHA card generation, forgot-ABHA-number,
  "Benefit" APIs, Child ABHA, ABHA-address verification. All follow the same
  `requestOtp`/`verifyOtp` helper pattern already in `routes/abha.js` — most are a new route
  plus the right `{ path, scope, loginHint, otpSystem }` combination from the source doc.
- Remaining ancillary HPR endpoints from the doc set: email verification, password
  recovery/change, search-by-HPR-ID/mobile, HPID forgot-flow, document upload.
- Remaining ancillary HFR endpoints: contact OTP verification, UWIN lookup, address dedup, the
  multi-facility HPR-services bridge API.
- CORS lockdown to clinuxflow-web's real origin before this goes anywhere near production.
- Cloudflare Queues for async retry of failed ABDM calls instead of failing the request outright
  (flagged in the approach doc as a resilience item — not wired up yet).
