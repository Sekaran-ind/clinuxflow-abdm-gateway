// HFR (Health Facility Registry) routes — facility search + the four-step onboarding sequence
// (basic -> additional -> detailed -> submit information), plus the master-data lookups the
// onboarding form depends on (facility types, ownership types, LGD states/districts/subdistricts,
// specialities).
//
// Auth model, per the doc: every call needs the gateway's own Authorization: Bearer <token>
// (client-credential token, handled transparently here via getAccessToken). Facility CREATION
// calls additionally need `x-hprid-auth`, a per-user token for the individual acting as the
// facility's "Facility Manager" — that's a *different* identity from the DSC's own credentials,
// obtained by that person logging in via POST /hpr/auth/password-login (see routes/hpr.js) with
// their own HPR ID/password. This gateway does not mint or cache that token itself — it's scoped
// to one human, not the whole Worker — so callers must pass it through as the
// `X-HPRID-Auth-Token` header on requests to the write endpoints below.
//
// The basic/additional/detailed/submit request bodies are large (60+ fields across the full
// onboarding form, see New_HFR_APIs_Documentation_SBX.pdf) and already validated server-side by
// ABDM. Rather than re-declare every field name here (which would just drift out of sync with
// ABDM's own schema), these routes do a thin passthrough: forward the caller's JSON body as-is,
// after checking the couple of fields this gateway itself depends on (trackingId once a facility
// exists in draft). Field-level validation before submission is left to the frontend form layer.

import { Hono } from 'hono';
import { callAbdm, AbdmApiError } from '../lib/abdmClient.js';
import { getAbdmConfig } from '../lib/config.js';
import { getAccessToken } from '../lib/sessionToken.js';
import { getCachedMasterData } from '../lib/masterData.js';

export const hfrRoutes = new Hono();

class HttpError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

function requireHpridAuth(c) {
    const token = c.req.header('X-HPRID-Auth-Token');
    if (!token) {
        throw new HttpError(400, 'X-HPRID-Auth-Token header is required (facility manager token from /hpr/auth/password-login)');
    }
    return token;
}

hfrRoutes.onError((err, c) => {
    if (err instanceof HttpError) return c.json({ success: false, error: err.message }, err.status);
    if (err instanceof AbdmApiError) {
        return c.json({ success: false, error: 'ABDM request failed', abdmStatus: err.status, abdmBody: err.body }, 502);
    }
    console.error('[hfr] unexpected error:', err);
    return c.json({ success: false, error: err.message }, 500);
});

// --- Search (mandatory before creating, to avoid duplicate facility records) -------------------
// Body: { ownershipCode, stateLGDCode, districtLGDCode?, subdistrictLGDCode?, pincode?,
//         facilityName, facilityId?, page, resultsPerPage }
hfrRoutes.post('/facility/search', async (c) => {
    const body = await c.req.json();
    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/FacilityManagement/v1.5/facility/search`,
        xCmId: config.xCmId,
        accessToken,
        body,
    });

    return c.json({ success: true, ...result });
});

// --- Step 1: Basic Information (creates the draft, returns trackingId) -------------------------
// Requires x-hprid-auth: the acting user must already hold an HPR ID registered with the
// "Facility Manager" role (see the doc's "Getting Started" note under Basic Facility
// Information API) — this gateway can't do that step on their behalf.
hfrRoutes.post('/facility/basic-information', async (c) => {
    const hpridAuth = requireHpridAuth(c);
    const body = await c.req.json();

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1.5/facility/basic-information`,
        xCmId: config.xCmId,
        accessToken,
        extraHeaders: { 'x-hprid-auth': hpridAuth },
        body,
    });

    return c.json({ success: true, ...result });
});

// --- Step 2: Additional Information (only for operationally-Functional facilities) --------------
// Body must include { trackingId, ... } — trackingId comes from Step 1's response.
hfrRoutes.post('/facility/additional-information', async (c) => {
    const body = await c.req.json();
    if (!body.trackingId) return c.json({ success: false, error: 'trackingId is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1.5/facility/additional-information`,
        xCmId: config.xCmId,
        accessToken,
        body,
    });

    return c.json({ success: true, ...result });
});

// --- Step 3: Detailed Information (only for operationally-Functional facilities) ----------------
hfrRoutes.post('/facility/detailed-information', async (c) => {
    const body = await c.req.json();
    if (!body.trackingId) return c.json({ success: false, error: 'trackingId is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1.5/facility/detailed-information`,
        xCmId: config.xCmId,
        accessToken,
        body,
    });

    return c.json({ success: true, ...result });
});

// --- Step 4: Submit (finalizes the facility, returns the permanent facilityId) -------------------
// Body: { trackingId, sourceOfInformation, sourceUniqueID }. Requires x-hprid-auth again.
hfrRoutes.post('/facility/submit', async (c) => {
    const hpridAuth = requireHpridAuth(c);
    const body = await c.req.json();
    if (!body.trackingId) return c.json({ success: false, error: 'trackingId is required' }, 400);

    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);

    const result = await callAbdm({
        url: `${config.hprHfrBaseUrl}/v1.5/facility/submit-facility`,
        xCmId: config.xCmId,
        accessToken,
        extraHeaders: { 'x-hprid-auth': hpridAuth },
        body,
    });

    if (result.status && result.status !== 'Not Created') {
        // facilityId here is what should be persisted against the clinic/facility record in
        // clinuxflow-api's D1, and is also the value that should show up as this facility's
        // registered ID wherever ClinuxFlow needs to reference it back to ABDM.
        console.log(`[hfr] facility submitted: facilityId=${result.facilityId} trackingId=${body.trackingId}`);
    }

    return c.json({ success: result.status !== 'Not Created', ...result });
});

// --- A submitted facility as HFR has it (for updates) -----------------------------------------
// Updates start from the registry, not from what this device remembers. No single HFR API returns
// a facility, so three are combined (all checked live on IN3310002300, 2026-10-03):
//   v1.5 facility/search {facilityId}     ownership, system of medicine, type code, state/district/
//                                         sub-district LGD codes, address, PIN, coordinates, status
//   v1.0 facility/search-facilities       address line 2 (city) and the full contact number; needs
//                                         { requestId, timestamp, facility: { facilityName, state,
//                                         district } } and returns every same-named facility there
//   v1.5 fetchFacilityContactDetails      contact name and the manager's HPR number (mobile and
//                                         email come back masked)
// Not available from HFR at all: the photos, opening hours, email (unmasked), ownership sub-types,
// facility sub-type, speciality type, type of service, and the additional/detailed sections.
// GET /hfr/facility/:facilityId/registry -> { facility: { ...normalised } }
export function registryFacility(search = {}, listing = {}, contact = {}) {
    const coords = (v) => (v === undefined || v === null || v === '' ? '' : String(v).trim());
    return {
        facilityId: search.facilityId,
        facilityName: search.facilityName,
        status: search.facilityStatus || listing.facilityProfileStatus || '',
        ownershipCode: search.ownershipCode || '',
        systemsOfMedicine: String(search.systemOfMedicineCode || '').split(',').map((x) => x.trim()).filter(Boolean),
        facilityTypeCode: search.facilityTypeCode || '',
        facilityType: search.facilityType || listing.facilityType || '',
        stateLGDCode: String(search.stateLGDCode ?? listing.address?.state ?? ''),
        districtLGDCode: String(search.districtLGDCode ?? listing.address?.district ?? ''),
        subDistrictLGDCode: String(search.subDistrictLGDCode ?? ''),
        addressLine1: listing.address?.addressLine1 || search.address || '',
        addressLine2: listing.address?.addressLine2 || listing.address?.city || '',
        pincode: String(search.pincode || listing.address?.pincode || ''),
        latitude: coords(search.latitude ?? listing.latitude),
        longitude: coords(search.longitude ?? listing.langitude ?? listing.longitude),
        contactNumber: listing.contactNumber ? String(listing.contactNumber) : '',
        contactName: contact.contactName || '',
        contactMobileMasked: contact.contactMobile || '',
        contactEmailMasked: contact.contactEmail || '',
        managerHprIdNumber: contact.hprid || '',
    };
}

hfrRoutes.get('/facility/:facilityId/registry', async (c) => {
    const facilityId = c.req.param('facilityId').toUpperCase();
    if (!/^IN[A-Z0-9]{10}$/.test(facilityId)) throw new HttpError(400, 'An HFR facility id starts with IN and has 12 characters.');
    const config = getAbdmConfig(c.env);
    const accessToken = await getAccessToken(c.env);
    const call = (path, body) => callAbdm({ url: `${config.hprHfrBaseUrl}${path}`, xCmId: config.xCmId, accessToken, body, maxAttempts: 2 });

    const found = await call('/FacilityManagement/v1.5/facility/search', { facilityId, ownershipCode: '', stateLGDCode: '', facilityName: '', page: 1, resultsPerPage: 10 });
    const search = (found?.facilities || []).find((f) => f.facilityId === facilityId);
    if (!search) throw new HttpError(404, 'HFR has no facility with that id.');
    const requestId = crypto.randomUUID();
    const [listed, contact] = await Promise.all([
        call('/v1.0/facility/search-facilities', { requestId, timestamp: new Date().toISOString(), facility: { facilityName: search.facilityName, state: String(search.stateLGDCode), district: String(search.districtLGDCode) } }).catch(() => null),
        call('/v1.5/facility/fetchFacilityContactDetails', { facilityId }).catch(() => null),
    ]);
    const listing = (listed?.facilities || []).find((f) => f.id === facilityId) || {};
    return c.json({ success: true, facility: registryFacility(search, listing, contact?.facility || {}) });
});

// --- Master data (cached) ------------------------------------------------------------------------
async function cachedGet(c, cacheKey, path) {
    const config = getAbdmConfig(c.env);
    const data = await getCachedMasterData(c.env.MASTER_DATA_CACHE, cacheKey, async () => {
        const accessToken = await getAccessToken(c.env);
        return callAbdm({ url: `${config.hprHfrBaseUrl}${path}`, method: 'GET', xCmId: config.xCmId, accessToken });
    });
    return c.json({ success: true, data });
}

// Real bug found live: fetch-facility-type/fetch-facility-Sub-type/get-owner-subtype/
// get-specialities are NOT simple GET master lists like get-master-data/lgd/states below — per
// New_HFR_APIs_Documentation_SBX.pdf §3.6-3.8 (cross-checked directly against the doc, not
// assumed) they're real POST endpoints that REQUIRE a body (ownershipCode+systemOfMedicineCode /
// facilityTypeCode / ownershipCode[+ownerSubtypeCode] / systemOfMedicineCode respectively) — an
// earlier pass called all four via cachedGet() (a bare GET, no body), which fails regardless of
// sandbox health; a prior comment attributing this to "the sandbox returning HIS-500" was
// misdiagnosing this exact bug. Frontend-facing contract stays GET+query-params (matching
// /master/lgd/districts's own convention below) — only the upstream call changes shape.
async function cachedPost(c, cacheKey, path, body) {
    const config = getAbdmConfig(c.env);
    const data = await getCachedMasterData(c.env.MASTER_DATA_CACHE, cacheKey, async () => {
        const accessToken = await getAccessToken(c.env);
        return callAbdm({ url: `${config.hprHfrBaseUrl}${path}`, method: 'POST', body, xCmId: config.xCmId, accessToken });
    });
    return c.json({ success: true, data });
}

// type = OWNER | MEDICINE | SPECIALITY-TYPE | TYPE-SERVICE | FAC-STATUS | WORKING-DAYS | ADDRESS-PROOF | ...
hfrRoutes.get('/master/data', (c) => {
    const type = c.req.query('type');
    if (!type) return c.json({ success: false, error: 'type query param is required' }, 400);
    return cachedGet(c, `hfr:master-data:${type}`, `/v1.5/facility/get-master-data?type=${encodeURIComponent(type)}`);
});

hfrRoutes.get('/master/types', (c) => cachedGet(c, 'hfr:master-types', '/v1.5/facility/get-master-types'));

// Cache keys are parameterized by the real inputs (same reasoning hfr:lgd-districts:${stateCode}
// below already gets right) — a flat, unparameterized key here would silently hand one facility's
// results to every other facility with different ownership/system-of-medicine once the request
// itself started succeeding.
hfrRoutes.get('/master/facility-types', (c) => {
    const ownershipCode = c.req.query('ownershipCode');
    const systemOfMedicineCode = c.req.query('systemOfMedicineCode');
    if (!ownershipCode || !systemOfMedicineCode) return c.json({ success: false, error: 'ownershipCode and systemOfMedicineCode query params are required' }, 400);
    return cachedPost(c, `hfr:facility-types:${ownershipCode}:${systemOfMedicineCode}`, '/v1.5/facility/fetch-facility-type', { ownershipCode, systemOfMedicineCode });
});

hfrRoutes.get('/master/facility-sub-types', (c) => {
    const facilityTypeCode = c.req.query('facilityTypeCode');
    if (!facilityTypeCode) return c.json({ success: false, error: 'facilityTypeCode query param is required' }, 400);
    return cachedPost(c, `hfr:facility-sub-types:${facilityTypeCode}`, '/v1.5/facility/fetch-facility-Sub-type', { facilityTypeCode });
});

// ownerSubtypeCode is optional (the doc's own §3.7 note: passing it gets the NEXT level of
// subtypes under an already-chosen one; omitting it gets the first level for ownershipCode alone).
hfrRoutes.get('/master/owner-subtypes', (c) => {
    const ownershipCode = c.req.query('ownershipCode');
    const ownerSubtypeCode = c.req.query('ownerSubtypeCode') || undefined;
    if (!ownershipCode) return c.json({ success: false, error: 'ownershipCode query param is required' }, 400);
    return cachedPost(c, `hfr:owner-subtypes:${ownershipCode}:${ownerSubtypeCode || ''}`, '/v1.5/facility/get-owner-subtype', { ownershipCode, ownerSubtypeCode });
});

hfrRoutes.get('/master/specialities', (c) => {
    const systemOfMedicineCode = c.req.query('systemOfMedicineCode');
    if (!systemOfMedicineCode) return c.json({ success: false, error: 'systemOfMedicineCode query param is required' }, 400);
    return cachedPost(c, `hfr:specialities:${systemOfMedicineCode}`, '/v1.5/facility/get-specialities', { systemOfMedicineCode });
});

hfrRoutes.get('/master/lgd/states', (c) => cachedGet(c, 'hfr:lgd-states', '/v1.5/facility/lgd/states'));

hfrRoutes.get('/master/lgd/districts', (c) => {
    const stateCode = c.req.query('stateCode');
    if (!stateCode) return c.json({ success: false, error: 'stateCode query param is required' }, 400);
    return cachedGet(c, `hfr:lgd-districts:${stateCode}`, `/v1.5/facility/lgd/districts?stateCode=${encodeURIComponent(stateCode)}`);
});

hfrRoutes.get('/master/lgd/subdistricts', (c) => {
    const districtCode = c.req.query('districtCode');
    if (!districtCode) return c.json({ success: false, error: 'districtCode query param is required' }, 400);
    return cachedGet(c, `hfr:lgd-subdistricts:${districtCode}`, `/v1.5/facility/lgd/subdistricts?districtCode=${encodeURIComponent(districtCode)}`);
});
