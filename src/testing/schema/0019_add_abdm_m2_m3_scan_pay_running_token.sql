-- ABDM Milestone 2 (HIP: care-context linking, discovery, consent and data transfer), Milestone 3
-- (HIU: consent requests and receiving health records), Scan & Pay and Running Token Status (NHA
-- sandbox docs: M2 v2.8 13-02-2026, M3 16-02-2026, Scan & Pay v1.0 11-08-2025, Running Token).
-- All written by clinuxflow-abdm-gateway in this shared database (src/routes/hip.js, hiu.js,
-- scanPay.js, scanShare.js); clinux-frontend reads them through the gateway's /hie/* routes.

-- What a facility does on ABDM besides Scan & Share (HIP): receive records as a HIU, take
-- payments through Scan & Pay (the UPI id patients pay to; payee name shown on the pay page).
ALTER TABLE hip_facilities ADD COLUMN hiu_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hip_facilities ADD COLUMN scan_pay_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hip_facilities ADD COLUMN upi_vpa TEXT;
ALTER TABLE hip_facilities ADD COLUMN payee_name TEXT;

-- ── Running Token Status ──────────────────────────────────────────────────────────────────────
-- The token being served at each counter today, advanced by staff ("Call next"); ABDM asks for
-- it on the patient's behalf (/api/v3/hip/patient/running-token/status).
ALTER TABLE scan_share_requests ADD COLUMN called_at TEXT;
CREATE TABLE IF NOT EXISTS counter_tokens (
    hip_id TEXT NOT NULL,
    context TEXT NOT NULL,              -- the counter id
    token_date TEXT NOT NULL,           -- yyyy-mm-dd (IST)
    clinic_id TEXT NOT NULL,
    running_token INTEGER NOT NULL DEFAULT 0,
    calls INTEGER NOT NULL DEFAULT 0,
    first_called_at TEXT,
    last_called_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (hip_id, context, token_date)
);

-- ── M2: HIP ───────────────────────────────────────────────────────────────────────────────────
-- A health record the clinic offers through ABDM (a care context), with the FHIR document served
-- when a HIU asks for it under a granted consent. Clinical data is otherwise local-first in the
-- browser; a record is copied here only when staff share it to the patient's ABHA.
CREATE TABLE IF NOT EXISTS hip_care_contexts (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL,
    hip_id TEXT NOT NULL,
    patient_reference TEXT NOT NULL,    -- the clinic's patient id
    patient_display TEXT,
    abha_address TEXT,                  -- lower case
    abha_number TEXT,                   -- 14 digits, no hyphens
    patient_name TEXT,
    gender TEXT,                        -- M | F | O | D
    year_of_birth INTEGER,
    mobile TEXT,
    care_context_reference TEXT NOT NULL, -- unique per HIP (the visit's id)
    display TEXT NOT NULL,
    hi_type TEXT NOT NULL,              -- OPConsultation | Prescription | DiagnosticReport | ...
    record_date TEXT,                   -- ISO date-time of the visit
    bundle_json TEXT NOT NULL,          -- FHIR document Bundle
    link_status TEXT NOT NULL DEFAULT 'unlinked', -- unlinked | awaiting_token | linking | linked | failed
    link_request_id TEXT,               -- REQUEST-ID of the link/carecontext call
    link_error TEXT,
    linked_via TEXT,                    -- hip (HIP-initiated) | patient (user-initiated)
    linked_at TEXT,
    notified_at TEXT,                   -- last context/notify
    created_by_account_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (hip_id, care_context_reference)
);
CREATE INDEX IF NOT EXISTS idx_hip_care_contexts_patient ON hip_care_contexts (clinic_id, patient_reference);
CREATE INDEX IF NOT EXISTS idx_hip_care_contexts_abha ON hip_care_contexts (hip_id, abha_address);
CREATE INDEX IF NOT EXISTS idx_hip_care_contexts_link ON hip_care_contexts (link_request_id);

-- Link tokens (generate-token -> on-generate-token), one per HIP and ABHA address; reused for
-- every care context until it expires.
CREATE TABLE IF NOT EXISTS hip_link_tokens (
    hip_id TEXT NOT NULL,
    abha_address TEXT NOT NULL,
    request_id TEXT NOT NULL,           -- REQUEST-ID of generate-token, echoed in the callback
    link_token TEXT,
    expires_at TEXT,
    status TEXT NOT NULL DEFAULT 'requested', -- requested | ready | failed
    error TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (hip_id, abha_address)
);
CREATE INDEX IF NOT EXISTS idx_hip_link_tokens_request ON hip_link_tokens (request_id);

-- User-initiated linking: a patient's ABHA app discovers records here (discover), asks to link
-- some (init; the HIP sends an OTP) and confirms with the OTP (confirm).
CREATE TABLE IF NOT EXISTS hip_link_requests (
    transaction_id TEXT PRIMARY KEY,
    hip_id TEXT NOT NULL,
    clinic_id TEXT NOT NULL,
    abha_address TEXT,
    abha_number TEXT,
    mobile TEXT,                        -- verified mobile from discovery, where the OTP goes
    matched_by TEXT,
    offered_json TEXT,                  -- care context ids offered in on-discover
    requested_json TEXT,                -- care context ids the patient asked to link
    link_ref_number TEXT,
    otp_hash TEXT,
    otp_expires_at TEXT,
    otp_attempts INTEGER NOT NULL DEFAULT 0,
    otp_delivery TEXT,                  -- sms | sandbox (no SMS provider; shown to staff, sandbox only)
    sandbox_otp TEXT,
    status TEXT NOT NULL DEFAULT 'discovered', -- discovered | otp_sent | linked | failed
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hip_link_requests_ref ON hip_link_requests (link_ref_number);
CREATE INDEX IF NOT EXISTS idx_hip_link_requests_clinic ON hip_link_requests (clinic_id, created_at);

-- Consent artefacts ABDM sent this HIP (consent/request/hip/notify): what may be shared, with
-- whom, for how long. A data request is honoured only within one of these.
CREATE TABLE IF NOT EXISTS hip_consents (
    consent_id TEXT PRIMARY KEY,
    hip_id TEXT NOT NULL,
    clinic_id TEXT NOT NULL,
    status TEXT NOT NULL,               -- GRANTED | REVOKED | EXPIRED | DENIED
    patient_abha TEXT,
    hiu_id TEXT,
    purpose_code TEXT,
    requester_name TEXT,
    hi_types_json TEXT,
    care_contexts_json TEXT,            -- [{ patientReference, careContextReference }]
    date_from TEXT,
    date_to TEXT,
    data_erase_at TEXT,
    detail_json TEXT,                   -- the whole consentDetail
    signature TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hip_consents_clinic ON hip_consents (clinic_id, updated_at);

-- Each data request (health-information/request) and what was pushed for it.
CREATE TABLE IF NOT EXISTS hip_data_transfers (
    transaction_id TEXT PRIMARY KEY,
    consent_id TEXT NOT NULL,
    hip_id TEXT NOT NULL,
    clinic_id TEXT,
    request_id TEXT,
    data_push_url TEXT,
    date_from TEXT,
    date_to TEXT,
    status TEXT NOT NULL DEFAULT 'requested', -- requested | refused | transferred | failed
    entries_json TEXT,                  -- [{ careContextReference, hiStatus }]
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hip_data_transfers_clinic ON hip_data_transfers (clinic_id, created_at);

-- ── M3: HIU ───────────────────────────────────────────────────────────────────────────────────
-- Consent requests a clinic raises to see a patient's records from other facilities.
CREATE TABLE IF NOT EXISTS hiu_consent_requests (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL,
    hiu_id TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE,    -- REQUEST-ID of consent/request/init
    consent_request_id TEXT,            -- ABDM's id, from on-init
    patient_abha TEXT NOT NULL,
    purpose_code TEXT NOT NULL,
    purpose_text TEXT,
    hi_types_json TEXT NOT NULL,
    date_from TEXT NOT NULL,
    date_to TEXT NOT NULL,
    data_erase_at TEXT NOT NULL,
    requester_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'requesting', -- requesting | REQUESTED | GRANTED | DENIED | REVOKED | EXPIRED | failed
    error TEXT,
    created_by_account_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hiu_consent_requests_abdm ON hiu_consent_requests (consent_request_id);
CREATE INDEX IF NOT EXISTS idx_hiu_consent_requests_patient ON hiu_consent_requests (clinic_id, patient_abha);

-- One consent artefact per HIP the patient approved (fetched with consent/fetch).
CREATE TABLE IF NOT EXISTS hiu_consent_artefacts (
    consent_id TEXT PRIMARY KEY,
    consent_request_id TEXT,
    clinic_id TEXT NOT NULL,
    hiu_id TEXT NOT NULL,
    hip_id TEXT,
    status TEXT NOT NULL,               -- GRANTED | REVOKED | EXPIRED
    patient_abha TEXT,
    detail_json TEXT,
    signature TEXT,
    fetch_request_id TEXT,
    data_erase_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hiu_consent_artefacts_fetch ON hiu_consent_artefacts (fetch_request_id);

-- A data request under an artefact. id is the secret in the data push URL; private_key is
-- this side's Fidelius key for the transfer, deleted once the data is in.
CREATE TABLE IF NOT EXISTS hiu_data_requests (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL,
    hiu_id TEXT NOT NULL,
    consent_id TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE,    -- REQUEST-ID of health-information/request
    transaction_id TEXT,                -- from on-request
    private_key TEXT,
    nonce TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'requested', -- requested | acknowledged | received | failed
    error TEXT,
    records_received INTEGER NOT NULL DEFAULT 0,
    pages_received INTEGER NOT NULL DEFAULT 0,
    statuses_json TEXT,                 -- [{ careContextReference, hiStatus, description }] for the notify
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hiu_data_requests_txn ON hiu_data_requests (transaction_id);

-- Decrypted records, kept only until the consent's dataEraseAt (or until it is revoked).
CREATE TABLE IF NOT EXISTS hiu_health_records (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL,
    consent_id TEXT NOT NULL,
    transaction_id TEXT,
    hip_id TEXT,
    patient_abha TEXT,
    care_context_reference TEXT,
    bundle_json TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT (datetime('now')),
    erase_at TEXT,
    UNIQUE (consent_id, care_context_reference)
);
CREATE INDEX IF NOT EXISTS idx_hiu_health_records_patient ON hiu_health_records (clinic_id, patient_abha);

-- ── Scan & Pay ────────────────────────────────────────────────────────────────────────────────
-- A bill staff published for a patient at Checkout, waiting for them to scan and pay.
CREATE TABLE IF NOT EXISTS scan_pay_bills (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL,
    hip_id TEXT NOT NULL,
    abha_address TEXT,
    abha_number TEXT,
    patient_name TEXT,
    encounter_reference TEXT,
    procedures_json TEXT NOT NULL,      -- [{ category, services: [{ serviceId, name, description, amount }] }]
    amount REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- open | offered | paid | cancelled
    created_by_account_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scan_pay_bills_patient ON scan_pay_bills (hip_id, abha_address, status);

-- One Scan & Pay order per open-order share (its REQUEST-ID is ABDM's openOrderRequestId).
CREATE TABLE IF NOT EXISTS scan_pay_orders (
    open_order_request_id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL,
    hip_id TEXT NOT NULL,
    counter_id TEXT,
    abha_address TEXT,
    abha_number TEXT,
    patient_name TEXT,
    profile_json TEXT,                  -- shared demographics, cleared after a day
    bill_ids_json TEXT,
    offered_json TEXT,                  -- procedures sent in on-share/open-order
    selected_json TEXT,                 -- procedures the patient chose (selection)
    order_number TEXT UNIQUE,
    amount REAL,
    payment_token TEXT UNIQUE,          -- the secret in the pay page URL
    status TEXT NOT NULL DEFAULT 'awaiting_bill', -- awaiting_bill | bill_sent | payment_requested | closed
    payment_status TEXT,                -- PENDING | SUCCESS | FAIL | CANCELED | REFUND_INITIATED | REFUND_SUCCESS
    payment_method TEXT,
    transaction_id TEXT,
    payment_date TEXT,
    notify_acknowledged INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scan_pay_orders_clinic ON scan_pay_orders (clinic_id, created_at);
