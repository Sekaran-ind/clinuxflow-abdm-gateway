-- ABDM M1 (Scan & Share) and the doctor roster (clinux-frontend /registries/scan-share and
-- /registries/roster), modelled on the Swastik ABDM Connector's Doctor roster.

-- The doctor roster: which HPR-registered practitioners work at which of the clinic's HFR
-- facilities. Written only by clinuxflow-api's routes/roster.js. hpr_verified_at is set only from
-- an attestation clinuxflow-abdm-gateway signs after finding the practitioner in HPR (the gateway
-- holds the ABDM credentials; this Worker does not), never from what the browser says.
CREATE TABLE IF NOT EXISTS facility_practitioners (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL,
    facility_id TEXT NOT NULL,          -- HFR facility id, e.g. IN3310002300
    facility_name TEXT NOT NULL DEFAULT '',
    hpr_id_number TEXT NOT NULL,        -- 14-digit HPR number, 71-xxxx-xxxx-xxxx
    hpr_address TEXT,                   -- name@hpr.abdm
    name TEXT NOT NULL,
    role TEXT NOT NULL,                 -- doctor | nurse | pharmacist | other
    hpr_category_id TEXT,               -- HPR category as HPR reported it (1 doctor, 2 nurse, 6 pharmacist)
    designation TEXT,
    department TEXT,
    hpr_verified_at TEXT,               -- when the gateway's attestation was accepted
    status TEXT NOT NULL DEFAULT 'active', -- active | left
    left_at TEXT,
    added_by_account_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (clinic_id, facility_id, hpr_id_number)
);
CREATE INDEX IF NOT EXISTS idx_facility_practitioners_facility ON facility_practitioners (clinic_id, facility_id, status);

-- Scan & Share (ABDM Scan & Share doc v1.0, 03-03-2025): a patient scans the facility's QR with an
-- ABHA app; ABDM calls the gateway's HIP callback with their profile; the gateway gives them a
-- token number at that counter. These tables are written by clinuxflow-abdm-gateway
-- (src/routes/scanShare.js) in this shared database.

-- Which clinic a facility's Scan & Share callbacks belong to. One clinic per HFR facility.
CREATE TABLE IF NOT EXISTS hip_facilities (
    facility_id TEXT PRIMARY KEY,       -- the HIP id ABDM sends (= HFR facility id)
    clinic_id TEXT NOT NULL,
    facility_name TEXT NOT NULL DEFAULT '',
    hip_name TEXT,                      -- the name ABHA apps show (<= 15 chars, no special characters)
    linked_with_abdm INTEGER NOT NULL DEFAULT 0, -- 1 = linked to this gateway's bridge through HFR's API
    active INTEGER NOT NULL DEFAULT 1,
    created_by_account_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hip_facilities_clinic ON hip_facilities (clinic_id);

-- One row per profile a patient shared. profile_json holds the shared demographics only until a
-- member of staff claims the row into the ABHA journey (then it is cleared), or for at most a day.
CREATE TABLE IF NOT EXISTS scan_share_requests (
    id TEXT PRIMARY KEY,
    clinic_id TEXT NOT NULL,
    hip_id TEXT NOT NULL,
    context TEXT NOT NULL DEFAULT '',   -- the counter id in the QR
    share_date TEXT NOT NULL,           -- yyyy-mm-dd (IST): token numbers restart each day per counter
    token_number INTEGER NOT NULL,
    request_id TEXT,                    -- ABDM's REQUEST-ID, echoed in on-share
    abha_number TEXT,
    abha_address TEXT,
    display_name TEXT,
    gender TEXT,
    year_of_birth TEXT,
    profile_json TEXT,
    status TEXT NOT NULL DEFAULT 'waiting', -- waiting | claimed | dismissed
    acknowledged INTEGER NOT NULL DEFAULT 0, -- 1 = on-share accepted by ABDM
    ack_error TEXT,
    claimed_by_account_id TEXT,
    claimed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (hip_id, context, share_date, token_number)
);
CREATE INDEX IF NOT EXISTS idx_scan_share_clinic_day ON scan_share_requests (clinic_id, share_date, status);
