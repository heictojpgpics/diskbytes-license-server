-- DiskBytes license server — D1 schema (migration 0001).
-- Design notes (docs in the app repo: docs/LICENSING-ARCHITECTURE.md §5):
--  * Raw license keys are NEVER stored — only sha256(key) hashes.
--  * One license = 1 Windows device + 1 macOS device (enforced in code,
--    indexed here: one live row per (license_id, platform)).
--  * audit_events stores no raw key and no full hardware hash (prefix only)
--    and a salted IP hash — support-grade forensics without PII blobs.
--  * nonce_seen gives single-use replay defense for authenticated requests.

CREATE TABLE IF NOT EXISTS licenses (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash       TEXT NOT NULL UNIQUE,          -- lowercase hex sha256(normalized key)
  key_last4      TEXT NOT NULL,                 -- display, e.g. "3K9P"
  tier           TEXT NOT NULL CHECK (tier IN ('yearly','lifetime')),
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','refunded','pending')),
  customer_name  TEXT NOT NULL,
  customer_email TEXT NOT NULL,
  note           TEXT,
  issued_at      INTEGER NOT NULL,              -- unix seconds
  expires_at     INTEGER,                       -- yearly: unix seconds; lifetime: NULL
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_licenses_key_hash ON licenses(key_hash);
CREATE INDEX IF NOT EXISTS idx_licenses_email    ON licenses(customer_email);
CREATE INDEX IF NOT EXISTS idx_licenses_status   ON licenses(status);

CREATE TABLE IF NOT EXISTS devices (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id    INTEGER NOT NULL REFERENCES licenses(id),
  platform      TEXT NOT NULL CHECK (platform IN ('windows','macos')),
  hardware_hash TEXT NOT NULL,                  -- client fingerprint (64 hex)
  hostname      TEXT,
  os_version    TEXT,
  app_version   TEXT,
  activated_at  INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_id);
CREATE INDEX IF NOT EXISTS idx_devices_hw      ON devices(hardware_hash);
CREATE INDEX IF NOT EXISTS idx_devices_live    ON devices(license_id, platform, revoked);

CREATE TABLE IF NOT EXISTS audit_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER,
  key_last4  TEXT,
  event      TEXT NOT NULL,                     -- activate|validate|deactivate|denied|admin|replay
  platform   TEXT,
  hw_prefix  TEXT,                              -- first 12 hex chars only
  reason     TEXT,
  ip_hash    TEXT,                              -- salted sha256 (server-side salt env)
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_license ON audit_events(license_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);

CREATE TABLE IF NOT EXISTS nonce_seen (
  nonce   TEXT PRIMARY KEY,                     -- 32 hex chars from X-DB-Nonce
  seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonce_seen_at ON nonce_seen(seen_at);
