/**
 * The D1 schema applied to the test database (setup.ts runs this via
 * env.DB on every test file's isolated storage). Keep in sync with
 * migrations/0001_init.sql + migrations/0002 — the CI typecheck + test
 * run execute both.
 */
export const INITIAL_SCHEMA = `
CREATE TABLE IF NOT EXISTS licenses (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  key_hash       TEXT NOT NULL UNIQUE,
  key_last4      TEXT NOT NULL,
  tier           TEXT NOT NULL CHECK (tier IN ('yearly','lifetime')),
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','refunded','pending')),
  customer_name  TEXT NOT NULL,
  customer_email TEXT NOT NULL,
  note           TEXT,
  issued_at      INTEGER NOT NULL,
  expires_at     INTEGER,
  source         TEXT,
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
  hardware_hash TEXT NOT NULL,
  hostname      TEXT,
  os_version    TEXT,
  app_version   TEXT,
  comp_machine  TEXT,
  comp_volume   TEXT,
  comp_cpu      TEXT,
  cpu_brand     TEXT,
  ram_mb        INTEGER,
  machine_model TEXT,
  activated_at  INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_id);
CREATE INDEX IF NOT EXISTS idx_devices_hw      ON devices(hardware_hash);
CREATE INDEX IF NOT EXISTS idx_devices_live    ON devices(license_id, platform, revoked);
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_live_slot ON devices(license_id, platform) WHERE revoked = 0;

CREATE TABLE IF NOT EXISTS audit_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER,
  key_last4  TEXT,
  event      TEXT NOT NULL,
  platform   TEXT,
  hw_prefix  TEXT,
  reason     TEXT,
  ip_hash    TEXT,
  detail     TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_license ON audit_events(license_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);

CREATE TABLE IF NOT EXISTS nonce_seen (
  nonce   TEXT PRIMARY KEY,
  seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonce_seen_at ON nonce_seen(seen_at);

CREATE TABLE IF NOT EXISTS rate_buckets (
  bucket_key   TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_window ON rate_buckets(window_start);
`;
