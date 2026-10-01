-- DiskGenie license server — migration 0002 (v2: device facts, race-safe
-- slot binding, rate limiting).
--
-- WHAT THIS ADDS (all additive — v1 rows keep working):
--  * devices: component hashes (machine/volume/cpu) + descriptive facts
--    (cpu_brand, ram_mb, machine_model) — richer binding forensics +
--    support display. The composite hardware_hash stays THE binding
--    identity (unchanged algorithm, so v1-activated devices re-match).
--  * A PARTIAL UNIQUE INDEX enforcing the owner's slot rule at the
--    storage layer: at most ONE live (revoked = 0) device row per
--    (license_id, platform). The v1 check-then-insert flow had a TOCTOU
--    race (two concurrent activations could both pass the SELECT and
--    both INSERT). With the index, SQLite itself refuses the second
--    row and the route maps the constraint error to DEVICE_SLOT_TAKEN.
--  * rate_buckets: fixed-window counters backing the /v1 rate limits
--    (atomic upsert; one write per limited request).
--  * licenses.source: provenance ('admin' | 'webhook' | 'seed').
--  * audit_events.detail: structured what-changed notes (OS upgrade,
--    app update, hostname rename) — support-grade detection without
--    growing any PII.
--
-- MIGRATION SAFETY: the unique index creation below first de-duplicates
-- any live-slot duplicates the v1 race may have produced (keeps the
-- OLDEST activation live, marks later duplicates revoked-by-support) —
-- idempotent, safe to re-run, safe on a clean database.

-- 1. New device columns (nullable: v1 clients / rows simply omit them).
ALTER TABLE devices ADD COLUMN comp_machine   TEXT;     -- sha256(machine identity) 64 hex
ALTER TABLE devices ADD COLUMN comp_volume    TEXT;     -- sha256(volume identity) 64 hex
ALTER TABLE devices ADD COLUMN comp_cpu       TEXT;     -- sha256(cpu identity) 64 hex
ALTER TABLE devices ADD COLUMN cpu_brand      TEXT;     -- e.g. "Intel Core i7-1260P"
ALTER TABLE devices ADD COLUMN ram_mb         INTEGER;  -- total physical memory
ALTER TABLE devices ADD COLUMN machine_model  TEXT;     -- "Dell Inc. XPS 15 9520" | "MacBookPro18,3"

-- 2. Race-proof the slot rule. First neutralize any duplicate live rows
--    the v1 TOCTOU race created (keep lowest id = first activation).
UPDATE devices SET revoked = 1
WHERE id NOT IN (
  SELECT MIN(id) FROM devices
  WHERE revoked = 0
  GROUP BY license_id, platform
)
AND revoked = 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_live_slot
  ON devices(license_id, platform)
  WHERE revoked = 0;

-- 3. Rate limiting storage (fixed window; swept with the nonces).
CREATE TABLE IF NOT EXISTS rate_buckets (
  bucket_key   TEXT PRIMARY KEY,   -- "act:key:<hash>" | "act:ip:<hash>" | ...
  window_start INTEGER NOT NULL,   -- window start (unix seconds)
  count        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_window ON rate_buckets(window_start);

-- 4. License provenance + audit detail.
ALTER TABLE licenses  ADD COLUMN source TEXT;
ALTER TABLE audit_events ADD COLUMN detail TEXT;
