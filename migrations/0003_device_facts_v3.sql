-- DiskBytes license server — migration 0003 (v3: deeper hardware
-- binding + smarter sanitization support).
--
-- WHAT THIS ADDS (all additive — v1/v2 clients and rows keep working):
--  * devices: baseboard_serial (Windows SMBIOS BaseBoard serial /
--      macOS IOPlatformSerialNumber), firmware_uuid (Windows SMBIOS
--      System UUID / macOS IOPlatformUUID), bios_version (firmware
--      build, display-only), cpu_cores (logical CPU count), arch
--      (x86_64/aarch64) + the matching component hashes comp_board
--      and comp_firmware. The composite hardware_hash stays THE
--      binding identity (algorithm frozen — v1-activated devices
--      re-match); the components give support swap-forensics: a
--      changed comp_board + stable comp_machine = motherboard RMA;
--      changed comp_machine + stable comp_board = case/machine swap.
--  * devices.facts_v3: provenance marker — which clients have already
--      reported the v3 claim set (support can tell "field missing
--      because the client is old" from "field missing because the
--      hardware refuses to report it").
--
-- MIGRATION SAFETY: pure ALTER TABLE ADD COLUMN (nullable defaults)
-- — no rewrites, no lock risk, safe on the live D1 with existing rows.

ALTER TABLE devices ADD COLUMN baseboard_serial TEXT;    -- SMBIOS/baseboard serial
ALTER TABLE devices ADD COLUMN firmware_uuid    TEXT;    -- SMBIOS System UUID (36 chars) / IOPlatformUUID
ALTER TABLE devices ADD COLUMN bios_version     TEXT;    -- firmware build ("DELL  A08" / "1926.60.71.0.0")
ALTER TABLE devices ADD COLUMN cpu_cores       INTEGER; -- logical processors
ALTER TABLE devices ADD COLUMN arch            TEXT;     -- "x86_64" | "aarch64"
ALTER TABLE devices ADD COLUMN comp_board      TEXT;     -- sha256("board:"+baseboard serial) 64 hex
ALTER TABLE devices ADD COLUMN comp_firmware   TEXT;     -- sha256("firmware:"+SMBIOS UUID) 64 hex
ALTER TABLE devices ADD COLUMN facts_v3        INTEGER;  -- 1 once a v3 claim touched this row
