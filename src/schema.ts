/**
 * Runtime schema bootstrap (v3): the worker self-heals additive schema
 * drift on first use per isolate.
 *
 * WHY: the deploy pipeline ships code faster than schema (Workers
 * Builds redeploys the Worker on every push; `wrangler d1 migrations
 * apply` is a separate manual step). A v3 worker INSERT naming v3
 * columns against a v2 database would 500 every activation until the
 * migration lands. Instead, the first request per isolate checks
 * PRAGMA table_info and applies exactly the ADDITIVE statements that
 * are missing (each individually guarded — concurrent isolates may
 * race; "duplicate column" is the harmless loser's outcome).
 *
 * RULES (what keeps this safe):
 *  * Only ADD COLUMN statements that match migrations/0003 verbatim —
 *    migrations stay the source of truth; this never rewrites, never
 *    drops, never creates tables.
 *  * Idempotent by construction (column-exists check + guarded ALTER).
 *  * Latched in-memory: one PRAGMA per isolate lifetime.
 */
interface ColumnInfo {
  name: string;
}

/** The additive v3 device columns (migration 0003, verbatim DDL). */
const V3_DEVICE_COLUMNS: string[] = [
  "ALTER TABLE devices ADD COLUMN baseboard_serial TEXT",
  "ALTER TABLE devices ADD COLUMN firmware_uuid TEXT",
  "ALTER TABLE devices ADD COLUMN bios_version TEXT",
  "ALTER TABLE devices ADD COLUMN cpu_cores INTEGER",
  "ALTER TABLE devices ADD COLUMN arch TEXT",
  "ALTER TABLE devices ADD COLUMN comp_board TEXT",
  "ALTER TABLE devices ADD COLUMN comp_firmware TEXT",
  "ALTER TABLE devices ADD COLUMN facts_v3 INTEGER",
];

const V3_COLUMN_NAMES = new Set(
  V3_DEVICE_COLUMNS.map((ddl) => ddl.split(" ADD COLUMN ")[1]?.split(" ")[0] ?? ""),
);

/** Per-isolate latch (a Worker isolate serves many requests). */
let ensured = false;

/**
 * Ensure the v3 device columns exist. Safe to call on every request —
 * the latch makes it a no-op after the first; errors are swallowed
 * ONLY for the duplicate-column race (any other failure must surface
 * as a 500 so the deploy is never silently degraded).
 */
export async function ensureSchema(db: D1Database): Promise<void> {
  if (ensured) return;
  const info = await db.prepare("PRAGMA table_info(devices)").all<ColumnInfo>();
  const have = new Set(info.results.map((r) => r.name));
  for (const ddl of V3_DEVICE_COLUMNS) {
    const col = ddl.split(" ADD COLUMN ")[1]?.split(" ")[0] ?? "";
    if (have.has(col)) continue;
    try {
      await db.prepare(ddl).run();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes("duplicate column name")) throw err;
      // Another isolate won the race — the column exists now.
    }
  }
  ensured = true;
}

/** Test-only: reset the per-isolate latch between scenarios. */
export function resetSchemaLatchForTest(): void {
  ensured = false;
}

/** Test-only: the v3 column names (assertion helper). */
export const v3ColumnNames = V3_COLUMN_NAMES;
