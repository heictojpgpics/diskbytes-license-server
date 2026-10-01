/**
 * Self-healing schema bootstrap (v3 deploy safety): a Worker deploy can
 * land minutes before `wrangler d1 migrations apply` runs (the deploy
 * pipeline auto-ships code). The bootstrap must ADD the missing v3
 * columns on first request and keep every route working against a
 * v2-shaped database — proven here against a REAL second D1 instance
 * that is created WITHOUT the v3 columns.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { env } from "cloudflare:test";
import worker from "../src/index";
import type { Env } from "../src/types";
import { resetSchemaLatchForTest, v3ColumnNames } from "../src/schema";
import { signedRequest, hw } from "./client";
import { TEST_ADMIN_KEY } from "./constants";

/** The test runtime's env carries the extra DB_V2 binding (vitest
 * config) that production Env intentionally does not. */
const testEnv = env as unknown as Env & { DB_V2: D1Database };

const ctx = undefined as unknown as ExecutionContext;

/** The v2 schema verbatim (INITIAL_SCHEMA minus the v3 columns). */
const V2_SCHEMA = `
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

beforeAll(async () => {
  // Build the v2-shaped database exactly like a lagged deploy would
  // have it: everything EXCEPT the migration-0003 columns.
  const statements = V2_SCHEMA.split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n")
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const stmt of statements) {
    await testEnv.DB_V2.prepare(stmt).run();
  }
});

/** Call the worker with the v2-shaped database swapped in. */
const callV2 = async (req: Request | Promise<Request>) => {
  const v2Env = { ...testEnv, DB: testEnv.DB_V2 } as unknown as Env;
  const res = await worker.fetch(await req, v2Env, ctx);
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
};

describe("self-healing schema bootstrap (v3 deploy safety)", () => {
  it("a v3 worker against a v2 database heals the columns and completes a full v3 activation", async () => {
    resetSchemaLatchForTest();
    // Pre-condition: the v3 columns really are absent.
    const before = await testEnv.DB_V2
      .prepare("PRAGMA table_info(devices)")
      .all<{ name: string }>();
    const beforeNames = new Set(before.results.map((r) => r.name));
    for (const col of v3ColumnNames) expect(beforeNames.has(col)).toBe(false);

    // First request through the router triggers the bootstrap.
    const keyRes = await callV2(new Request("https://license.diskgenie.test/v1/admin/keys", {
      method: "POST",
      headers: { authorization: `Bearer ${TEST_ADMIN_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ tier: "lifetime", customerName: "Heal Test", customerEmail: "heal@example.com" }),
    }));
    expect(keyRes.status).toBe(200);
    const key = (keyRes.body.keys as Array<{ key: string }>)[0]!.key;

    // The v3 columns now exist (the bootstrap added exactly them).
    const after = await testEnv.DB_V2
      .prepare("PRAGMA table_info(devices)")
      .all<{ name: string }>();
    const afterNames = new Set(after.results.map((r) => r.name));
    for (const col of v3ColumnNames) expect(afterNames.has(col)).toBe(true);

    // A FULL v3 activation works end-to-end against the healed schema.
    const act = await callV2(signedRequest("POST", "/v1/activate", {
      licenseKey: key, hardwareHash: hw(21), platform: "windows",
      hostname: "HEAL-PC", osVersion: "Windows 11.0.26100", appVersion: "0.1.0",
      cpuBrand: "QEMU\x00Virtual CPU", ramMb: 16384, machineModel: "Generic",
      baseboardSerial: "BXHEAL1", firmwareUuid: "4c4c4544-0042-4e10-8032-b2c04f475031",
      biosVersion: "AMI 5.6", cpuCores: 8, arch: "x86_64",
      compBoard: "a".repeat(64), compFirmware: "b".repeat(64),
    }));
    expect(act.status).toBe(200);

    const detail = await callV2(new Request(
      `https://license.diskgenie.test/v1/admin/lookup`,
      { method: "POST", headers: { authorization: `Bearer ${TEST_ADMIN_KEY}`, "content-type": "application/json" }, body: JSON.stringify({ key }) },
    ));
    expect(detail.status).toBe(200);
    const dev = (detail.body.devices as Array<Record<string, unknown>>)[0]!;
    expect(dev.baseboardSerial).toBe("BXHEAL1");
    expect(dev.firmwareUuid).toBe("4c4c4544-0042-4e10-8032-b2c04f475031");
    expect(dev.cpuCores).toBe(8);
    expect(dev.arch).toBe("x86_64");
    expect(dev.cpuBrand).toBe("QEMU Virtual CPU");
    expect(dev.factsV3).toBe(true);
  });

  it("the bootstrap is idempotent (a second pass changes nothing and never throws)", async () => {
    resetSchemaLatchForTest();
    const res = await callV2(new Request("https://license.diskgenie.test/v1/health"));
    expect(res.status).toBe(200);
    expect(res.body.version).toBe(3);
    const info = await testEnv.DB_V2.prepare("PRAGMA table_info(devices)").all<{ name: string }>();
    // 16 v2 columns + exactly the 8 v3 additions — nothing more.
    expect(info.results.length).toBe(16 + v3ColumnNames.size);
  });
});
