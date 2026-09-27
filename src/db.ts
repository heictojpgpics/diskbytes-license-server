/**
 * D1 query layer — one place per table so route handlers stay protocol
 * logic, and so every query is reviewable against the schema at once.
 */
import type { DeviceClaim } from "./types";

export interface LicenseRow {
  id: number;
  key_hash: string;
  key_last4: string;
  tier: "yearly" | "lifetime";
  status: "active" | "revoked" | "refunded" | "pending";
  customer_name: string;
  customer_email: string;
  note: string | null;
  issued_at: number;
  expires_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface DeviceRow {
  id: number;
  license_id: number;
  platform: "windows" | "macos";
  hardware_hash: string;
  hostname: string | null;
  os_version: string | null;
  app_version: string | null;
  activated_at: number;
  last_seen_at: number;
  revoked: number;
}

export interface AuditRow {
  id: number;
  license_id: number | null;
  key_last4: string | null;
  event: string;
  platform: string | null;
  hw_prefix: string | null;
  reason: string | null;
  ip_hash: string | null;
  created_at: number;
}

export class Db {
  constructor(private readonly d1: D1Database) {}

  // ── licenses ──────────────────────────────────────────────────────

  licenseByHash(keyHash: string): Promise<LicenseRow | null> {
    return this.d1
      .prepare("SELECT * FROM licenses WHERE key_hash = ?1")
      .bind(keyHash)
      .first<LicenseRow>();
  }

  licenseById(id: number): Promise<LicenseRow | null> {
    return this.d1
      .prepare("SELECT * FROM licenses WHERE id = ?1")
      .bind(id)
      .first<LicenseRow>();
  }

  licensesPage(offset: number, limit: number): Promise<LicenseRow[]> {
    return this.d1
      .prepare("SELECT * FROM licenses ORDER BY id DESC LIMIT ?1 OFFSET ?2")
      .bind(limit, offset)
      .all<LicenseRow>()
      .then((r) => r.results);
  }

  countLicenses(): Promise<number> {
    return this.d1
      .prepare("SELECT COUNT(*) AS n FROM licenses")
      .first<{ n: number }>()
      .then((r) => r?.n ?? 0);
  }

  insertLicense(license: {
    keyHash: string;
    keyLast4: string;
    tier: "yearly" | "lifetime";
    customerName: string;
    customerEmail: string;
    note: string | null;
    issuedAt: number;
    expiresAt: number | null;
    now: number;
  }): Promise<LicenseRow> {
    return this.d1
      .prepare(
        `INSERT INTO licenses
           (key_hash, key_last4, tier, status, customer_name, customer_email,
            note, issued_at, expires_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?6, ?7, ?8, ?9, ?9)
         RETURNING *`,
      )
      .bind(
        license.keyHash,
        license.keyLast4,
        license.tier,
        license.customerName,
        license.customerEmail,
        license.note,
        license.issuedAt,
        license.expiresAt,
        license.now,
      )
      .first<LicenseRow>()
      .then((r) => {
        if (!r) throw new Error("insert license returned no row");
        return r;
      });
  }

  setLicenseStatus(id: number, status: LicenseRow["status"], now: number): Promise<void> {
    return this.d1
      .prepare("UPDATE licenses SET status = ?2, updated_at = ?3 WHERE id = ?1")
      .bind(id, status, now)
      .run()
      .then(() => undefined);
  }

  extendLicenseExpiry(id: number, expiresAt: number | null, now: number): Promise<void> {
    return this.d1
      .prepare("UPDATE licenses SET expires_at = ?2, updated_at = ?3 WHERE id = ?1")
      .bind(id, expiresAt, now)
      .run()
      .then(() => undefined);
  }

  // ── devices ───────────────────────────────────────────────────────

  deviceByLicensePlatformHw(
    licenseId: number,
    platform: "windows" | "macos",
    hardwareHash: string,
  ): Promise<DeviceRow | null> {
    return this.d1
      .prepare(
        "SELECT * FROM devices WHERE license_id = ?1 AND platform = ?2 AND hardware_hash = ?3",
      )
      .bind(licenseId, platform, hardwareHash)
      .first<DeviceRow>();
  }

  liveDevicesForPlatform(
    licenseId: number,
    platform: "windows" | "macos",
  ): Promise<DeviceRow[]> {
    return this.d1
      .prepare(
        "SELECT * FROM devices WHERE license_id = ?1 AND platform = ?2 AND revoked = 0",
      )
      .bind(licenseId, platform)
      .all<DeviceRow>()
      .then((r) => r.results);
  }

  devicesOfLicense(licenseId: number): Promise<DeviceRow[]> {
    return this.d1
      .prepare("SELECT * FROM devices WHERE license_id = ?1 ORDER BY id")
      .bind(licenseId)
      .all<DeviceRow>()
      .then((r) => r.results);
  }

  insertDevice(licenseId: number, claim: DeviceClaim, now: number): Promise<DeviceRow> {
    return this.d1
      .prepare(
        `INSERT INTO devices
           (license_id, platform, hardware_hash, hostname, os_version, app_version,
            activated_at, last_seen_at, revoked)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 0)
         RETURNING *`,
      )
      .bind(
        licenseId,
        claim.platform,
        claim.hardwareHash,
        claim.hostname ?? null,
        claim.osVersion ?? null,
        claim.appVersion ?? null,
        now,
      )
      .first<DeviceRow>()
      .then((r) => {
        if (!r) throw new Error("insert device returned no row");
        return r;
      });
  }

  touchDevice(id: number, claim: DeviceClaim, now: number): Promise<void> {
    return this.d1
      .prepare(
        `UPDATE devices SET last_seen_at = ?2, hostname = ?3, os_version = ?4,
         app_version = ?5 WHERE id = ?1`,
      )
      .bind(id, now, claim.hostname ?? null, claim.osVersion ?? null, claim.appVersion ?? null)
      .run()
      .then(() => undefined);
  }

  /** Reactivate a revoked-by-support row for the SAME hardware. */
  reviveDevice(id: number, now: number): Promise<void> {
    return this.d1
      .prepare("UPDATE devices SET revoked = 0, last_seen_at = ?2 WHERE id = ?1")
      .bind(id, now)
      .run()
      .then(() => undefined);
  }

  revokeDevice(id: number, now: number): Promise<void> {
    return this.d1
      .prepare("UPDATE devices SET revoked = 1, last_seen_at = ?2 WHERE id = ?1")
      .bind(id, now)
      .run()
      .then(() => undefined);
  }

  deviceById(id: number): Promise<DeviceRow | null> {
    return this.d1
      .prepare("SELECT * FROM devices WHERE id = ?1")
      .bind(id)
      .first<DeviceRow>();
  }

  countDevices(): Promise<number> {
    return this.d1
      .prepare("SELECT COUNT(*) AS n FROM devices WHERE revoked = 0")
      .first<{ n: number }>()
      .then((r) => r?.n ?? 0);
  }

  // ── audit ─────────────────────────────────────────────────────────

  audit(event: {
    licenseId?: number | null;
    keyLast4?: string | null;
    event: string;
    platform?: string | null;
    hwPrefix?: string | null;
    reason?: string | null;
    ipHash?: string | null;
    now: number;
  }): Promise<void> {
    return this.d1
      .prepare(
        `INSERT INTO audit_events
           (license_id, key_last4, event, platform, hw_prefix, reason, ip_hash, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`,
      )
      .bind(
        event.licenseId ?? null,
        event.keyLast4 ?? null,
        event.event,
        event.platform ?? null,
        event.hwPrefix ?? null,
        event.reason ?? null,
        event.ipHash ?? null,
        event.now,
      )
      .run()
      .then(() => undefined);
  }

  recentAudit(limit: number): Promise<AuditRow[]> {
    return this.d1
      .prepare("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?1")
      .bind(limit)
      .all<AuditRow>()
      .then((r) => r.results);
  }

  // ── nonce replay defense ──────────────────────────────────────────

  /** Returns true when the nonce is fresh (and records it). */
  consumeNonce(nonce: string, now: number): Promise<boolean> {
    return this.d1
      .prepare("INSERT INTO nonce_seen (nonce, seen_at) VALUES (?1, ?2)")
      .bind(nonce, now)
      .run()
      .then(() => true)
      .catch(() => false);
  }

  /** Housekeeping: drop nonces older than the request window. */
  sweepNonces(now: number, olderThanSeconds: number): Promise<void> {
    return this.d1
      .prepare("DELETE FROM nonce_seen WHERE seen_at < ?1")
      .bind(now - olderThanSeconds)
      .run()
      .then(() => undefined);
  }
}
