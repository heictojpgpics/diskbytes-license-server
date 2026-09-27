/**
 * Admin API (`/v1/admin/*`, `Authorization: Bearer ADMIN_API_KEY`).
 *
 * This is the ONLY place license keys are created — the production
 * pattern (README §6): your payment provider's webhook (or a trusted
 * operator) calls POST /v1/admin/keys after payment, receives the raw
 * keys ONCE, and emails them to the customer. Raw keys are never stored.
 *
 * Routes:
 *   POST /v1/admin/keys            { count?, tier, customerName, customerEmail, note?, days? }
 *   GET  /v1/admin/keys?offset&limit
 *   GET  /v1/admin/keys/:id
 *   POST /v1/admin/keys/:id/revoke
 *   POST /v1/admin/keys/:id/renew  { days }
 *   POST /v1/admin/devices/:id/revoke     (frees a platform slot — support)
 *   POST /v1/admin/devices/:id/revive     (undo a device reset)
 *   GET  /v1/admin/stats
 */
import type { Env } from "../types";
import { Db, type LicenseRow } from "../db";
import { generateKey, isValidKeyShape, normalizeKey } from "../keys";
import { keyHashOf } from "../tokens";
import type { GeneratedKey } from "../types";
import { verifyAdmin } from "../guard";

const json = (status: number, body: object): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const fail = (status: number, code: string, message: string): Response =>
  json(status, { ok: false, code, message });

const YEAR_DAYS = 365;

interface GenerateBody {
  count?: number;
  tier?: string;
  customerName?: string;
  customerEmail?: string;
  note?: string;
  days?: number;
}

export async function handleAdmin(env: Env, request: Request, url: URL): Promise<Response> {
  const adminFail = verifyAdmin(env, request);
  if (adminFail) return fail(401, adminFail, "Admin authentication failed.");

  const db = new Db(env.DB);
  const now = Math.floor(Date.now() / 1000);
  const path = url.pathname.replace(/^\/v1\/admin\/?/, "").replace(/\/$/, "");
  const parts = path.split("/").filter(Boolean);

  // POST /v1/admin/keys — generate
  if (request.method === "POST" && parts.length === 1 && parts[0] === "keys") {
    let body: GenerateBody;
    try {
      body = (await request.json()) as GenerateBody;
    } catch {
      return fail(400, "BAD_REQUEST", "Malformed body.");
    }
    const count = Math.min(Math.max(Number(body.count ?? 1), 1), 500);
    const tier = body.tier === "yearly" || body.tier === "lifetime" ? body.tier : null;
    if (!tier) return fail(400, "BAD_REQUEST", "tier must be 'yearly' or 'lifetime'.");
    const name = (body.customerName ?? "").trim();
    const email = (body.customerEmail ?? "").trim();
    if (name.length < 1 || name.length > 120) return fail(400, "BAD_REQUEST", "customerName required (1-120 chars).");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(400, "BAD_REQUEST", "customerEmail must be a valid email.");
    const days = body.days ?? YEAR_DAYS;
    if (!Number.isFinite(days) || days < 1 || days > 3650) return fail(400, "BAD_REQUEST", "days must be 1-3650.");
    const expiresAt = tier === "yearly" ? now + days * 86_400 : null;

    const generated: GeneratedKey[] = [];
    for (let i = 0; i < count; i++) {
      let key = "";
      let inserted: LicenseRow | null = null;
      // Retry on the (2^-50-scale) hash collision; shape guarantees uniqueness in practice.
      for (let attempt = 0; attempt < 5 && !inserted; attempt++) {
        key = normalizeKey(generateKey());
        if (!isValidKeyShape(key)) continue;
        try {
          inserted = await db.insertLicense({
            keyHash: await keyHashOf(key),
            keyLast4: key.slice(-4),
            tier,
            customerName: name,
            customerEmail: email,
            note: body.note ?? null,
            issuedAt: now,
            expiresAt,
            now,
          });
        } catch {
          inserted = null;
        }
      }
      if (!inserted) return fail(500, "GEN_FAILED", "Key generation failed — retry.");
      generated.push({ key, tier, name, email, expiresAt });
    }
    await db.audit({ event: "admin", reason: `generate:${tier}x${count}`, now });
    return json(200, { ok: true, keys: generated });
  }

  // GET /v1/admin/keys — paged list (no raw keys anywhere in the response)
  if (request.method === "GET" && parts.length === 1 && parts[0] === "keys") {
    const offset = Math.max(Number(url.searchParams.get("offset") ?? 0) || 0, 0);
    const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 50) || 50, 1), 200);
    const rows = await db.licensesPage(offset, limit);
    const total = await db.countLicenses();
    return json(200, {
      ok: true,
      total,
      offset,
      limit,
      keys: rows.map(publicLicense),
    });
  }

  // GET /v1/admin/keys/:id
  if (request.method === "GET" && parts.length === 2 && parts[0] === "keys") {
    const id = Number(parts[1]);
    if (!Number.isInteger(id)) return fail(400, "BAD_REQUEST", "Bad id.");
    const row = await db.licenseById(id);
    if (!row) return fail(404, "NOT_FOUND", "No such license.");
    const devices = (await db.devicesOfLicense(id)).map((d) => ({
      id: d.id,
      platform: d.platform,
      hardwareHash: d.hardware_hash,
      hostname: d.hostname,
      osVersion: d.os_version,
      appVersion: d.app_version,
      activatedAt: d.activated_at,
      lastSeenAt: d.last_seen_at,
      revoked: d.revoked === 1,
    }));
    return json(200, { ok: true, license: publicLicense(row), devices });
  }

  // POST /v1/admin/keys/:id/revoke | renew
  if (request.method === "POST" && parts.length === 3 && parts[0] === "keys") {
    const id = Number(parts[1]);
    const action = parts[2];
    if (!Number.isInteger(id)) return fail(400, "BAD_REQUEST", "Bad id.");
    const row = await db.licenseById(id);
    if (!row) return fail(404, "NOT_FOUND", "No such license.");
    if (action === "revoke") {
      await db.setLicenseStatus(id, "revoked", now);
      await db.audit({ licenseId: id, keyLast4: row.key_last4, event: "admin", reason: "revoke", now });
      return json(200, { ok: true });
    }
    if (action === "renew") {
      let days = 365;
      try {
        const body = (await request.json()) as { days?: number };
        days = Math.min(Math.max(Number(body?.days ?? 365), 1), 3650);
      } catch {
        // default 365
      }
      const base = Math.max(row.expires_at ?? row.issued_at, now);
      await db.extendLicenseExpiry(id, base + days * 86_400, now);
      await db.setLicenseStatus(id, "active", now);
      await db.audit({ licenseId: id, keyLast4: row.key_last4, event: "admin", reason: `renew:${days}d`, now });
      return json(200, { ok: true, expiresAt: base + days * 86_400 });
    }
    return fail(404, "NOT_FOUND", "Unknown action.");
  }

  // POST /v1/admin/devices/:id/revoke | revive
  if (request.method === "POST" && parts.length === 3 && parts[0] === "devices") {
    const id = Number(parts[1]);
    const action = parts[2];
    if (!Number.isInteger(id)) return fail(400, "BAD_REQUEST", "Bad id.");
    const row = await db.deviceById(id);
    if (!row) return fail(404, "NOT_FOUND", "No such device.");
    if (action === "revoke") {
      await db.revokeDevice(id, now);
      await db.audit({ licenseId: row.license_id, event: "admin", reason: "device-revoke", platform: row.platform, hwPrefix: row.hardware_hash.slice(0, 12), now });
      return json(200, { ok: true });
    }
    if (action === "revive") {
      await db.reviveDevice(id, now);
      await db.audit({ licenseId: row.license_id, event: "admin", reason: "device-revive", platform: row.platform, now });
      return json(200, { ok: true });
    }
    return fail(404, "NOT_FOUND", "Unknown action.");
  }

  // GET /v1/admin/stats
  if (request.method === "GET" && parts.length === 1 && parts[0] === "stats") {
    const licenses = await db.countLicenses();
    const devices = await db.countDevices();
    const recent = await db.recentAudit(20);
    return json(200, { ok: true, licenses, activeDevices: devices, recentAudit: recent });
  }

  return fail(404, "NOT_FOUND", "Unknown admin route.");
}

function publicLicense(row: LicenseRow) {
  return {
    id: row.id,
    tier: row.tier,
    status: row.status,
    customerName: row.customer_name,
    customerEmail: row.customer_email,
    note: row.note,
    keyLast4: row.key_last4,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
  };
}
