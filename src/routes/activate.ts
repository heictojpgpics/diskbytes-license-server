/**
 * POST /v1/activate — bind a device to a license key, mint the first
 * (or refresh) entitlement token.
 *
 * Binding policy (owner decision, docs §1): one key = 1 Windows + 1
 * macOS device. Same-hardware re-activation is always allowed (reinstall
 * / re-image / OS upgrade keep the same machine identity). A different
 * hardware fingerprint hitting an occupied platform slot gets
 * DEVICE_SLOT_TAKEN.
 */
import type { Env } from "../types";
import { Db } from "../db";
import { entitlementResponse, keyHashOf, mintToken } from "../tokens";
import type { DeviceClaim, EntitlementResponse, ErrorResponse } from "../types";
import { verifyAppRequest, type GuardFailure } from "../guard";
import { sha256Hex } from "../crypto";

interface ActivateBody extends DeviceClaim {
  licenseKey: string;
}

const json = (status: number, body: object): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const fail = (status: number, code: string, message: string): Response =>
  json(status, { ok: false, code, message } satisfies ErrorResponse);

const GUARD_STATUS: Record<GuardFailure, number> = {
  BAD_SIGNATURE: 401,
  BAD_TIMESTAMP: 401,
  REPLAYED: 401,
  BAD_UA: 403,
  BAD_ADMIN_KEY: 401,
};

export async function handleActivate(env: Env, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const raw = await request.text();
  const guard = await verifyAppRequest(env, request, url.pathname, raw);
  if ("fail" in guard) {
    await new Db(env.DB).audit({ event: "denied", reason: guard.fail, now: nowSec() });
    return fail(GUARD_STATUS[guard.fail], guard.fail, "Request rejected.");
  }

  const ipHash = await sha256Hex(`ip:${request.headers.get("cf-connecting-ip") ?? "unknown"}`);

  let body: ActivateBody;
  try {
    body = JSON.parse(raw) as ActivateBody;
  } catch {
    return fail(400, "BAD_REQUEST", "Malformed request body.");
  }
  const key = (body.licenseKey ?? "").toUpperCase().replace(/[^0-9A-Z]/g, "");
  if (key.length !== 22) return fail(400, "BAD_REQUEST", "Malformed license key.");
  if (!isValidPlatform(body.platform)) return fail(400, "BAD_REQUEST", "Malformed platform.");
  const hw = (body.hardwareHash ?? "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hw)) return fail(400, "BAD_REQUEST", "Malformed device fingerprint.");

  // Nonce replay: record AFTER structural validation so garbage floods
  // do not burn nonce rows.
  const db = new Db(env.DB);
  const now = nowSec();
  if (!(await db.consumeNonce(request.headers.get("x-db-nonce") ?? "", now))) {
    await db.audit({ event: "replay", reason: "nonce", now, ipHash });
    return fail(401, "REPLAYED", "Request rejected (replayed).");
  }
  await db.sweepNonces(now, 600);

  const keyHash = await keyHashOf(key);
  const license = await db.licenseByHash(keyHash);
  if (!license) {
    await db.audit({ event: "denied", reason: "KEY_NOT_FOUND", keyLast4: key.slice(-4), platform: body.platform, ipHash, now });
    return fail(404, "KEY_NOT_FOUND", "That license key isn't in our records. Check it and try again.");
  }
  const last4 = license.key_last4;

  if (license.status === "revoked" || license.status === "refunded") {
    await db.audit({ licenseId: license.id, keyLast4: last4, event: "denied", reason: `KEY_${license.status.toUpperCase()}`, platform: body.platform, ipHash, now });
    return fail(403, license.status === "revoked" ? "KEY_REVOKED" : "KEY_REFUNDED", "This license key is no longer active. Contact support.");
  }
  if (license.status === "pending") {
    return fail(403, "KEY_PENDING", "This license key hasn't been issued yet.");
  }
  if (license.expires_at !== null && license.expires_at <= now) {
    await db.audit({ licenseId: license.id, keyLast4: last4, event: "denied", reason: "LICENSE_EXPIRED", platform: body.platform, ipHash, now });
    return fail(403, "LICENSE_EXPIRED", "Your yearly license has expired — renew to keep DiskBytes Pro.");
  }

  const platform = body.platform as "windows" | "macos";
  const existing = await db.deviceByLicensePlatformHw(license.id, platform, hw);
  let deviceRow;
  if (existing && existing.revoked === 0) {
    await db.touchDevice(existing.id, body, now);
    deviceRow = { ...existing, last_seen_at: now };
  } else if (existing && existing.revoked === 1) {
    // Same hardware on a support-reset row: re-register it.
    await db.reviveDevice(existing.id, now);
    deviceRow = { ...existing, revoked: 0, last_seen_at: now, activated_at: now };
  } else {
    const live = await db.liveDevicesForPlatform(license.id, platform);
    if (live.length >= 1) {
      await db.audit({ licenseId: license.id, keyLast4: last4, event: "denied", reason: "DEVICE_SLOT_TAKEN", platform, hwPrefix: hw.slice(0, 12), ipHash, now });
      return fail(
        409,
        "DEVICE_SLOT_TAKEN",
        "This key is already activated on another Windows PC — deactivate it there (or contact support) to move it here.",
      );
    }
    deviceRow = await db.insertDevice(license.id, body, now);
  }

  const token = await mintToken(
    env,
    { id: license.id, keyHash: license.key_hash, tier: license.tier, customerName: license.customer_name, customerEmail: license.customer_email, expiresAt: license.expires_at },
    { platform, hardwareHash: hw },
    now,
  );
  await db.audit({ licenseId: license.id, keyLast4: last4, event: "activate", platform, hwPrefix: hw.slice(0, 12), ipHash, now });
  return json(200, entitlementResponse(token, {
    tier: license.tier,
    customerName: license.customer_name,
    customerEmail: license.customer_email,
    expiresAt: license.expires_at,
    keyLast4: last4,
  }, { platform, activatedAt: deviceRow.activated_at, lastSeenAt: now }) satisfies EntitlementResponse);
}

function isValidPlatform(p: unknown): boolean {
  return p === "windows" || p === "macos";
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}
