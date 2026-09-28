/**
 * POST /v1/activate — bind a device to a license key, mint the first
 * (or refresh) entitlement token.
 *
 * Binding policy (owner decision, docs §1): one key = 1 Windows + 1
 * macOS device. Same-hardware re-activation is always allowed (reinstall
 * / re-image / OS upgrade keep the same machine identity). A different
 * hardware fingerprint hitting an occupied platform slot gets
 * DEVICE_SLOT_TAKEN.
 *
 * v2 hardening:
 *  * The slot rule is enforced by the partial unique index
 *    `idx_devices_live_slot` — INSERT and revive both map its
 *    constraint failure to DEVICE_SLOT_TAKEN, so concurrent
 *    activations can never double-register a slot (v1 had a
 *    SELECT-then-INSERT TOCTOU window).
 *  * Full v2 DeviceClaim (component hashes + descriptive facts) is
 *    stored/refreshed with COALESCE semantics — never regresses to
 *    NULL (the v1 validate path wiped hostname/os/app on recheck).
 *  * Per-key and per-IP rate limits (D1 fixed window) on the
 *    brute-forceable surface.
 *  * Change detection: an OS/app/hostname change on a KNOWN device is
 *    audited with a structured diff (support forensics).
 */
import type { Env, EntitlementResponse } from "../types";
import { Db } from "../db";
import { entitlementResponse, keyHashOf, mintToken } from "../tokens";
import { detectChanges } from "../detect";
import {
  fail,
  json,
  normalizeKeyClaim,
  isValidPlatform,
  nowSec,
  sanitizeClaim,
  checkRate,
  ACTIVATE_RATE,
  isSlotTaken,
  verifyAndParse,
} from "./shared";

interface ActivateBody {
  licenseKey?: unknown;
  platform?: unknown;
  hardwareHash?: unknown;
  [k: string]: unknown;
}

export async function handleActivate(env: Env, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const guard = await verifyAndParse<ActivateBody>(env, request, url.pathname);
  if ("fail" in guard) return guard.fail;
  const { body, ipHash } = guard.ok;

  const db = new Db(env.DB);
  const now = nowSec();

  const key = normalizeKeyClaim(body.licenseKey);
  if (key.length !== 22) return fail(400, "BAD_REQUEST", "Malformed license key.");
  if (!isValidPlatform(body.platform)) return fail(400, "BAD_REQUEST", "Malformed platform.");
  const platform = body.platform;
  const hwRaw = typeof body.hardwareHash === "string" ? body.hardwareHash.toLowerCase() : "";
  if (!/^[0-9a-f]{64}$/.test(hwRaw)) return fail(400, "BAD_REQUEST", "Malformed device fingerprint.");
  const claim = sanitizeClaim(body, platform, hwRaw);
  if (!claim) return fail(400, "BAD_REQUEST", "Malformed device claim.");
  const hw = hwRaw;

  // Nonce replay: record AFTER structural validation so garbage floods
  // do not burn nonce rows (v1 semantics, kept).
  if (!(await db.consumeNonce(request.headers.get("x-db-nonce") ?? "", now))) {
    await db.audit({ event: "replay", reason: "nonce", ipHash, now });
    return fail(401, "REPLAYED", "Request rejected (replayed).");
  }
  await db.sweepNonces(now, 600);

  // Rate limits (per key hash + per IP): the brute-force surface.
  const keyHash = await keyHashOf(key);
  const limited = await checkRate(db, env, ACTIVATE_RATE, `act:key:${keyHash.slice(0, 16)}`, ipHash, now);
  if (limited) {
    await db.audit({
      event: "denied",
      reason: "RATE_LIMITED",
      keyLast4: key.slice(-4),
      platform,
      ipHash,
      now,
    });
    return limited;
  }

  const license = await db.licenseByHash(keyHash);
  if (!license) {
    await db.audit({ event: "denied", reason: "KEY_NOT_FOUND", keyLast4: key.slice(-4), platform, ipHash, now });
    return fail(404, "KEY_NOT_FOUND", "That license key isn't in our records. Check it and try again.");
  }
  const last4 = license.key_last4;

  if (license.status === "revoked" || license.status === "refunded") {
    await db.audit({ licenseId: license.id, keyLast4: last4, event: "denied", reason: `KEY_${license.status.toUpperCase()}`, platform, ipHash, now });
    return fail(403, license.status === "revoked" ? "KEY_REVOKED" : "KEY_REFUNDED", "This license key is no longer active. Contact support.");
  }
  if (license.status === "pending") {
    return fail(403, "KEY_PENDING", "This license key hasn't been issued yet.");
  }
  if (license.expires_at !== null && license.expires_at <= now) {
    await db.audit({ licenseId: license.id, keyLast4: last4, event: "denied", reason: "LICENSE_EXPIRED", platform, ipHash, now });
    return fail(403, "LICENSE_EXPIRED", "Your yearly license has expired — renew to keep DiskBytes Pro.");
  }

  // Bind the slot (race-safe: the partial unique index is the
  // invariant; the explicit SELECT is just the fast path).
  let deviceRow;
  let outcome: "new" | "refresh" | "revive";
  try {
    const existing = await db.deviceByLicensePlatformHw(license.id, platform, hw);
    if (existing && existing.revoked === 0) {
      // Same hardware re-activating (reinstall): refresh facts, note
      // anything that changed since the last time we saw this device.
      const changes = detectChanges(claim, existing);
      await db.touchDevice(existing.id, claim, now);
      if (changes.event === "device_update") {
        await db.audit({ licenseId: license.id, keyLast4: last4, event: changes.event, platform, hwPrefix: hw.slice(0, 12), ipHash, detail: changes.detail, now });
      }
      deviceRow = { ...existing, last_seen_at: now };
      outcome = "refresh";
    } else if (existing && existing.revoked === 1) {
      // Same hardware on a support-reset row: re-register — the atomic
      // revive refuses when another live device now holds the slot.
      deviceRow = await db.reviveDevice(license.id, existing.id, platform, now);
      await db.touchDevice(deviceRow.id, claim, now);
      outcome = "revive";
    } else {
      deviceRow = await db.insertDevice(license.id, claim, now);
      outcome = "new";
    }
  } catch (err) {
    if (isSlotTaken(err)) {
      await db.audit({ licenseId: license.id, keyLast4: last4, event: "denied", reason: "DEVICE_SLOT_TAKEN", platform, hwPrefix: hw.slice(0, 12), ipHash, now });
      return fail(
        409,
        "DEVICE_SLOT_TAKEN",
        "This key is already activated on another device. Contact support to move your license.",
      );
    }
    throw err;
  }

  const token = await mintToken(
    env,
    { id: license.id, keyHash: license.key_hash, tier: license.tier, customerName: license.customer_name, customerEmail: license.customer_email, expiresAt: license.expires_at },
    { platform, hardwareHash: hw },
    now,
  );
  await db.audit({ licenseId: license.id, keyLast4: last4, event: "activate", platform, hwPrefix: hw.slice(0, 12), ipHash, detail: outcome, now });
  return json(200, entitlementResponse(token, {
    tier: license.tier,
    customerName: license.customer_name,
    customerEmail: license.customer_email,
    expiresAt: license.expires_at,
    keyLast4: last4,
  }, { platform, activatedAt: deviceRow.activated_at, lastSeenAt: now }) satisfies EntitlementResponse);
}
