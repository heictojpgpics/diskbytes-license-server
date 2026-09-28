/**
 * POST /v1/validate — the 24 h revalidation endpoint. Checks license
 * status, expiry, and that THIS device is still the bound one; mints a
 * fresh token on success. Explicit invalid outcomes (revoked, expired,
 * device revoked/mismatch) return the contract codes the client treats
 * as hard failures (local deactivate), NOT network errors.
 *
 * v2 — THE WIPE FIX: the v1 handler called touchDevice with an EMPTY
 * claim {hardwareHash, platform}, and v1's touchDevice SET (not
 * COALESCE) every column — so the FIRST 24 h revalidation blanked
 * hostname/os_version/app_version to NULL. The owner saw exactly that
 * in the admin panel ("doesn't save hostname/windows version"). The
 * app now sends the FULL device claim on validate (same shape as
 * activate), the server sanitizes it, and touchDevice COALESCEs — a
 * missing field keeps the last known good value. Detectable changes
 * (OS upgrade, app update) land in the audit trail with a structured
 * diff.
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
  VALIDATE_RATE,
  verifyAndParse,
} from "./shared";

interface ValidateBody {
  licenseKey?: unknown;
  platform?: unknown;
  hardwareHash?: unknown;
  [k: string]: unknown;
}

export async function handleValidate(env: Env, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const guard = await verifyAndParse<ValidateBody>(env, request, url.pathname);
  if ("fail" in guard) return guard.fail;
  const { body, ipHash } = guard.ok;

  const key = normalizeKeyClaim(body.licenseKey);
  const hw = typeof body.hardwareHash === "string" ? body.hardwareHash.toLowerCase() : "";
  const platform = body.platform;
  if (key.length !== 22 || !/^[0-9a-f]{64}$/.test(hw) || !isValidPlatform(platform)) {
    return fail(400, "BAD_REQUEST", "Malformed request body.");
  }
  const claim = sanitizeClaim(body, platform, hw);
  if (!claim) return fail(400, "BAD_REQUEST", "Malformed device claim.");

  const db = new Db(env.DB);
  const now = nowSec();
  if (!(await db.consumeNonce(request.headers.get("x-db-nonce") ?? "", now))) {
    return fail(401, "REPLAYED", "Request rejected (replayed).");
  }
  await db.sweepNonces(now, 600);

  const keyHash = await keyHashOf(key);
  const limited = await checkRate(db, env, VALIDATE_RATE, `val:key:${keyHash.slice(0, 16)}`, ipHash, now);
  if (limited) return limited;

  const license = await db.licenseByHash(keyHash);
  if (!license) {
    await db.audit({ event: "denied", reason: "KEY_NOT_FOUND", keyLast4: key.slice(-4), platform, ipHash, now });
    return fail(404, "KEY_NOT_FOUND", "That license key isn't in our records.");
  }
  const denied = async (code: string, message: string): Promise<Response> => {
    await db.audit({ licenseId: license.id, keyLast4: license.key_last4, event: "denied", reason: code, platform, hwPrefix: hw.slice(0, 12), ipHash, now });
    return fail(403, code, message);
  };

  if (license.status === "revoked" || license.status === "refunded") {
    return denied(license.status === "revoked" ? "KEY_REVOKED" : "KEY_REFUNDED", "This license key is no longer active.");
  }
  if (license.expires_at !== null && license.expires_at <= now) {
    return denied("LICENSE_EXPIRED", "Your yearly license has expired — renew to keep DiskBytes Pro.");
  }

  const device = await db.deviceByLicensePlatformHw(license.id, platform, hw);
  if (!device) {
    return denied("DEVICE_MISMATCH", "This device is not registered with this license key.");
  }
  if (device.revoked === 1) {
    return denied("DEVICE_MISMATCH", "This device was deactivated. Activate again to re-register it.");
  }

  // THE FIX: refresh with the FULL claim (COALESCE on the write side).
  const changes = detectChanges(claim, device);
  await db.touchDevice(device.id, claim, now);
  if (changes.event === "device_update") {
    await db.audit({ licenseId: license.id, keyLast4: license.key_last4, event: changes.event, platform, hwPrefix: hw.slice(0, 12), ipHash, detail: changes.detail, now });
  }

  const token = await mintToken(
    env,
    { id: license.id, keyHash: license.key_hash, tier: license.tier, customerName: license.customer_name, customerEmail: license.customer_email, expiresAt: license.expires_at },
    { platform, hardwareHash: hw },
    now,
  );
  await db.audit({ licenseId: license.id, keyLast4: license.key_last4, event: "validate", platform, hwPrefix: hw.slice(0, 12), ipHash, now });
  return json(200, entitlementResponse(token, {
    tier: license.tier,
    customerName: license.customer_name,
    customerEmail: license.customer_email,
    expiresAt: license.expires_at,
    keyLast4: license.key_last4,
  }, { platform, activatedAt: device.activated_at, lastSeenAt: now }) satisfies EntitlementResponse);
}
