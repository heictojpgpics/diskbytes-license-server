/**
 * POST /v1/validate — the 24 h revalidation endpoint. Checks license
 * status, expiry, and that THIS device is still the bound one; mints a
 * fresh token on success. Explicit invalid outcomes (revoked, expired,
 * device revoked/mismatch) return the contract codes the client treats
 * as hard failures (local deactivate), NOT network errors.
 */
import type { Env } from "../types";
import { Db } from "../db";
import { entitlementResponse, keyHashOf, mintToken } from "../tokens";
import type { EntitlementResponse } from "../types";
import { verifyAppRequest, type GuardFailure } from "../guard";
import { sha256Hex } from "../crypto";

interface ValidateBody {
  licenseKey: string;
  hardwareHash: string;
  platform: string;
}

const json = (status: number, body: object): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const fail = (status: number, code: string, message: string): Response =>
  json(status, { ok: false, code, message });

const GUARD_STATUS: Record<GuardFailure, number> = {
  BAD_SIGNATURE: 401,
  BAD_TIMESTAMP: 401,
  REPLAYED: 401,
  BAD_UA: 403,
  BAD_ADMIN_KEY: 401,
};

export async function handleValidate(env: Env, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const raw = await request.text();
  const guard = await verifyAppRequest(env, request, url.pathname, raw);
  if ("fail" in guard) {
    await new Db(env.DB).audit({ event: "denied", reason: guard.fail, now: nowSec() });
    return fail(GUARD_STATUS[guard.fail], guard.fail, "Request rejected.");
  }

  let body: ValidateBody;
  try {
    body = JSON.parse(raw) as ValidateBody;
  } catch {
    return fail(400, "BAD_REQUEST", "Malformed request body.");
  }
  const key = (body.licenseKey ?? "").toUpperCase().replace(/[^0-9A-Z]/g, "");
  const hw = (body.hardwareHash ?? "").toLowerCase();
  const platform = body.platform;
  if (key.length !== 22 || !/^[0-9a-f]{64}$/.test(hw) || (platform !== "windows" && platform !== "macos")) {
    return fail(400, "BAD_REQUEST", "Malformed request body.");
  }

  const db = new Db(env.DB);
  const now = nowSec();
  if (!(await db.consumeNonce(request.headers.get("x-db-nonce") ?? "", now))) {
    return fail(401, "REPLAYED", "Request rejected (replayed).");
  }
  await db.sweepNonces(now, 600);
  const ipHash = await sha256Hex(`ip:${request.headers.get("cf-connecting-ip") ?? "unknown"}`);

  const keyHash = await keyHashOf(key);
  const license = await db.licenseByHash(keyHash);
  if (!license) {
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

  await db.touchDevice(device.id, { hardwareHash: hw, platform }, now);
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

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}
