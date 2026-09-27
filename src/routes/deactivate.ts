/**
 * POST /v1/deactivate — frees THIS device's platform slot (the app calls
 * it from the Pro status card; support can also do it via the admin
 * device API). Idempotent: unknown key/device still returns ok so the
 * client always clears local state.
 */
import type { Env } from "../types";
import { Db } from "../db";
import { keyHashOf } from "../tokens";
import { verifyAppRequest, type GuardFailure } from "../guard";
import { sha256Hex } from "../crypto";

interface DeactivateBody {
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

export async function handleDeactivate(env: Env, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const raw = await request.text();
  const guard = await verifyAppRequest(env, request, url.pathname, raw);
  if ("fail" in guard) {
    return fail(GUARD_STATUS[guard.fail], guard.fail, "Request rejected.");
  }

  let body: DeactivateBody;
  try {
    body = JSON.parse(raw) as DeactivateBody;
  } catch {
    return fail(400, "BAD_REQUEST", "Malformed request body.");
  }
  const key = (body.licenseKey ?? "").toUpperCase().replace(/[^0-9A-Z]/g, "");
  const hw = (body.hardwareHash ?? "").toLowerCase();
  const platform = body.platform === "macos" ? "macos" : "windows";
  if (key.length !== 22 || !/^[0-9a-f]{64}$/.test(hw)) {
    return fail(400, "BAD_REQUEST", "Malformed request body.");
  }

  const db = new Db(env.DB);
  const now = Math.floor(Date.now() / 1000);
  if (!(await db.consumeNonce(request.headers.get("x-db-nonce") ?? "", now))) {
    return fail(401, "REPLAYED", "Request rejected (replayed).");
  }
  const ipHash = await sha256Hex(`ip:${request.headers.get("cf-connecting-ip") ?? "unknown"}`);

  const keyHash = await keyHashOf(key);
  const license = await db.licenseByHash(keyHash);
  if (license) {
    const device = await db.deviceByLicensePlatformHw(license.id, platform, hw);
    if (device) {
      await db.revokeDevice(device.id, now);
      await db.audit({ licenseId: license.id, keyLast4: license.key_last4, event: "deactivate", platform, hwPrefix: hw.slice(0, 12), ipHash, now });
    }
  }
  return json(200, { ok: true });
}
