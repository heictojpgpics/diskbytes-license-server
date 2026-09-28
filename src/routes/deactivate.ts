/**
 * POST /v1/deactivate — frees THIS device's platform slot (the app calls
 * it when moving a machine; support can also do it via the admin device
 * API). Idempotent: unknown key/device still returns ok so the client
 * always clears local state.
 *
 * v2: platform is strictly validated (v1 silently coerced garbage to
 * "windows"); missing keys are audited; rate-limited like the other
 * authenticated routes.
 */
import type { Env } from "../types";
import { Db } from "../db";
import { keyHashOf } from "../tokens";
import {
  fail,
  json,
  normalizeKeyClaim,
  isValidPlatform,
  nowSec,
  checkRate,
  DEACTIVATE_RATE,
  verifyAndParse,
} from "./shared";

interface DeactivateBody {
  licenseKey?: unknown;
  hardwareHash?: unknown;
  platform?: unknown;
}

export async function handleDeactivate(env: Env, request: Request): Promise<Response> {
  const url = new URL(request.url);
  const guard = await verifyAndParse<DeactivateBody>(env, request, url.pathname);
  if ("fail" in guard) return guard.fail;
  const { body, ipHash } = guard.ok;

  const key = normalizeKeyClaim(body.licenseKey);
  const hw = typeof body.hardwareHash === "string" ? body.hardwareHash.toLowerCase() : "";
  if (key.length !== 22 || !/^[0-9a-f]{64}$/.test(hw) || !isValidPlatform(body.platform)) {
    return fail(400, "BAD_REQUEST", "Malformed request body.");
  }
  const platform = body.platform;

  const db = new Db(env.DB);
  const now = nowSec();
  if (!(await db.consumeNonce(request.headers.get("x-db-nonce") ?? "", now))) {
    return fail(401, "REPLAYED", "Request rejected (replayed).");
  }
  await db.sweepNonces(now, 600);

  const keyHash = await keyHashOf(key);
  const limited = await checkRate(db, env, DEACTIVATE_RATE, `dea:key:${keyHash.slice(0, 16)}`, ipHash, now);
  if (limited) return limited;

  const license = await db.licenseByHash(keyHash);
  if (license) {
    const device = await db.deviceByLicensePlatformHw(license.id, platform, hw);
    if (device) {
      await db.revokeDevice(device.id, now);
      await db.audit({ licenseId: license.id, keyLast4: license.key_last4, event: "deactivate", platform, hwPrefix: hw.slice(0, 12), ipHash, now });
    } else {
      await db.audit({ licenseId: license.id, keyLast4: license.key_last4, event: "deactivate", reason: "not-registered", platform, ipHash, now });
    }
  } else {
    await db.audit({ event: "deactivate", reason: "KEY_NOT_FOUND", keyLast4: key.slice(-4), platform, ipHash, now });
  }
  return json(200, { ok: true });
}
