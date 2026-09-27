/**
 * Token minting + response shaping. All timing inputs are unix SECONDS.
 * The client (Rust) independently re-verifies signature, hw, plat, key
 * hash, exp and lexp — this module is the issuance side only.
 */
import type { Env, EntitlementResponse, TokenPayload } from "./types";
import { randomHex, signToken } from "./crypto";
import { sha256Hex } from "./crypto";

/** Token grace window (seconds) — TOKEN_TTL_DAYS, default 14 days. */
export function tokenTtlSeconds(env: Env): number {
  const days = Number.parseInt(env.TOKEN_TTL_DAYS ?? "14", 10);
  const safe = Number.isFinite(days) && days > 0 && days <= 90 ? days : 14;
  return safe * 86_400;
}

/** Mint a signed token for a validated (license, device) pair. */
export async function mintToken(
  env: Env,
  license: {
    id: number;
    keyHash: string;
    tier: "yearly" | "lifetime";
    customerName: string;
    customerEmail: string;
    expiresAt: number | null;
  },
  device: { platform: "windows" | "macos"; hardwareHash: string },
  now: number,
): Promise<string> {
  const payload: TokenPayload = {
    iss: "db-license",
    ver: 1,
    jti: randomHex(16),
    iat: now,
    exp: now + tokenTtlSeconds(env),
    key: license.keyHash,
    tier: license.tier,
    name: license.customerName,
    email: license.customerEmail,
    hw: device.hardwareHash,
    plat: device.platform,
    lexp: license.expiresAt,
  };
  return signToken(env.LICENSE_SIGNING_PRIVATE_KEY, payload);
}

/** Build the app-facing success body. */
export function entitlementResponse(
  token: string,
  license: {
    tier: "yearly" | "lifetime";
    customerName: string;
    customerEmail: string;
    expiresAt: number | null;
    keyLast4: string;
  },
  device: { platform: "windows" | "macos"; activatedAt: number; lastSeenAt: number },
): EntitlementResponse {
  return {
    ok: true,
    token,
    license: {
      tier: license.tier,
      name: license.customerName,
      email: license.customerEmail,
      expiresAt: license.expiresAt,
      last4: license.keyLast4,
    },
    device,
  };
}

/** sha256(key) hex — the ONLY form of the key that persists. */
export function keyHashOf(normalizedKey: string): Promise<string> {
  return sha256Hex(normalizedKey);
}
