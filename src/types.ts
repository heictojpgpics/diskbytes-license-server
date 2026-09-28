/**
 * Shared types: the Worker environment (bindings) and the wire contracts.
 * Every route in src/routes/ consumes these; the app repo's Rust client
 * mirrors the response shapes (serde camelCase).
 */

/** Worker bindings (wrangler.jsonc + secrets). */
export interface Env {
  /** D1 database (binding "DB"). */
  DB: D1Database;
  /** Ed25519 seed, 64 hex chars — SECRET. Signs every entitlement token. */
  LICENSE_SIGNING_PRIVATE_KEY: string;
  /** Admin API bearer — SECRET. */
  ADMIN_API_KEY: string;
  /** Shared HMAC secret with the desktop client — SECRET (see README §9). */
  CLIENT_REQUEST_SECRET: string;
  /** Token offline-grace window in days (var, default 14). */
  TOKEN_TTL_DAYS?: string;
  /** Activate attempts per key per hour (var, default 10). */
  RATE_ACTIVATE_KEY_PER_HR?: string;
  /** Activate attempts per IP per hour (var, default 30). */
  RATE_ACTIVATE_IP_PER_HR?: string;
  /** Validate attempts per key per hour (var, default 60). */
  RATE_VALIDATE_KEY_PER_HR?: string;
}

/** The client's hardware fingerprint claim.
 *
 * v2 (additive — v1 clients simply omit the new fields):
 * the composite `hardwareHash` stays THE binding identity (algorithm
 * unchanged, so v1-activated devices re-match after upgrade). The
 * component hashes + descriptive facts give the server swap forensics
 * (which component changed: disk swap vs machine swap) and the admin
 * surface a real device census. Descriptive fields never gate access. */
export interface DeviceClaim {
  /** 64-hex client fingerprint (sha256 over platform machine identity). */
  hardwareHash: string;
  /** "windows" | "macos". */
  platform: string;
  /** Human-readable hostname (audit + support display). */
  hostname?: string;
  /** OS version string (audit + support display). */
  osVersion?: string;
  /** App semver (audit + support display). */
  appVersion?: string;
  /** sha256 of the machine identity component (64 hex) — Windows
   * MachineGuid / macOS IOPlatformUUID. Empty when the client could
   * not read it. */
  compMachine?: string;
  /** sha256 of the volume identity component (64 hex) — system-drive
   * serial / root fsid. */
  compVolume?: string;
  /** sha256 of the CPU identity component (64 hex) — CPUID brand. */
  compCpu?: string;
  /** CPU brand string for display ("Intel Core i7-1260P"). */
  cpuBrand?: string;
  /** Total physical memory (MB). */
  ramMb?: number;
  /** Machine model for display ("Dell Inc. XPS 15 9520"). */
  machineModel?: string;
}

/** Entitlement token payload (Ed25519-signed; b64url(json).b64url(sig)). */
export interface TokenPayload {
  iss: "db-license";
  ver: 1;
  jti: string;
  iat: number;
  exp: number;
  key: string;
  tier: "yearly" | "lifetime";
  name: string;
  email: string;
  hw: string;
  plat: "windows" | "macos";
  lexp: number | null;
}

/** The app-facing success body (activate + validate). */
export interface EntitlementResponse {
  ok: true;
  /** Signed compact token. */
  token: string;
  /** Decoded payload (for display without re-parsing the token). */
  license: {
    tier: "yearly" | "lifetime";
    name: string;
    email: string;
    /** unix seconds or null (lifetime). */
    expiresAt: number | null;
    last4: string;
  };
  device: {
    platform: "windows" | "macos";
    activatedAt: number;
    lastSeenAt: number;
  };
}

/** Error body: { ok:false, code, message } — codes are a stable contract. */
export interface ErrorResponse {
  ok: false;
  code: string;
  message: string;
}

/** A generated key from the admin API (the only place raw keys appear). */
export interface GeneratedKey {
  key: string;
  tier: "yearly" | "lifetime";
  name: string;
  email: string;
  expiresAt: number | null;
}
