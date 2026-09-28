/**
 * Cryptography helpers: Ed25519 entitlement signing, request HMAC
 * verification, base64url, constant-time comparison.
 *
 * @noble/ed25519 is pure JS and runs identically in Workers, Node, and
 * CI — one audited implementation everywhere (noble is the industry
 * standard for JS curves; audited 2024, see README §Dependencies).
 */
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

// Wire the synchronous SHA-512 provider (noble v3 leaves it unset by
// default; getPublicKey + verify need it, signAsync falls back to
// WebCrypto). @noble/hashes/sha2 is pure JS — identical behavior in
// Workers, Node, and the vitest workerd pool.
ed.hashes.sha512 = sha512;

/** RFC 4648 base64url without padding (token encoding). */
export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url (padding optional). */
export function b64urlDecode(s: string): Uint8Array {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = norm + "=".repeat((4 - (norm.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Hex encode. */
export function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Hex decode (64-hex secrets/keys). */
export function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Constant-time string compare (HMAC/admin-key checks). */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** SHA-256 hex of a string. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return toHex(new Uint8Array(digest));
}

/** HMAC-SHA256 hex over a string with a hex key. */
export async function hmacHex(keyHex: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    fromHex(keyHex) as unknown as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return toHex(new Uint8Array(sig));
}

// ── Ed25519 ────────────────────────────────────────────────────────────

/** Extract the 32-byte public key from a 64-hex seed. */
export async function publicKeyFromSeed(seedHex: string): Promise<Uint8Array> {
  const seed = fromHex(seedHex);
  return ed.getPublicKey(seed);
}

/**
 * Sign a payload JSON string → compact token `b64url(payload).b64url(sig)`.
 * The payload is signed byte-exact (the client verifies the same bytes).
 */
export async function signToken(seedHex: string, payload: object): Promise<string> {
  const payloadJson = JSON.stringify(payload);
  const payloadBytes = new TextEncoder().encode(payloadJson);
  const seed = fromHex(seedHex);
  const sig = await ed.signAsync(payloadBytes, seed);
  return `${b64url(payloadBytes)}.${b64url(sig)}`;
}

/**
 * Verify a compact token (used by tests + a debug endpoint; the client
 * performs the identical check in Rust with the public key).
 */
export async function verifyToken(
  pubKeyHex: string,
  token: string,
): Promise<object | null> {
  const dot = token.indexOf(".");
  if (dot <= 0) return null;
  const payloadB = b64urlDecode(token.slice(0, dot));
  const sig = b64urlDecode(token.slice(dot + 1));
  if (sig.length !== 64) return null;
  const ok = await ed.verify(sig, payloadB, fromHex(pubKeyHex));
  if (!ok) return null;
  try {
    return JSON.parse(new TextDecoder().decode(payloadB)) as object;
  } catch {
    return null;
  }
}

/** Fresh lowercase-hex random of `n` bytes. */
export function randomHex(n: number): string {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return toHex(b);
}

// ── IP-hash salt (v2) ──────────────────────────────────────────────────
//
// v1 hashed `sha256("ip:" + ip)` — unsalted, so the schema's "salted"
// comment was false and the hash was enumerable by anyone who could
// test-candidate IPs against a leaked digest. The salt is now derived
// from the Ed25519 signing seed (a value that NEVER ships in the
// client), memoized per isolate (the seed is immutable per deploy).
// Rotation note: rotating the signing key also rotates the salt —
// pre-rotation ip_hash values stop matching; acceptable + documented.

let ipSaltCache: string | null = null;

/** The per-deployment IP-hash salt (derived; memoized per isolate). */
export async function ipSalt(env: { LICENSE_SIGNING_PRIVATE_KEY: string }): Promise<string> {
  if (ipSaltCache === null) {
    ipSaltCache = await sha256Hex(`${env.LICENSE_SIGNING_PRIVATE_KEY}:ip-salt:v2`);
  }
  return ipSaltCache;
}

/** Salted, non-enumerable hash of the caller IP (audit storage form). */
export async function ipHashOf(env: { LICENSE_SIGNING_PRIVATE_KEY: string }, ip: string | null): Promise<string> {
  const salt = await ipSalt(env);
  return sha256Hex(`${salt}:${ip ?? "unknown"}`);
}
