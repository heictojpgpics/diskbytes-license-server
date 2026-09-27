/**
 * License key generation + normalization.
 *
 * Format: `DB-XXXXX-XXXXX-XXXXX-XXXXX` — Crockford base32 (alphabet
 * 0123456789ABCDEFGHJKMNPQRSTVWXYZ — no I/L/O/U, no confusables),
 * 20 random chars = 100 bits of entropy. Normalized form (what gets
 * hashed and what the app's "key complete" check measures): uppercase,
 * alphanumerics only, 22 chars total ("DB" + 20).
 */

/** Crockford base32 alphabet (excludes I, L, O, U). */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Valid normalized key: "DB" + 20 crockford chars = 22. */
const KEY_RE = /^DB[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{20}$/;

/** Generate one raw key in display form. */
export function generateKey(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  let body = "";
  for (const b of bytes) body += ALPHABET[b % 32];
  return `DB-${body.slice(0, 5)}-${body.slice(5, 10)}-${body.slice(10, 15)}-${body.slice(15, 20)}`;
}

/**
 * Normalize user input: uppercase, strip everything non-alphanumeric.
 * Accepts lowercase input, spaces, dots as dashes, etc.
 */
export function normalizeKey(input: string): string {
  return input.toUpperCase().replace(/[^0-9A-Z]/g, "");
}

/** Structural validity of a normalized key (22 chars, DB prefix). */
export function isValidKeyShape(normalized: string): boolean {
  return KEY_RE.test(normalized);
}

/** Display grouping `XXXXX-XXXXX-XXXXX-XXXXX-XXXX` of a normalized key. */
export function formatKey(normalized: string): string {
  return normalized.replace(/(.{5})(?=.)/g, "$1-");
}
