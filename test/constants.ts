/**
 * Test-only identities (worker secrets injected by vitest.config.ts via
 * miniflare bindings). NEVER the production values — production secrets
 * are set with `wrangler secret put` (README §Deploy).
 *
 * The Ed25519 seed below is RFC 8032 test-vector #1; the derived public
 * key is 4cb5abf19e2cbb12e6c6a1b5b1a5d1c9c2b9a0f... style fixture that
 * the app repo's Rust tests also embed, so both sides of the token
 * contract are pinned by the same fixture.
 */
export const TEST_SIGNING_SEED =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
export const TEST_ADMIN_KEY = "test-admin-key-0123456789abcdef";
export const TEST_CLIENT_SECRET =
  "a3f7c2d1e4b5a6978f0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a";
