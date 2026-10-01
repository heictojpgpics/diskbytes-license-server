#!/usr/bin/env node
/**
 * Seed the LOCAL (miniflare/wrangler dev) D1 with one lifetime + one
 * yearly dev key so you can exercise activation end-to-end in `wrangler
 * dev` / the app's dev mode. NEVER run against --remote production.
 *
 *   node scripts/seed-local.mjs
 *   (prints the raw dev keys, inserts hashes via wrangler d1 execute)
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import * as ed from "@noble/ed25519";
import { createHash, randomBytes } from "node:crypto";

const run = promisify(execFile);

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function genKey() {
  const b = randomBytes(20);
  let body = "";
  for (const x of b) body += ALPHABET[x % 32];
  return "DB" + body;
}
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

const now = Math.floor(Date.now() / 1000);
const entries = [
  { key: genKey(), tier: "lifetime", expiresAt: null },
  { key: genKey(), tier: "yearly", expiresAt: now + 365 * 86400 },
];
const statements = entries.map((e) => {
  const last4 = e.key.slice(-4);
  return `INSERT INTO licenses (key_hash, key_last4, tier, status, customer_name, customer_email, note, source, issued_at, expires_at, created_at, updated_at) VALUES ('${sha256(e.key)}', '${last4}', '${e.tier}', 'active', 'Dev Tester', 'dev@diskgenie.local', 'local seed', 'seed', ${now}, ${e.expiresAt ?? "NULL"}, ${now}, ${now});`;
});
const sql = statements.join("\n");
await run("npx", ["wrangler", "d1", "execute", "DB", "--local", "--command", sql], { cwd: process.cwd() });
console.log("Seeded local D1 (lifetime + yearly dev keys):");
for (const e of entries) {
  const pretty = e.key.replace(/(.{5})(?=.)/g, "$1-");
  console.log(`  ${pretty}  (${e.tier}, dev@diskgenie.local)`);
}
