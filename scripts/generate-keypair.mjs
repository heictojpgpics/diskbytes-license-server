#!/usr/bin/env node
/**
 * Generate the Ed25519 keypair for token signing.
 *
 * Output: the 64-hex SEED (goes to `wrangler secret put
 * LICENSE_SIGNING_PRIVATE_KEY` on the Worker) and the 32-hex PUBLIC key
 * (goes into the app repo: src-tauri/src/license.rs
 * `LICENSE_PUBLIC_KEY_HEX`, and — if you rotate later — the Rust const
 * plus a released app update).
 *
 * Run ONCE per deployment (rotation procedure: README §8).
 */
import * as ed from "@noble/ed25519";
import { randomBytes } from "node:crypto";

const seed = randomBytes(32);
const pub = await ed.getPublicKey(seed);
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

console.log("LICENSE_SIGNING_PRIVATE_KEY (Worker secret):");
console.log("  " + hex(seed));
console.log();
console.log("LICENSE_PUBLIC_KEY_HEX (app repo, src-tauri/src/license.rs):");
console.log("  " + hex(pub));
console.log();
console.log("Keep the seed private. The public key is safe to embed in the app.");
