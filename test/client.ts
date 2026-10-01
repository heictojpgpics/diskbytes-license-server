/**
 * The test-side app client — mirrors the Rust client's request signing
 * (X-DB-* headers + HMAC over ts.nonce.method.path.sha256(body)) so the
 * tests exercise the EXACT wire contract the desktop app speaks.
 */
import { hmacHex, randomHex, sha256Hex } from "../src/crypto";
import { TEST_CLIENT_SECRET } from "./constants";

export const UA = "DiskGenie-License-Client/1";

export interface RequestOpts {
  timestamp?: number;
  nonce?: string;
  signature?: string;
  userAgent?: string;
}

export async function signedRequest(
  method: "POST" | "GET",
  path: string,
  body: object,
  opts: RequestOpts = {},
): Promise<Request> {
  const raw = JSON.stringify(body);
  const timestamp = opts.timestamp ?? Date.now();
  const nonce = opts.nonce ?? randomHex(16);
  const bodyHash = await sha256Hex(raw);
  const signature =
    opts.signature ??
    (await hmacHex(TEST_CLIENT_SECRET, `${timestamp}.${nonce}.${method}.${path}.${bodyHash}`));
  return new Request(`https://license.diskgenie.test${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      "user-agent": opts.userAgent ?? UA,
      "x-db-app": "diskgenie",
      "x-db-version": "0.1.0",
      "x-db-timestamp": String(timestamp),
      "x-db-nonce": nonce,
      "x-db-signature": signature,
    },
    body: raw,
  });
}

/** A canonical hardware fingerprint for tests (64 hex). */
export function hw(n: number): string {
  return String(n).padStart(64, "0").slice(0, 62) + String(n).padStart(2, "0");
}
