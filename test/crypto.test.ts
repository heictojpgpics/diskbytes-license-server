import { describe, expect, it } from "vitest";
import {
  b64url,
  b64urlDecode,
  fromHex,
  hmacHex,
  publicKeyFromSeed,
  randomHex,
  signToken,
  toHex,
  verifyToken,
} from "../src/crypto";
import { TEST_SIGNING_SEED } from "./constants";

describe("base64url", () => {
  it("roundtrips arbitrary bytes without padding", () => {
    for (const len of [0, 1, 2, 3, 31, 32, 64, 100]) {
      const bytes = new Uint8Array(len);
      crypto.getRandomValues(bytes);
      const round = b64urlDecode(b64url(bytes));
      expect([...round]).toEqual([...bytes]);
      expect(b64url(bytes)).not.toMatch(/[+/=]/);
    }
  });
});

describe("hex", () => {
  it("roundtrips", () => {
    const bytes = fromHex("deadbeef00ff");
    expect(toHex(bytes)).toBe("deadbeef00ff");
  });
  it("rejects malformed", () => {
    expect(() => fromHex("xyz")).toThrow();
    expect(() => fromHex("abc")).toThrow();
  });
});

describe("hmac", () => {
  it("is deterministic and key-bound", async () => {
    const a = await hmacHex("a".repeat(64), "message");
    const b = await hmacHex("a".repeat(64), "message");
    const c = await hmacHex("b".repeat(64), "message");
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("ed25519 sign/verify (the anti-spoofing core)", () => {
  it("verifies genuine tokens and rejects every tamper path", async () => {
    const pub = toHex(await publicKeyFromSeed(TEST_SIGNING_SEED));
    const payload = { iss: "db-license", ver: 1, hw: "ab".repeat(32), iat: 100, exp: 200 };
    const token = await signToken(TEST_SIGNING_SEED, payload);

    // Genuine → payload decoded.
    const ok = await verifyToken(pub, token);
    expect(ok).toEqual(payload);

    // Tampered payload (same signature) → rejected.
    const parts = token.split("."); const p = parts[0] ?? ""; const s = parts[1] ?? "";
    const decoded = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
    decoded.exp = 999_999; // privilege escalation attempt
    const escalated = `${b64url(new TextEncoder().encode(JSON.stringify(decoded)))}.${s}`;
    expect(await verifyToken(pub, escalated)).toBeNull();

    // Forged signature → rejected.
    expect(await verifyToken(pub, `${p}.${b64url(new Uint8Array(64))}`)).toBeNull();

    // Wrong public key (rotation / different server) → rejected.
    const otherPub = toHex(await publicKeyFromSeed(randomHex(32)));
    expect(await verifyToken(otherPub, token)).toBeNull();

    // Garbage shapes → rejected, never thrown.
    expect(await verifyToken(pub, "")).toBeNull();
    expect(await verifyToken(pub, "noseparator")).toBeNull();
    expect(await verifyToken(pub, "aaa.bbb")).toBeNull();
  });
});
