import { describe, expect, it } from "vitest";
import { formatKey, generateKey, isValidKeyShape, normalizeKey } from "../src/keys";

describe("license key shape", () => {
  it("generates 22-char crockford keys with the DB prefix", () => {
    for (let i = 0; i < 200; i++) {
      const key = generateKey();
      expect(key).toMatch(/^DB-[0-9A-HJKMNP-Z]{5}(-[0-9A-HJKMNP-Z]{5}){3}$/);
      const norm = normalizeKey(key);
      expect(norm.length).toBe(22);
      expect(norm.startsWith("DB")).toBe(true);
      expect(isValidKeyShape(norm)).toBe(true);
    }
  });

  it("never contains confusable characters", () => {
    for (let i = 0; i < 200; i++) {
      expect(generateKey()).not.toMatch(/[ILOU]/);
    }
  });

  it("normalizes messy user input", () => {
    expect(normalizeKey(" db-xk2m9-qf3p8 ")).toBe("DBXK2M9QF3P8");
    expect(normalizeKey("db.xk2m9-qf3p8nr4")).toBe("DBXK2M9QF3P8NR4");
    expect(normalizeKey("dbxk2m9qf3p8nr4")).toBe("DBXK2M9QF3P8NR4");
  });

  it("rejects wrong shapes", () => {
    expect(isValidKeyShape("DBXK2M9QF3P8NR4")).toBe(false); // 15 chars
    expect(isValidKeyShape("AB" + "X".repeat(20))).toBe(false); // wrong prefix
    expect(isValidKeyShape("DB" + "I".repeat(20))).toBe(false); // confusable letter
    expect(isValidKeyShape("")).toBe(false);
  });

  it("formats for display", () => {
    expect(formatKey("DBXK2M9QF3P8NR4T2VW6Y")).toBe("DBXK2-M9QF3-P8NR4-T2VW6-Y");
  });
});
