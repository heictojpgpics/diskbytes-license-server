/**
 * Test setup: apply the D1 schema to each test file's isolated storage.
 * Statement-by-statement (D1 exec's naive splitter chokes on multi-line
 * CREATE TABLE); comments are stripped first.
 */
import { beforeAll } from "vitest";
import { env } from "cloudflare:test";
import { INITIAL_SCHEMA } from "./schema";

beforeAll(async () => {
  const statements = INITIAL_SCHEMA.split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n")
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const stmt of statements) {
    await env.DB.prepare(stmt).run();
  }
});
