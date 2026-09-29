import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { TEST_SIGNING_SEED, TEST_ADMIN_KEY, TEST_CLIENT_SECRET } from "./test/constants";

// Real Workers runtime + real D1 (miniflare) via the Cloudflare pool —
// the tests execute the ACTUAL worker code with the ACTUAL wrangler.jsonc
// binding, so route logic, signing, and the D1 schema are exercised
// exactly as deployed. (vitest-4 plugin pattern: `cloudflareTest` takes
// the former `poolOptions.workers` options object.)
export default defineConfig({
  test: {
    setupFiles: ["./test/setup.ts"],
  },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // Test-only secrets (never the production values) — see
        // test/constants.ts.
        bindings: {
          LICENSE_SIGNING_PRIVATE_KEY: TEST_SIGNING_SEED,
          ADMIN_API_KEY: TEST_ADMIN_KEY,
          CLIENT_REQUEST_SECRET: TEST_CLIENT_SECRET,
          TOKEN_TTL_DAYS: "14",
        },
        // Second D1 database (v2-shaped) for the self-healing schema
        // bootstrap test — a deploy where the Worker updated but the
        // migration lagged must keep working. (Pool-workers' override
        // form: binding → database id string.)
        d1Databases: { DB_V2: "v2-schema-test-db" },
      },
    }),
  ],
});
