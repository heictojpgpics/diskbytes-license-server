#!/usr/bin/env node
/**
 * Admin-side key batch generator — calls the deployed Worker's admin API.
 *
 *   node scripts/generate-keys.mjs https://license.example.com <ADMIN_API_KEY> \
 *        --tier lifetime --name "Alex Morgan" --email "alex@example.com" [--count 5] [--note "..."]
 *
 * Prints the raw keys (the ONLY time they exist) — pipe into your email
 * merge tool / payment webhook handler. The production pattern is to
 * call the same endpoint FROM the payment webhook (README §6).
 */
const [base, adminKey, ...rest] = process.argv.slice(2);
if (!base || !adminKey) {
  console.error("usage: node scripts/generate-keys.mjs <worker-base-url> <admin-key> --tier lifetime|yearly --name <name> --email <email> [--count n] [--note s] [--days n]");
  process.exit(1);
}
const args = rest.reduce((acc, cur, i, arr) => {
  if (cur.startsWith("--")) acc[cur.slice(2)] = arr[i + 1];
  return acc;
}, {});

const res = await fetch(base.replace(/\/$/, "") + "/v1/admin/keys", {
  method: "POST",
  headers: { "content-type": "application/json", authorization: `Bearer ${adminKey}` },
  body: JSON.stringify({
    count: Number(args.count ?? 1),
    tier: args.tier ?? "lifetime",
    customerName: args.name ?? "Customer",
    customerEmail: args.email ?? "customer@example.com",
    note: args.note ?? null,
    days: args.days ? Number(args.days) : undefined,
  }),
});
if (!res.ok) {
  console.error(`admin API failed: HTTP ${res.status}`);
  console.error(await res.text());
  process.exit(1);
}
const body = await res.json();
for (const k of body.keys) {
  console.log(`${k.key}\t${k.tier}\t${k.name}\t${k.email}\t${k.expiresAt ?? "lifetime"}`);
}
