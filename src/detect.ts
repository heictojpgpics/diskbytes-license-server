/**
 * Device-change detection (v2): when a known device checks in with a
 * fresh claim, compare it to the stored row and describe WHAT changed
 * — OS upgrade, app update, hostname rename, hardware-swap signals.
 * The comparison feeds the audit trail (detail column) so support can
 * distinguish "user updated Windows" from "user moved the disk" at a
 * glance. Detection NEVER gates access (the composite hardware hash
 * is the binding); it is forensics + display.
 */
import type { DeviceClaim } from "./types";
import type { DeviceRow } from "./db";

export interface DeviceChanges {
  /** Audit event name ("device_update" when anything changed). */
  event: "device_update" | "checkin";
  /** Compact JSON: {"osVersion":["Win 11","Win 12"],...} old → new. */
  detail: string | null;
}

/** Which stored columns the claim is allowed to refresh + their labels. */
const TEXT_FIELDS: { key: keyof DeviceClaim; col: keyof DeviceRow; label: string }[] = [
  { key: "hostname", col: "hostname", label: "hostname" },
  { key: "osVersion", col: "os_version", label: "osVersion" },
  { key: "appVersion", col: "app_version", label: "appVersion" },
  { key: "cpuBrand", col: "cpu_brand", label: "cpuBrand" },
  { key: "machineModel", col: "machine_model", label: "machineModel" },
  { key: "compMachine", col: "comp_machine", label: "compMachine" },
  { key: "compVolume", col: "comp_volume", label: "compVolume" },
  { key: "compCpu", col: "comp_cpu", label: "compCpu" },
];

/**
 * Diff a fresh claim against the stored row. Only NEW values count as
 * changes (COALESCE semantics on the write side: absent fields never
 * revert). RAM uses a ≥ 25% threshold — module swaps under warranty
 * report slightly different sizes.
 */
export function detectChanges(claim: DeviceClaim, row: DeviceRow): DeviceChanges {
  const changes: Record<string, [string | null, string | null]> = {};
  for (const f of TEXT_FIELDS) {
    const incoming = claim[f.key] as string | undefined;
    if (incoming === undefined) continue;
    const stored = row[f.col] as string | null;
    if (stored !== incoming) {
      changes[f.label] = [stored, incoming];
    }
  }
  if (claim.ramMb !== undefined && row.ram_mb !== null) {
    const drift = Math.abs(claim.ramMb - row.ram_mb) / Math.max(row.ram_mb, 1);
    if (drift >= 0.25) {
      changes.ramMb = [String(row.ram_mb), String(claim.ramMb)];
    }
  }
  const keys = Object.keys(changes);
  if (keys.length === 0) {
    return { event: "checkin", detail: null };
  }
  return { event: "device_update", detail: JSON.stringify(changes) };
}
