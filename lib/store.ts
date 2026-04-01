import { ScanRecord, ScanRequestInput, ScanStatus } from "@/lib/types";
import { createId } from "@/lib/utils";

declare global {
  // Preserve in-memory scans across Next.js dev reloads in the same process.
  var __vulnPilotScans__: Map<string, ScanRecord> | undefined;
}

const scans = globalThis.__vulnPilotScans__ ?? new Map<string, ScanRecord>();

if (!globalThis.__vulnPilotScans__) {
  globalThis.__vulnPilotScans__ = scans;
}

function now() {
  return new Date().toISOString();
}

export async function createScan(input: ScanRequestInput) {
  const id = createId("scan");
  const record: ScanRecord = {
    id,
    status: "queued",
    createdAt: now(),
    updatedAt: now(),
    input,
    repoUrl: input.repoUrl,
    summary: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },
    findings: [],
    frameworks: [],
    languages: [],
    notes: []
  };

  scans.set(id, record);
  return record;
}

export async function getScan(id: string) {
  return scans.get(id) ?? null;
}

export async function listScans() {
  return [...scans.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function updateScan(id: string, patch: Partial<ScanRecord>) {
  const current = scans.get(id);
  if (!current) {
    return null;
  }

  const next = {
    ...current,
    ...patch,
    updatedAt: now()
  };

  scans.set(id, next);
  return next;
}

export async function setScanStatus(id: string, status: ScanStatus, error?: string) {
  return updateScan(id, { status, error });
}
