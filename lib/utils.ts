import { Finding, ScanSummary, Severity } from "@/lib/types";

export function slugify(input: string) {
  return input.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

export function createId(prefix: string) {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

export function summarizeFindings(findings: Finding[]): ScanSummary {
  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const finding of findings) {
    summary[finding.severity] += 1;
  }

  return {
    total: findings.length,
    ...summary
  };
}

export function escapeMarkdown(input: string) {
  return input.replace(/[\\`*_{}[\]()#+\-.!]/g, "\\$&");
}
