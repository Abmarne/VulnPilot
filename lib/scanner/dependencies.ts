import { Finding, RepoFile } from "@/lib/types";
import { createId } from "@/lib/utils";

const FLAGGED_PACKAGES: Array<{
  packageName: string;
  ecosystem: "npm" | "pip";
  severity: Finding["severity"];
  title: string;
  whyItMatters: string;
  suggestedFix: string;
}> = [
  {
    packageName: "lodash@4.17.15",
    ecosystem: "npm",
    severity: "high",
    title: "Known vulnerable lodash version",
    whyItMatters: "Older lodash releases have known prototype-pollution and command-injection style risks in some usage patterns.",
    suggestedFix: "Upgrade lodash to the latest 4.17.x patch release or newer and verify lockfiles are refreshed."
  },
  {
    packageName: "pyyaml==5.3",
    ecosystem: "pip",
    severity: "medium",
    title: "Outdated PyYAML version detected",
    whyItMatters: "Older PyYAML versions have had unsafe loader and parsing issues that make review important.",
    suggestedFix: "Upgrade PyYAML and use safe loaders by default."
  }
];

export function scanDependencies(files: RepoFile[]) {
  const findings: Finding[] = [];

  for (const file of files) {
    const lower = file.content.toLowerCase();

    for (const entry of FLAGGED_PACKAGES) {
      const packageToken = entry.packageName.toLowerCase();
      const matchesEcosystem =
        (entry.ecosystem === "npm" && file.path.endsWith("package-lock.json")) ||
        (entry.ecosystem === "pip" && file.path.endsWith("requirements.txt"));

      if (!matchesEcosystem || !lower.includes(packageToken)) continue;

      findings.push({
        id: createId("dep"),
        title: entry.title,
        severity: entry.severity,
        confidence: "likely",
        category: "vulnerable_dependency",
        cwe: "CWE-1104",
        owasp: "A06:2021 Vulnerable and Outdated Components",
        file: file.path,
        line: file.content.split("\n").findIndex((line) => line.toLowerCase().includes(packageToken)) + 1,
        evidence: entry.packageName,
        whyItMatters: entry.whyItMatters,
        suggestedFix: entry.suggestedFix,
        source: "dependency_audit",
        language: file.language
      });
    }
  }

  return findings;
}
