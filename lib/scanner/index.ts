import { AnalysisResult, RepoSnapshot, ScanRequestInput } from "@/lib/types";
import { enrichFindingWithLlm } from "@/lib/llm";
import { scanDependencies } from "@/lib/scanner/dependencies";
import { scanRuleMatches } from "@/lib/scanner/rules";
import { scanSecrets } from "@/lib/scanner/secrets";

export async function analyzeRepository(
  snapshot: RepoSnapshot,
  input: ScanRequestInput
): Promise<AnalysisResult> {
  const notes = [
    "Passive analysis only. No active exploit attempts or deployed URL probing were performed.",
    `Scan coverage included ${snapshot.stats.totalFiles} text files and ${snapshot.stats.totalBytes.toLocaleString()} bytes.`
  ];

  const findings = [
    ...scanRuleMatches(snapshot.files),
    ...scanDependencies(snapshot.files),
    ...scanSecrets(snapshot.files)
  ];

  if (input.llm?.apiKey) {
    notes.push("LLM enrichment enabled for top findings using user-supplied credentials.");
    const topFindings = findings
      .sort((left, right) => severityScore(right.severity) - severityScore(left.severity))
      .slice(0, 5);

    for (const candidate of topFindings) {
      const enriched = await enrichFindingWithLlm(candidate, snapshot, input.llm);
      if (!enriched) continue;
      const index = findings.findIndex((finding) => finding.id === candidate.id);
      if (index >= 0) {
        findings[index] = enriched;
      }
    }
  } else {
    notes.push("LLM enrichment skipped. Remediation text came from curated rule guidance.");
  }

  if (!snapshot.languages.length) {
    notes.push("No strongly supported application languages were detected. Results may be sparse.");
  }

  return {
    findings,
    frameworks: snapshot.frameworks,
    languages: snapshot.languages,
    notes
  };
}

function severityScore(severity: string) {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}
