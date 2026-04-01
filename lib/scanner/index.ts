import { AnalysisResult, Finding, RepoSnapshot, ScanRequestInput } from "@/lib/types";
import { analyzeRepositoryWithLlm } from "@/lib/llm";
import { getServerLlmConfig } from "@/lib/llm-config";

export async function analyzeRepository(
  snapshot: RepoSnapshot,
  input: ScanRequestInput
): Promise<AnalysisResult> {
  const notes = [
    "Passive analysis only. No active exploit attempts or deployed URL probing were performed.",
    `Scan coverage included ${snapshot.stats.totalFiles} text files and ${snapshot.stats.totalBytes.toLocaleString()} bytes.`
  ];
  const llmConfig = getServerLlmConfig();
  let findings: Finding[] = [];

  if (llmConfig) {
    notes.push(`LLM-first analysis enabled using the configured ${llmConfig.model} model.`);
    try {
      findings = await analyzeRepositoryWithLlm(snapshot, llmConfig);
      if (!findings.length) {
        notes.push("The model did not return any concrete vulnerabilities for the reviewed repository chunks.");
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown LLM error.";
      notes.push(`LLM analysis failed: ${message}`);
    }
  } else {
    notes.push("LLM analysis skipped because no server-side LLM secrets are configured.");
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
