import { Finding, RepoFile, RepoSnapshot } from "@/lib/types";
import { createId } from "@/lib/utils";

export interface LlmInput {
  provider: string;
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

interface ChatMessage {
  role: "system" | "user";
  content: string;
}

interface StageNote {
  stage: "triage" | "extraction" | "consolidation";
  detail: string;
}

interface LlmAnalysisResult {
  findings: Finding[];
  notes: string[];
}

interface RankedFileCandidate {
  path?: string;
  priority?: number;
  reason?: string;
}

interface RankedFile {
  file: RepoFile;
  priority: number;
  reason: string;
}

interface LlmFindingCandidate {
  title?: string;
  severity?: Finding["severity"];
  confidence?: Finding["confidence"];
  category?: string;
  cwe?: string;
  owasp?: string;
  file?: string;
  line?: number;
  evidence?: string;
  triageNote?: string;
  whyItMatters?: string;
  suggestedFix?: string;
  language?: string;
}

interface ConsolidationResponse {
  findings?: LlmFindingCandidate[];
  qualityNote?: string;
}

const MAX_TRIAGE_FILE_COUNT = 18;
const MAX_FILES_PER_BATCH = 4;
const MAX_FILE_CHARS = 5200;
const MAX_FINDINGS_PER_BATCH = 4;
const MAX_FINAL_FINDINGS = 12;

export async function analyzeRepositoryWithLlm(repo: RepoSnapshot, llm: LlmInput): Promise<LlmAnalysisResult> {
  if (!llm.apiKey) {
    return { findings: [], notes: [] };
  }

  const stageNotes: StageNote[] = [];
  const triaged = await triageRepository(repo, llm, stageNotes);
  const extracted = await extractFindings(repo, triaged, llm, stageNotes);
  const consolidated = await consolidateFindings(repo, extracted, llm, stageNotes);

  const notes = stageNotes.map((note) => `${capitalize(note.stage)}: ${note.detail}`);
  if (consolidated.qualityNote) {
    notes.push(`Quality note: ${consolidated.qualityNote}`);
  }

  const lowConfidenceCount = consolidated.findings.filter((finding) => finding.confidence === "needs_review").length;
  if (consolidated.findings.length > 0 && lowConfidenceCount === consolidated.findings.length) {
    notes.push("Quality note: all returned findings need manual review because the model could not confidently verify exploitability.");
  }

  if (consolidated.findings.length === 0) {
    notes.push("Quality note: the quality filter removed speculative or weak findings, so no reviewer-facing issues were retained.");
  }

  return {
    findings: consolidated.findings,
    notes
  };
}

async function triageRepository(repo: RepoSnapshot, llm: LlmInput, notes: StageNote[]) {
  const triageCandidates = repo.files
    .filter((file) => shouldReviewFile(file))
    .slice(0, MAX_TRIAGE_FILE_COUNT);

  if (!triageCandidates.length) {
    notes.push({ stage: "triage", detail: "no reviewable files were selected for triage." });
    return [] as RankedFile[];
  }

  const prompt = [
    "Rank the most security-relevant files in this repository for vulnerability review.",
    "Prefer server-side request handlers, auth, middleware, config, secret-bearing files, and risky integrations.",
    "Return strict JSON with one key: files.",
    "files must be an array of objects with path, priority, reason.",
    "priority should be 1-10 and reason should be short.",
    `Repository: ${repo.repo.owner}/${repo.repo.name}`,
    `Frameworks: ${repo.frameworks.join(", ") || "unknown"}`,
    `Languages: ${repo.languages.join(", ") || "unknown"}`,
    "Available files:"
  ].join("\n");

  const fileList = triageCandidates.map((file) => `- ${file.path} (${file.language}, ${file.content.length} chars)`).join("\n");
  const parsed = await requestJson<{ files?: RankedFileCandidate[] }>(
    [
      {
        role: "system",
        content:
          "You are a senior application security reviewer. Rank files for review based on exploitability potential. Always return strict JSON."
      },
      {
        role: "user",
        content: `${prompt}\n${fileList}`
      }
    ],
    llm
  );

  const ranked = normalizeRankedFiles(triageCandidates, parsed?.files);
  notes.push({
    stage: "triage",
    detail: ranked.length
      ? `ranked ${ranked.length} candidate files for deeper review using model-guided prioritization.`
      : "triage returned no ranked files, so heuristic ranking was used."
  });

  return ranked;
}

async function extractFindings(repo: RepoSnapshot, rankedFiles: RankedFile[], llm: LlmInput, notes: StageNote[]) {
  const filesToReview = rankedFiles.length
    ? rankedFiles.map((entry) => entry.file)
    : repo.files.filter((file) => shouldReviewFile(file)).slice(0, MAX_TRIAGE_FILE_COUNT);
  const batches = chunk(filesToReview, MAX_FILES_PER_BATCH);
  const findings: Finding[] = [];
  let degradedBatches = 0;

  for (const [index, batch] of batches.entries()) {
    try {
      const parsed = await requestJson<{ findings?: LlmFindingCandidate[] }>(
        extractionMessages(repo, batch, index + 1, batches.length),
        llm
      );
      const candidates = Array.isArray(parsed?.findings) ? parsed.findings : [];

      for (const candidate of candidates) {
        const finding = normalizeCandidateFinding(candidate, repo, batch);
        if (finding) {
          findings.push(finding);
        }
      }
    } catch (error) {
      degradedBatches += 1;
      const message = error instanceof Error ? error.message : "unknown extraction error";
      notes.push({
        stage: "extraction",
        detail: `batch ${index + 1}/${batches.length} fell back to no findings after model output failure (${message}).`
      });
    }
  }

  notes.push({
    stage: "extraction",
    detail: degradedBatches
      ? `reviewed ${batches.length} batches with ${degradedBatches} degraded batch responses.`
      : `reviewed ${batches.length} batches with strict JSON extraction.`
  });

  return findings;
}

async function consolidateFindings(
  repo: RepoSnapshot,
  extractedFindings: Finding[],
  llm: LlmInput,
  notes: StageNote[]
) {
  const grounded = extractedFindings.filter((finding) => isGroundedFinding(finding, repo));
  const deduped = dedupeFindings(grounded);

  if (!deduped.length) {
    notes.push({
      stage: "consolidation",
      detail: "no grounded findings survived extraction, so the final report is empty."
    });
    return { findings: [] as Finding[], qualityNote: "" };
  }

  try {
    const parsed = await requestJson<ConsolidationResponse>(
      consolidationMessages(repo, deduped),
      llm
    );
    const consolidatedCandidates = Array.isArray(parsed?.findings) ? parsed.findings : [];
    const consolidated = consolidatedCandidates
      .map((candidate) => normalizeCandidateFinding(candidate, repo, repo.files))
      .filter((finding): finding is Finding => Boolean(finding))
      .filter((finding) => isGroundedFinding(finding, repo))
      .filter((finding) => passesAcceptanceRubric(finding))
      .sort((left, right) => compareFindings(left, right))
      .slice(0, MAX_FINAL_FINDINGS);

    notes.push({
      stage: "consolidation",
      detail: `reduced ${deduped.length} grounded findings to ${consolidated.length} reviewer-facing findings after dedupe and quality filtering.`
    });

    return {
      findings: consolidated,
      qualityNote: (parsed?.qualityNote || "").trim()
    };
  } catch (error) {
    const filtered = deduped
      .map((finding) => calibrateFinding(finding, repo))
      .filter((finding) => passesAcceptanceRubric(finding))
      .sort((left, right) => compareFindings(left, right))
      .slice(0, MAX_FINAL_FINDINGS);

    const message = error instanceof Error ? error.message : "unknown consolidation error";
    notes.push({
      stage: "consolidation",
      detail: `model consolidation failed (${message}), so heuristic dedupe and confidence calibration were used.`
    });

    return {
      findings: filtered,
      qualityNote: "Final findings were produced from heuristic consolidation after the model could not complete the final merge cleanly."
    };
  }
}

function extractionMessages(repo: RepoSnapshot, files: RepoFile[], batchNumber: number, totalBatches: number): ChatMessage[] {
  const prompt = [
    "Review this repository batch for concrete, exploitable vulnerabilities.",
    "Only report issues with a plausible security impact and code-supported exploit path.",
    "Do not report style issues, generic best-practice advice, broad architecture concerns, or hypothetical weaknesses without a visible sink.",
    `Repository: ${repo.repo.owner}/${repo.repo.name}`,
    `Frameworks: ${repo.frameworks.join(", ") || "unknown"}`,
    `Languages: ${repo.languages.join(", ") || "unknown"}`,
    `Batch: ${batchNumber}/${totalBatches}`,
    `Return JSON with one key: findings. findings must be an array of up to ${MAX_FINDINGS_PER_BATCH} objects.`,
    "Each finding must include title, severity, confidence, category, cwe, owasp, file, line, evidence, triageNote, whyItMatters, suggestedFix, language.",
    "Allowed severity values: critical, high, medium, low, info.",
    "Allowed confidence values: confirmed, likely, needs_review.",
    "Use confirmed only when the provided code directly supports exploitability.",
    "If no concrete vulnerabilities are present, return {\"findings\":[]}.",
    "",
    files
      .map((file) =>
        [`FILE: ${file.path}`, `LANGUAGE: ${file.language}`, "CODE:", "```", truncateFileContent(file.content, MAX_FILE_CHARS), "```"].join(
          "\n"
        )
      )
      .join("\n\n")
  ].join("\n");

  return [
    {
      role: "system",
      content:
        "You are a senior application security reviewer. Report only concrete vulnerabilities that can be grounded in the provided code. Always return strict JSON."
    },
    {
      role: "user",
      content: prompt
    }
  ];
}

function consolidationMessages(repo: RepoSnapshot, findings: Finding[]): ChatMessage[] {
  const prompt = [
    "Consolidate these extracted vulnerability findings into a final reviewer-facing set.",
    "Merge duplicates, remove speculative or low-signal findings, calibrate severity/confidence conservatively, and keep only the strongest grounded issues.",
    "Reject findings that lack clear exploitability, grounded evidence, or meaningful security impact.",
    "Use confirmed only for especially concrete evidence. Prefer likely or needs_review otherwise.",
    `Repository: ${repo.repo.owner}/${repo.repo.name}`,
    "Return strict JSON with keys findings and qualityNote.",
    `findings must be an array of up to ${MAX_FINAL_FINDINGS} objects with the same fields as the inputs plus triageNote.`,
    "qualityNote should be a single short sentence describing any quality caveat, or an empty string if none.",
    "Candidate findings:",
    JSON.stringify(
      findings.map((finding) => ({
        title: finding.title,
        severity: finding.severity,
        confidence: finding.confidence,
        category: finding.category,
        cwe: finding.cwe,
        owasp: finding.owasp,
        file: finding.file,
        line: finding.line,
        evidence: finding.evidence,
        triageNote: finding.triageNote,
        whyItMatters: finding.whyItMatters,
        suggestedFix: finding.suggestedFix,
        language: finding.language
      }))
    )
  ].join("\n");

  return [
    {
      role: "system",
      content:
        "You are the final security triage reviewer. Prefer under-reporting to over-reporting and keep only findings worth a human security reviewer's time. Always return strict JSON."
    },
    {
      role: "user",
      content: prompt
    }
  ];
}

async function requestJson<T>(messages: ChatMessage[], llm: LlmInput) {
  const { content, mode } = await sendChat(messages, llm, true);
  let parsed = parseJsonObject(content);

  if (!parsed) {
    const repaired = await sendChat(
      [
        ...messages,
        {
          role: "user",
          content:
            "Your previous reply was not valid JSON. Repair it now. Return only strict JSON matching the requested schema and do not add markdown."
        }
      ],
      llm,
      true
    );
    parsed = parseJsonObject(repaired.content);
    if (!parsed) {
      throw new Error(`Malformed JSON after repair attempt (${mode}/${repaired.mode}).`);
    }
  }

  return parsed as T;
}

async function sendChat(messages: ChatMessage[], llm: LlmInput, preferJson: boolean) {
  const baseUrl = (llm.baseUrl?.trim() || "https://api.openai.com/v1").replace(/\/$/, "");
  const endpoint = `${baseUrl}/chat/completions`;

  const body: Record<string, unknown> = {
    model: llm.model,
    temperature: 0.1,
    messages
  };

  if (preferJson) {
    body.response_format = { type: "json_object" };
  }

  let response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${llm.apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  let mode = preferJson ? "json" : "plain";
  if (!response.ok && preferJson) {
    const fallbackBody = { ...body };
    delete fallbackBody.response_format;
    response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${llm.apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(fallbackBody)
    });
    mode = "plain";
  }

  if (!response.ok) {
    throw new Error(`LLM request failed with status ${response.status}.`);
  }

  const payload = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };

  return {
    content: payload.choices?.[0]?.message?.content ?? "",
    mode
  };
}

function normalizeRankedFiles(files: RepoFile[], rankedCandidates: RankedFileCandidate[] | undefined) {
  const byPath = new Map(files.map((file) => [file.path, file]));
  const ranked: RankedFile[] = [];
  const seen = new Set<string>();

  for (const candidate of rankedCandidates ?? []) {
    if (!candidate.path) continue;
    const file = byPath.get(candidate.path);
    if (!file || seen.has(file.path)) continue;
    ranked.push({
      file,
      priority: clampPriority(candidate.priority),
      reason: (candidate.reason || "Model-prioritized review target.").trim()
    });
    seen.add(file.path);
  }

  for (const file of files) {
    if (seen.has(file.path)) continue;
    ranked.push({
      file,
      priority: heuristicPriority(file),
      reason: "Fallback heuristic ranking."
    });
  }

  return ranked.sort((left, right) => right.priority - left.priority).slice(0, MAX_TRIAGE_FILE_COUNT);
}

function normalizeCandidateFinding(candidate: LlmFindingCandidate, repo: RepoSnapshot, files: RepoFile[]) {
  if (!candidate.title || !candidate.file) {
    return null;
  }

  const matchingFile = files.find((file) => file.path === candidate.file) ?? repo.files.find((file) => file.path === candidate.file);
  if (!matchingFile) {
    return null;
  }

  const evidence = sanitizeText(candidate.evidence, 220);
  const normalizedEvidence = normalizeEvidenceAgainstFile(evidence, matchingFile.content);
  const line = normalizeLine(candidate.line, matchingFile.content, normalizedEvidence || evidence);
  const finding: Finding = {
    id: createId("llm"),
    title: sanitizeText(candidate.title, 120) || "Potential security issue",
    severity: normalizeSeverity(candidate.severity) ?? "medium",
    confidence: normalizeConfidence(candidate.confidence) ?? "needs_review",
    category: sanitizeCategory(candidate.category),
    cwe: normalizeTaxonomy(candidate.cwe, "CWE-unknown"),
    owasp: normalizeTaxonomy(candidate.owasp, "OWASP-review"),
    file: matchingFile.path,
    line,
    evidence: normalizedEvidence || buildEvidenceSnippet(matchingFile.content, line),
    triageNote: sanitizeText(candidate.triageNote, 180),
    whyItMatters:
      sanitizeText(candidate.whyItMatters, 420) ||
      "The model identified a potentially exploitable security issue in this code path.",
    suggestedFix:
      sanitizeText(candidate.suggestedFix, 420) ||
      "Review the data flow, confirm exploitability, and apply a bounded remediation at the vulnerable sink.",
    source: "llm",
    language: matchingFile.language
  };

  return calibrateFinding(finding, repo);
}

function calibrateFinding(finding: Finding, repo: RepoSnapshot) {
  const groundedEvidence = normalizeEvidenceAgainstFile(finding.evidence, repo.files.find((file) => file.path === finding.file)?.content || "");
  const calibrated = { ...finding };

  if (!groundedEvidence) {
    calibrated.confidence = "needs_review";
    calibrated.severity = downgradeSeverity(calibrated.severity);
  }

  if (calibrated.confidence === "confirmed" && !hasStrongEvidenceSignal(calibrated)) {
    calibrated.confidence = "likely";
  }

  if (looksSpeculative(calibrated)) {
    calibrated.confidence = "needs_review";
    calibrated.severity = downgradeSeverity(calibrated.severity);
  }

  return calibrated;
}

function passesAcceptanceRubric(finding: Finding) {
  if (!finding.file || !finding.evidence.trim()) return false;
  if (finding.confidence === "needs_review" && finding.severity === "info") return false;
  if (looksLowSignal(finding)) return false;
  return true;
}

function isGroundedFinding(finding: Finding, repo: RepoSnapshot) {
  const file = repo.files.find((entry) => entry.path === finding.file);
  if (!file) return false;
  if (!finding.evidence.trim()) return false;
  return Boolean(normalizeEvidenceAgainstFile(finding.evidence, file.content));
}

function dedupeFindings(findings: Finding[]) {
  const deduped = new Map<string, Finding>();

  for (const finding of findings) {
    const key = [
      finding.file,
      finding.category,
      slugKey(finding.title),
      slugKey(finding.evidence.slice(0, 100))
    ].join("::");
    const existing = deduped.get(key);
    if (!existing || compareFindings(finding, existing) < 0) {
      deduped.set(key, finding);
    }
  }

  return [...deduped.values()];
}

function compareFindings(left: Finding, right: Finding) {
  return severityScore(right.severity) - severityScore(left.severity) || confidenceScore(right.confidence) - confidenceScore(left.confidence);
}

function parseJsonObject(content: string) {
  const cleaned = content.trim().replace(/^```json\s*/i, "").replace(/^```\s*/i, "").replace(/\s*```$/, "");
  try {
    return JSON.parse(cleaned) as Record<string, unknown>;
  } catch {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(cleaned.slice(start, end + 1)) as Record<string, unknown>;
      } catch {
        return null;
      }
    }
    return null;
  }
}

function shouldReviewFile(file: RepoFile) {
  return file.language !== "text" || isLikelySensitiveConfig(file.path);
}

function heuristicPriority(file: RepoFile) {
  const path = file.path.toLowerCase();
  let score = 1;
  if (path.includes("api") || path.includes("route") || path.includes("controller") || path.includes("server")) score += 4;
  if (path.includes("auth") || path.includes("admin") || path.includes("middleware")) score += 3;
  if (path.endsWith(".env") || path.includes("config")) score += 2;
  if (file.language === "typescript" || file.language === "javascript" || file.language === "python") score += 1;
  return Math.min(score, 10);
}

function isLikelySensitiveConfig(path: string) {
  const lower = path.toLowerCase();
  return lower.endsWith(".env") || lower.includes("config") || lower.endsWith("package.json");
}

function truncateFileContent(content: string, maxChars: number) {
  if (content.length <= maxChars) {
    return content;
  }

  return `${content.slice(0, maxChars)}\n/* truncated for review */`;
}

function chunk<T>(items: T[], size: number) {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
}

function normalizeSeverity(value?: string): Finding["severity"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "critical":
    case "high":
    case "medium":
    case "low":
    case "info":
      return value!.trim().toLowerCase() as Finding["severity"];
    default:
      return null;
  }
}

function normalizeConfidence(value?: string): Finding["confidence"] | null {
  switch ((value || "").trim().toLowerCase()) {
    case "confirmed":
    case "likely":
    case "needs_review":
      return value!.trim().toLowerCase() as Finding["confidence"];
    default:
      return null;
  }
}

function normalizeTaxonomy(value: string | undefined, fallback: string) {
  const normalized = sanitizeText(value, 48);
  return normalized || fallback;
}

function sanitizeCategory(value?: string) {
  const normalized = sanitizeText(value, 40).toLowerCase().replace(/[^a-z0-9_ -]/g, "").replace(/\s+/g, "_");
  return normalized || "llm_review";
}

function normalizeLine(line: number | undefined, content: string, evidence: string) {
  if (typeof line === "number" && Number.isFinite(line) && line > 0) {
    return Math.floor(line);
  }

  if (evidence) {
    const index = content.indexOf(evidence);
    if (index >= 0) {
      return content.slice(0, index).split("\n").length;
    }
  }

  return 1;
}

function buildEvidenceSnippet(content: string, line: number) {
  const lines = content.split("\n");
  return sanitizeText((lines[line - 1] || lines[0] || "").trim(), 220);
}

function normalizeEvidenceAgainstFile(evidence: string, content: string) {
  if (!evidence || !content) return "";
  if (content.includes(evidence)) return evidence;

  const compactEvidence = evidence.replace(/\s+/g, "");
  const matchingLine = content
    .split("\n")
    .map((line) => line.trim())
    .find((line) => line && compactEvidence && line.replace(/\s+/g, "").includes(compactEvidence));

  return sanitizeText(matchingLine, 220);
}

function sanitizeText(value: string | undefined, maxLength: number) {
  return (value || "").replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function hasStrongEvidenceSignal(finding: Finding) {
  const evidence = finding.evidence.toLowerCase();
  return evidence.includes("(") || evidence.includes("=") || evidence.includes("exec") || evidence.includes("select");
}

function looksSpeculative(finding: Finding) {
  const text = `${finding.title} ${finding.triageNote || ""} ${finding.whyItMatters}`.toLowerCase();
  return /\b(might|may|could|possibly|potentially|consider)\b/.test(text) && finding.confidence !== "confirmed";
}

function looksLowSignal(finding: Finding) {
  const combined = `${finding.title} ${finding.triageNote || ""} ${finding.whyItMatters}`.toLowerCase();
  return (
    /\b(best practice|hardening|should review|could be improved|general risk|informational only)\b/.test(combined) ||
    (finding.confidence === "needs_review" && finding.severity === "low")
  );
}

function downgradeSeverity(severity: Finding["severity"]): Finding["severity"] {
  switch (severity) {
    case "critical":
      return "high";
    case "high":
      return "medium";
    case "medium":
      return "low";
    default:
      return severity;
  }
}

function severityScore(severity: Finding["severity"]) {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}

function confidenceScore(confidence: Finding["confidence"]) {
  switch (confidence) {
    case "confirmed":
      return 3;
    case "likely":
      return 2;
    default:
      return 1;
  }
}

function clampPriority(priority?: number) {
  if (typeof priority !== "number" || !Number.isFinite(priority)) return 5;
  return Math.max(1, Math.min(10, Math.round(priority)));
}

function slugKey(input: string) {
  return input.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
}

function capitalize(input: string) {
  return input.charAt(0).toUpperCase() + input.slice(1);
}
