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
  whyItMatters?: string;
  suggestedFix?: string;
  language?: string;
}

const MAX_FILES_PER_BATCH = 4;
const MAX_FILE_CHARS = 6000;
const MAX_FINDINGS_PER_BATCH = 5;

export async function analyzeRepositoryWithLlm(repo: RepoSnapshot, llm: LlmInput): Promise<Finding[]> {
  if (!llm.apiKey) {
    return [];
  }

  const candidateFiles = repo.files
    .filter((file) => file.language !== "text" || isLikelySensitiveConfig(file.path))
    .sort((left, right) => scoreFileForReview(right) - scoreFileForReview(left))
    .slice(0, 16);

  const batches = chunk(candidateFiles, MAX_FILES_PER_BATCH);
  const findings: Finding[] = [];

  for (const [index, batch] of batches.entries()) {
    const payload = buildRepositoryBatchPrompt(repo, batch, index + 1, batches.length);
    const content = await sendChat(messagesForRepositoryReview(payload), llm, true);
    const parsed = parseJsonObject(content);
    const candidates = Array.isArray(parsed?.findings) ? (parsed.findings as LlmFindingCandidate[]) : [];

    for (const candidate of candidates) {
      const finding = normalizeLlmFinding(candidate, repo, batch);
      if (finding) {
        findings.push(finding);
      }
    }
  }

  return dedupeFindings(findings)
    .sort((left, right) => severityScore(right.severity) - severityScore(left.severity))
    .slice(0, 20);
}

function buildRepositoryBatchPrompt(
  repo: RepoSnapshot,
  files: RepoFile[],
  batchNumber: number,
  totalBatches: number
) {
  const header = [
    "Review this repository batch for real, developer-actionable vulnerabilities.",
    "Focus on exploitable issues such as auth flaws, injection, SSRF, path traversal, XSS, deserialization, crypto misuse, secrets, and dangerous trust boundaries.",
    "Avoid reporting style issues, missing best practices without impact, or speculative findings with no supporting code path.",
    `Repository: ${repo.repo.owner}/${repo.repo.name}`,
    `Frameworks: ${repo.frameworks.join(", ") || "unknown"}`,
    `Languages: ${repo.languages.join(", ") || "unknown"}`,
    `Batch: ${batchNumber}/${totalBatches}`,
    `Return JSON with one key: findings. findings must be an array of up to ${MAX_FINDINGS_PER_BATCH} objects.`,
    "Each finding object must include: title, severity, confidence, category, cwe, owasp, file, line, evidence, whyItMatters, suggestedFix, language.",
    "Allowed severity values: critical, high, medium, low, info.",
    "Allowed confidence values: confirmed, likely, needs_review.",
    "Use a precise file path from the provided files. Use line numbers only when reasonably inferable from the snippet. If unsure, choose the best approximate line."
  ].join("\n");

  const fileBlocks = files.map((file) => {
    const content = truncateFileContent(file.content, MAX_FILE_CHARS);
    return [
      `FILE: ${file.path}`,
      `LANGUAGE: ${file.language}`,
      "CODE:",
      "```",
      content,
      "```"
    ].join("\n");
  });

  return `${header}\n\n${fileBlocks.join("\n\n")}`;
}

function messagesForRepositoryReview(prompt: string): ChatMessage[] {
  return [
    {
      role: "system",
      content:
        "You are a senior application security reviewer. Report only concrete vulnerabilities supported by the provided code. Always return strict JSON."
    },
    {
      role: "user",
      content: prompt
    }
  ];
}

export async function enrichFindingWithLlm(finding: Finding, repo: RepoSnapshot, llm: LlmInput) {
  if (!llm.apiKey) {
    return null;
  }

  const prompt = [
    "Improve this existing security finding.",
    "Return compact JSON with keys confidence, whyItMatters, suggestedFix.",
    "Do not include markdown fences.",
    `Repository: ${repo.repo.owner}/${repo.repo.name}`,
    `Frameworks: ${repo.frameworks.join(", ") || "unknown"}`,
    `Finding title: ${finding.title}`,
    `Category: ${finding.category}`,
    `Current confidence: ${finding.confidence}`,
    `Evidence: ${finding.evidence}`,
    `File: ${finding.file}:${finding.line}`
  ].join("\n");

  const content = await sendChat(
    [
      {
        role: "system",
        content: "You review code security findings and improve remediation quality. Always return strict JSON."
      },
      {
        role: "user",
        content: prompt
      }
    ],
    llm,
    true
  );

  const parsed = parseJsonObject(content) as Partial<Pick<Finding, "confidence" | "whyItMatters" | "suggestedFix">> | null;
  if (!parsed) {
    return null;
  }

  return {
    ...finding,
    confidence: normalizeConfidence(parsed.confidence) ?? finding.confidence,
    whyItMatters: parsed.whyItMatters ?? finding.whyItMatters,
    suggestedFix: parsed.suggestedFix ?? finding.suggestedFix,
    source: "llm" as const
  };
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
  }

  if (!response.ok) {
    throw new Error(`LLM request failed with status ${response.status}.`);
  }

  const payload = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };

  return payload.choices?.[0]?.message?.content ?? "";
}

function normalizeLlmFinding(
  candidate: LlmFindingCandidate,
  repo: RepoSnapshot,
  files: RepoFile[]
) {
  if (!candidate.title || !candidate.file) {
    return null;
  }

  const matchingFile = files.find((file) => file.path === candidate.file) ?? repo.files.find((file) => file.path === candidate.file);
  if (!matchingFile) {
    return null;
  }

  const evidence = (candidate.evidence || "").trim();
  const line = normalizeLine(candidate.line, matchingFile.content, evidence);

  return {
    id: createId("llm"),
    title: candidate.title.trim(),
    severity: normalizeSeverity(candidate.severity) ?? "medium",
    confidence: normalizeConfidence(candidate.confidence) ?? "needs_review",
    category: (candidate.category || "llm_review").trim().toLowerCase(),
    cwe: normalizeTaxonomy(candidate.cwe, "CWE-unknown"),
    owasp: normalizeTaxonomy(candidate.owasp, "OWASP-review"),
    file: matchingFile.path,
    line,
    evidence: evidence.slice(0, 220) || buildEvidenceSnippet(matchingFile.content, line),
    whyItMatters:
      (candidate.whyItMatters || "").trim() || "The model identified a potentially exploitable security issue in this code path.",
    suggestedFix:
      (candidate.suggestedFix || "").trim() || "Review the data flow, confirm exploitability, and apply a bounded remediation at the vulnerable sink.",
    source: "llm" as const,
    language: matchingFile.language
  };
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
  const normalized = (value || "").trim();
  return normalized || fallback;
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
  return (lines[line - 1] || lines[0] || "").trim().slice(0, 220);
}

function dedupeFindings(findings: Finding[]) {
  const seen = new Set<string>();
  const deduped: Finding[] = [];

  for (const finding of findings) {
    const key = [finding.file, finding.line, finding.category, finding.title.toLowerCase()].join("::");
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    deduped.push(finding);
  }

  return deduped;
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

function scoreFileForReview(file: RepoFile) {
  const path = file.path.toLowerCase();
  let score = 0;

  if (path.includes("api") || path.includes("route") || path.includes("controller") || path.includes("server")) score += 5;
  if (path.includes("auth") || path.includes("admin") || path.includes("middleware")) score += 4;
  if (path.endsWith(".env") || path.includes("config")) score += 3;
  if (file.language === "typescript" || file.language === "javascript" || file.language === "python") score += 2;
  score += Math.min(file.content.length / 2000, 3);

  return score;
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
