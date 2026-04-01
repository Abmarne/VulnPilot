import { Finding, RepoSnapshot } from "@/lib/types";

interface LlmInput {
  provider: string;
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

export async function enrichFindingWithLlm(
  finding: Finding,
  repo: RepoSnapshot,
  llm: LlmInput
) {
  if (!llm.apiKey) {
    return null;
  }

  const baseUrl = (llm.baseUrl?.trim() || "https://api.openai.com/v1").replace(/\/$/, "");
  const endpoint = `${baseUrl}/chat/completions`;
  const prompt = [
    "You are a secure code review assistant.",
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

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${llm.apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: llm.model,
      temperature: 0.2,
      messages: [
        {
          role: "system",
          content: "You review code security findings and improve remediation quality."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      response_format: { type: "json_object" }
    })
  });

  if (!response.ok) {
    return null;
  }

  const payload = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };
  const content = payload.choices?.[0]?.message?.content;
  if (!content) {
    return null;
  }

  try {
    const parsed = JSON.parse(content) as Partial<Pick<Finding, "confidence" | "whyItMatters" | "suggestedFix">>;
    return {
      ...finding,
      confidence: parsed.confidence ?? finding.confidence,
      whyItMatters: parsed.whyItMatters ?? finding.whyItMatters,
      suggestedFix: parsed.suggestedFix ?? finding.suggestedFix,
      source: "llm" as const
    };
  } catch {
    return null;
  }
}
