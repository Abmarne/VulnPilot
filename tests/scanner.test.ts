import test from "node:test";
import assert from "node:assert/strict";
import { analyzeRepository } from "../lib/scanner";
import type { RepoSnapshot } from "../lib/types";

const sampleRepo: RepoSnapshot = {
  repo: {
    owner: "demo",
    name: "vulnerable-app",
    branch: "main",
    defaultBranch: "main",
    url: "https://github.com/demo/vulnerable-app"
  },
  files: [
    {
      path: "src/server.ts",
      language: "typescript",
      content: `
        import { exec } from "child_process";
        exec(req.body.command);
        res.redirect(req.query.next);
      `
    },
    {
      path: ".env",
      language: "text",
      content: "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF"
    }
  ],
  languages: ["typescript"],
  frameworks: ["express"],
  stats: {
    totalFiles: 2,
    totalBytes: 160
  }
};

test("analyzeRepository returns normalized findings from the shared LLM", async () => {
  const originalFetch = global.fetch;
  const originalApiKey = process.env.SCANNER_LLM_API_KEY;
  const originalBaseUrl = process.env.SCANNER_LLM_BASE_URL;
  const originalModel = process.env.SCANNER_LLM_MODEL;

  process.env.SCANNER_LLM_API_KEY = "test-key";
  process.env.SCANNER_LLM_BASE_URL = "https://example.test/v1";
  process.env.SCANNER_LLM_MODEL = "gemini-test";

  global.fetch = (async () =>
    new Response(
      JSON.stringify({
        choices: [
          {
            message: {
              content: JSON.stringify({
                findings: [
                  {
                    title: "Command execution with user input",
                    severity: "critical",
                    confidence: "likely",
                    category: "command_injection",
                    cwe: "CWE-78",
                    owasp: "A03:2021 Injection",
                    file: "src/server.ts",
                    line: 3,
                    evidence: "exec(req.body.command);",
                    whyItMatters: "Untrusted input reaching shell execution can become remote code execution.",
                    suggestedFix: "Avoid shell execution or strictly allowlist arguments.",
                    language: "typescript"
                  }
                ]
              })
            }
          }
        ]
      }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    )) as typeof fetch;

  try {
    const result = await analyzeRepository(sampleRepo, {
      repoUrl: sampleRepo.repo.url
    });

    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.source, "llm");
    assert.equal(result.findings[0]?.category, "command_injection");
    assert.match(result.notes.join(" "), /LLM-first analysis enabled/i);
  } finally {
    global.fetch = originalFetch;
    if (originalApiKey === undefined) delete process.env.SCANNER_LLM_API_KEY;
    else process.env.SCANNER_LLM_API_KEY = originalApiKey;
    if (originalBaseUrl === undefined) delete process.env.SCANNER_LLM_BASE_URL;
    else process.env.SCANNER_LLM_BASE_URL = originalBaseUrl;
    if (originalModel === undefined) delete process.env.SCANNER_LLM_MODEL;
    else process.env.SCANNER_LLM_MODEL = originalModel;
  }
});

test("analyzeRepository reports skipped analysis when no shared LLM is configured", async () => {
  const originalApiKey = process.env.SCANNER_LLM_API_KEY;
  delete process.env.SCANNER_LLM_API_KEY;

  try {
    const result = await analyzeRepository(sampleRepo, {
      repoUrl: sampleRepo.repo.url
    });

    assert.equal(result.findings.length, 0);
    assert.match(result.notes.join(" "), /LLM analysis skipped/i);
  } finally {
    if (originalApiKey === undefined) delete process.env.SCANNER_LLM_API_KEY;
    else process.env.SCANNER_LLM_API_KEY = originalApiKey;
  }
});
