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
        export async function handler(req, res) {
          exec(req.body.command);
          res.redirect(req.query.next);
        }
      `
    },
    {
      path: "src/admin.ts",
      language: "typescript",
      content: `
        export function adminRoute(req, res) {
          const template = req.body.template;
          return render(template);
        }
      `
    },
    {
      path: "src/auth.ts",
      language: "typescript",
      content: `
        export async function login(req, res) {
          return db.query("select * from users where email = '" + req.body.email + "'");
        }
      `
    },
    {
      path: "src/routes.ts",
      language: "typescript",
      content: `
        export function route(req, res) {
          return fetch(req.body.url);
        }
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
    totalFiles: 5,
    totalBytes: 1200
  }
};

test("analyzeRepository dedupes across batches and filters weak findings", async () => {
  const cleanup = setupLlmEnv();
  const originalFetch = global.fetch;
  const responses = [
    jsonReply({
      files: [
        { path: "src/server.ts", priority: 10, reason: "Command execution sink." },
        { path: "src/auth.ts", priority: 9, reason: "Auth query handling." },
        { path: "src/routes.ts", priority: 8, reason: "Outbound request path." },
        { path: "src/admin.ts", priority: 7, reason: "Rendering user content." },
        { path: ".env", priority: 6, reason: "Secret-bearing config." }
      ]
    }),
    jsonReply({
      findings: [
        {
          title: "Command execution with user input",
          severity: "critical",
          confidence: "confirmed",
          category: "command_injection",
          cwe: "CWE-78",
          owasp: "A03:2021 Injection",
          file: "src/server.ts",
          line: 4,
          evidence: "exec(req.body.command);",
          triageNote: "Direct shell execution sink reachable from request data.",
          whyItMatters: "User input reaches shell execution directly.",
          suggestedFix: "Avoid shell execution or strictly allowlist arguments.",
          language: "typescript"
        },
        {
          title: "Security best practice improvement",
          severity: "low",
          confidence: "needs_review",
          category: "hardening",
          cwe: "CWE-unknown",
          owasp: "OWASP-review",
          file: "src/admin.ts",
          line: 3,
          evidence: "const template = req.body.template;",
          triageNote: "Could be improved.",
          whyItMatters: "General risk that should be reviewed.",
          suggestedFix: "Add more checks.",
          language: "typescript"
        }
      ]
    }),
    jsonReply({
      findings: [
        {
          title: "Command execution with user input",
          severity: "critical",
          confidence: "confirmed",
          category: "command_injection",
          cwe: "CWE-78",
          owasp: "A03:2021 Injection",
          file: "src/server.ts",
          line: 4,
          evidence: "exec(req.body.command);",
          triageNote: "Duplicate from another batch.",
          whyItMatters: "Duplicate issue.",
          suggestedFix: "Duplicate fix.",
          language: "typescript"
        }
      ]
    }),
    jsonReply({
      findings: [
        {
          title: "Command execution with user input",
          severity: "critical",
          confidence: "confirmed",
          category: "command_injection",
          cwe: "CWE-78",
          owasp: "A03:2021 Injection",
          file: "src/server.ts",
          line: 4,
          evidence: "exec(req.body.command);",
          triageNote: "Strongly grounded sink with request-controlled input.",
          whyItMatters: "Attacker-controlled input can trigger remote code execution.",
          suggestedFix: "Use non-shell APIs or fixed argument allowlists.",
          language: "typescript"
        }
      ],
      qualityNote: "Weak or speculative findings were filtered from the final report."
    })
  ];

  global.fetch = createFetchStub(responses);

  try {
    const result = await analyzeRepository(sampleRepo, { repoUrl: sampleRepo.repo.url });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.source, "llm");
    assert.equal(result.findings[0]?.category, "command_injection");
    assert.equal(result.findings[0]?.triageNote, "Strongly grounded sink with request-controlled input.");
    assert.match(result.notes.join(" "), /Quality note: Weak or speculative findings were filtered/i);
  } finally {
    global.fetch = originalFetch;
    cleanup();
  }
});

test("analyzeRepository repairs malformed JSON and succeeds", async () => {
  const cleanup = setupLlmEnv();
  const originalFetch = global.fetch;
  const responses = [
    jsonReply({
      files: [{ path: "src/server.ts", priority: 10, reason: "Critical route." }]
    }),
    rawReply("{invalid json"),
    jsonReply({
      findings: [
        {
          title: "Command execution with user input",
          severity: "high",
          confidence: "likely",
          category: "command_injection",
          cwe: "CWE-78",
          owasp: "A03:2021 Injection",
          file: "src/server.ts",
          line: 4,
          evidence: "exec(req.body.command);",
          triageNote: "Shell sink on a request path.",
          whyItMatters: "This can lead to command execution.",
          suggestedFix: "Remove shell execution.",
          language: "typescript"
        }
      ]
    }),
    jsonReply({
      findings: [
        {
          title: "Command execution with user input",
          severity: "high",
          confidence: "likely",
          category: "command_injection",
          cwe: "CWE-78",
          owasp: "A03:2021 Injection",
          file: "src/server.ts",
          line: 4,
          evidence: "exec(req.body.command);",
          triageNote: "Grounded command sink.",
          whyItMatters: "This can lead to command execution.",
          suggestedFix: "Remove shell execution.",
          language: "typescript"
        }
      ],
      qualityNote: ""
    })
  ];

  global.fetch = createFetchStub(responses);

  try {
    const result = await analyzeRepository(sampleRepo, { repoUrl: sampleRepo.repo.url });
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.confidence, "likely");
  } finally {
    global.fetch = originalFetch;
    cleanup();
  }
});

test("analyzeRepository records degraded extraction when a batch fails", async () => {
  const cleanup = setupLlmEnv();
  const originalFetch = global.fetch;
  const responses = [
    jsonReply({
      files: [
        { path: "src/server.ts", priority: 10, reason: "Critical route." },
        { path: "src/auth.ts", priority: 9, reason: "Auth route." },
        { path: "src/routes.ts", priority: 8, reason: "SSRF path." },
        { path: "src/admin.ts", priority: 7, reason: "Render path." },
        { path: ".env", priority: 6, reason: "Secrets." }
      ]
    }),
    jsonReply({
      findings: [
        {
          title: "Command execution with user input",
          severity: "critical",
          confidence: "confirmed",
          category: "command_injection",
          cwe: "CWE-78",
          owasp: "A03:2021 Injection",
          file: "src/server.ts",
          line: 4,
          evidence: "exec(req.body.command);",
          triageNote: "Strong sink.",
          whyItMatters: "Direct execution path.",
          suggestedFix: "Remove shell execution.",
          language: "typescript"
        }
      ]
    }),
    statusReply(500, { error: "temporary failure" }),
    jsonReply({
      findings: [
        {
          title: "Command execution with user input",
          severity: "high",
          confidence: "likely",
          category: "command_injection",
          cwe: "CWE-78",
          owasp: "A03:2021 Injection",
          file: "src/server.ts",
          line: 4,
          evidence: "exec(req.body.command);",
          triageNote: "Final merged issue.",
          whyItMatters: "Direct execution path.",
          suggestedFix: "Remove shell execution.",
          language: "typescript"
        }
      ],
      qualityNote: "One batch failed, so the final report may be incomplete."
    })
  ];

  global.fetch = createFetchStub(responses);

  try {
    const result = await analyzeRepository(sampleRepo, { repoUrl: sampleRepo.repo.url });
    assert.equal(result.findings.length, 1);
    assert.match(result.notes.join(" "), /degraded batch responses/i);
    assert.match(result.notes.join(" "), /Quality note: One batch failed/i);
  } finally {
    global.fetch = originalFetch;
    cleanup();
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

function setupLlmEnv() {
  const originalApiKey = process.env.SCANNER_LLM_API_KEY;
  const originalBaseUrl = process.env.SCANNER_LLM_BASE_URL;
  const originalModel = process.env.SCANNER_LLM_MODEL;

  process.env.SCANNER_LLM_API_KEY = "test-key";
  process.env.SCANNER_LLM_BASE_URL = "https://example.test/v1";
  process.env.SCANNER_LLM_MODEL = "gemini-test";

  return () => {
    if (originalApiKey === undefined) delete process.env.SCANNER_LLM_API_KEY;
    else process.env.SCANNER_LLM_API_KEY = originalApiKey;
    if (originalBaseUrl === undefined) delete process.env.SCANNER_LLM_BASE_URL;
    else process.env.SCANNER_LLM_BASE_URL = originalBaseUrl;
    if (originalModel === undefined) delete process.env.SCANNER_LLM_MODEL;
    else process.env.SCANNER_LLM_MODEL = originalModel;
  };
}

function createFetchStub(responses: Array<{ status: number; body: string }>) {
  let index = 0;
  return (async () => {
    const next = responses[index++];
    assert.ok(next, `Unexpected fetch call at index ${index}`);
    return new Response(next.body, {
      status: next.status,
      headers: { "Content-Type": "application/json" }
    });
  }) as typeof fetch;
}

function jsonReply(payload: unknown) {
  return {
    status: 200,
    body: JSON.stringify({
      choices: [
        {
          message: {
            content: JSON.stringify(payload)
          }
        }
      ]
    })
  };
}

function rawReply(content: string) {
  return {
    status: 200,
    body: JSON.stringify({
      choices: [
        {
          message: {
            content
          }
        }
      ]
    })
  };
}

function statusReply(status: number, payload: unknown) {
  return {
    status,
    body: JSON.stringify(payload)
  };
}
