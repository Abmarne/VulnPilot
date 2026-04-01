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
        const userUrl = req.query.url;
        fetch(req.query.url);
        div.innerHTML = req.body.content;
        exec(req.body.command);
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
    totalBytes: 200
  }
};

test("analyzeRepository finds multiple passive security issues", async () => {
  const result = await analyzeRepository(sampleRepo, {
    repoUrl: sampleRepo.repo.url
  });

  assert.ok(result.findings.some((finding) => finding.category === "xss"));
  assert.ok(result.findings.some((finding) => finding.category === "command_injection"));
  assert.ok(result.findings.some((finding) => finding.category === "ssrf"));
  assert.ok(result.findings.some((finding) => finding.category === "secrets"));
});
