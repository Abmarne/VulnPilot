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
        import { createHash } from "crypto";
        const userUrl = req.query.url;
        fetch(req.query.url);
        div.innerHTML = req.body.content;
        exec(req.body.command);
        res.redirect(req.query.next);
        fs.readFile(req.query.path);
        const digest = createHash("md5").update(password).digest("hex");
      `
    },
    {
      path: "src/legacy.ts",
      language: "typescript",
      content: `
        div.innerHTML = profile.bio;
        section.innerHTML = settings.signature;
      `
    },
    {
      path: "package.json",
      language: "javascript",
      content: `
        {
          "dependencies": {
            "lodash": "4.17.15",
            "axios": "0.27.2"
          }
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
    totalFiles: 4,
    totalBytes: 600
  }
};

test("analyzeRepository finds multiple passive security issues", async () => {
  const result = await analyzeRepository(sampleRepo, {
    repoUrl: sampleRepo.repo.url
  });

  assert.ok(result.findings.some((finding) => finding.category === "xss"));
  assert.ok(result.findings.some((finding) => finding.category === "command_injection"));
  assert.ok(result.findings.some((finding) => finding.category === "ssrf"));
  assert.ok(result.findings.some((finding) => finding.category === "path_traversal"));
  assert.ok(result.findings.some((finding) => finding.category === "weak_crypto"));
  assert.ok(result.findings.some((finding) => finding.category === "open_redirect"));
  assert.ok(result.findings.some((finding) => finding.category === "vulnerable_dependency"));
  assert.ok(result.findings.some((finding) => finding.category === "secrets"));
});

test("analyzeRepository reports multiple matches for the same rule in one file", async () => {
  const result = await analyzeRepository(sampleRepo, {
    repoUrl: sampleRepo.repo.url
  });

  const xssFindings = result.findings.filter((finding) => finding.category === "xss");
  assert.ok(xssFindings.length >= 2);
  assert.ok(xssFindings.some((finding) => finding.file === "src/legacy.ts"));
});
