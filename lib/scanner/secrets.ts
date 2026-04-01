import { Finding, RepoFile } from "@/lib/types";
import { createId } from "@/lib/utils";

const SECRET_PATTERNS: Array<{
  title: string;
  pattern: RegExp;
  severity: Finding["severity"];
  whyItMatters: string;
  suggestedFix: string;
}> = [
  {
    title: "Potential embedded GitHub token",
    pattern: /ghp_[A-Za-z0-9]{20,}/,
    severity: "critical",
    whyItMatters: "Hardcoded access tokens can grant immediate unauthorized access to source control and secrets.",
    suggestedFix: "Revoke the token, rotate credentials, and move the new secret into environment-managed storage."
  },
  {
    title: "Potential AWS access key",
    pattern: /AKIA[0-9A-Z]{16}/,
    severity: "critical",
    whyItMatters: "Embedded cloud keys can allow direct account compromise and resource abuse.",
    suggestedFix: "Rotate the key immediately and move access to short-lived credentials or secret management."
  },
  {
    title: "Possible hardcoded private key material",
    pattern: /-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/,
    severity: "critical",
    whyItMatters: "Committed private keys can allow attackers to impersonate services or decrypt protected traffic.",
    suggestedFix: "Remove the key from the repo, rotate any affected certificates or identities, and use a secure secret store."
  }
];

export function scanSecrets(files: RepoFile[]) {
  const findings: Finding[] = [];

  for (const file of files) {
    for (const secret of SECRET_PATTERNS) {
      const match = secret.pattern.exec(file.content);
      if (!match) continue;

      findings.push({
        id: createId("secret"),
        title: secret.title,
        severity: secret.severity,
        confidence: "confirmed",
        category: "secrets",
        cwe: "CWE-798",
        owasp: "A02:2021 Cryptographic Failures",
        file: file.path,
        line: file.content.slice(0, match.index).split("\n").length,
        evidence: match[0].slice(0, 80),
        whyItMatters: secret.whyItMatters,
        suggestedFix: secret.suggestedFix,
        source: "secret_scan",
        language: file.language
      });
    }
  }

  return findings;
}
