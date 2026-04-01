import { Confidence, Finding, RepoFile, Severity } from "@/lib/types";
import { createId } from "@/lib/utils";

interface Rule {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  cwe: string;
  owasp: string;
  source: Finding["source"];
  appliesTo: string[];
  pattern: RegExp;
  whyItMatters: string;
  suggestedFix: string;
}

const RULES: Rule[] = [
  {
    id: "dangerous-html",
    title: "Potential unsafe HTML rendering",
    severity: "high",
    confidence: "likely",
    category: "xss",
    cwe: "CWE-79",
    owasp: "A03:2021 Injection",
    source: "custom_rules",
    appliesTo: ["javascript", "typescript"],
    pattern: /dangerouslySetInnerHTML|innerHTML\s*=/,
    whyItMatters: "Rendering unsanitized HTML can allow attackers to inject script into the browser.",
    suggestedFix: "Avoid raw HTML sinks. Render trusted content only, or sanitize with a vetted library before assigning HTML."
  },
  {
    id: "sql-concat",
    title: "Possible SQL query string concatenation",
    severity: "high",
    confidence: "likely",
    category: "sql_injection",
    cwe: "CWE-89",
    owasp: "A03:2021 Injection",
    source: "custom_rules",
    appliesTo: ["javascript", "typescript", "python", "php", "java"],
    pattern: /(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,80}(\+|f"|%s|format\(|\$\{)/i,
    whyItMatters: "Building SQL with untrusted input can allow attackers to change query behavior and exfiltrate data.",
    suggestedFix: "Use parameterized queries or ORM placeholders. Keep user input separate from SQL statements."
  },
  {
    id: "child-process",
    title: "Command execution sink with possible user input",
    severity: "critical",
    confidence: "needs_review",
    category: "command_injection",
    cwe: "CWE-78",
    owasp: "A03:2021 Injection",
    source: "custom_rules",
    appliesTo: ["javascript", "typescript", "python"],
    pattern: /exec\(|spawn\(|subprocess\.(Popen|run|call)\(/,
    whyItMatters: "Shell execution paths can become remote command execution when user input reaches them.",
    suggestedFix: "Avoid shell invocation when possible. Use allowlisted arguments and pass arrays instead of shell strings."
  },
  {
    id: "weak-jwt-secret",
    title: "Hardcoded weak JWT secret",
    severity: "high",
    confidence: "likely",
    category: "auth",
    cwe: "CWE-798",
    owasp: "A07:2021 Identification and Authentication Failures",
    source: "secret_scan",
    appliesTo: ["javascript", "typescript", "python"],
    pattern: /jwt.*(secret|key).*(changeme|secret|password|123456)/i,
    whyItMatters: "Weak embedded secrets allow attackers to forge or validate tokens offline.",
    suggestedFix: "Move signing keys to environment-managed secrets and rotate any exposed values immediately."
  },
  {
    id: "debug-enabled",
    title: "Debug mode enabled in application code",
    severity: "medium",
    confidence: "confirmed",
    category: "security_misconfiguration",
    cwe: "CWE-489",
    owasp: "A05:2021 Security Misconfiguration",
    source: "custom_rules",
    appliesTo: ["python", "javascript", "typescript", "php"],
    pattern: /\bDEBUG\s*=\s*true\b|app\.debug\s*=\s*True|debug:\s*true/i,
    whyItMatters: "Debug mode can expose stack traces, internal state, and sensitive operational details.",
    suggestedFix: "Disable debug in production builds and drive environment-specific behavior from deployment config."
  },
  {
    id: "ssrf-target",
    title: "Potential SSRF via arbitrary URL fetch",
    severity: "high",
    confidence: "needs_review",
    category: "ssrf",
    cwe: "CWE-918",
    owasp: "A10:2021 Server-Side Request Forgery",
    source: "custom_rules",
    appliesTo: ["javascript", "typescript", "python"],
    pattern: /(fetch|axios\.(get|post))\(\s*req\.(body|query|params)|requests\.(get|post)\(\s*request\.(args|form|json)/i,
    whyItMatters: "Server-side requests to attacker-controlled URLs can expose internal services and cloud metadata.",
    suggestedFix: "Validate outbound destinations against an allowlist and block private-network or link-local addresses."
  },
  {
    id: "path-traversal",
    title: "Potential path traversal in file system access",
    severity: "high",
    confidence: "needs_review",
    category: "path_traversal",
    cwe: "CWE-22",
    owasp: "A01:2021 Broken Access Control",
    source: "custom_rules",
    appliesTo: ["javascript", "typescript", "python", "php"],
    pattern:
      /(fs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream|unlink|unlinkSync)\(\s*(req|request)\.(body|query|params)|open\(\s*(request\.(args|form)|input))/i,
    whyItMatters: "Using attacker-controlled file paths can expose sensitive files or overwrite application data.",
    suggestedFix: "Resolve paths against a fixed base directory, normalize them, and reject traversal sequences like ../ before access."
  },
  {
    id: "unsafe-deserialization",
    title: "Potential unsafe deserialization primitive",
    severity: "high",
    confidence: "needs_review",
    category: "deserialization",
    cwe: "CWE-502",
    owasp: "A08:2021 Software and Data Integrity Failures",
    source: "custom_rules",
    appliesTo: ["javascript", "typescript", "python", "php", "java"],
    pattern: /yaml\.load\(|pickle\.loads\(|ObjectInputStream\(|unserialize\(/i,
    whyItMatters: "Unsafe deserialization can let attackers trigger unintended object behavior, denial of service, or code execution.",
    suggestedFix: "Use safe parsing APIs, deserialize only trusted formats, and enforce strict type validation on untrusted data."
  },
  {
    id: "weak-crypto",
    title: "Weak cryptographic primitive detected",
    severity: "medium",
    confidence: "likely",
    category: "weak_crypto",
    cwe: "CWE-327",
    owasp: "A02:2021 Cryptographic Failures",
    source: "custom_rules",
    appliesTo: ["javascript", "typescript", "python", "java", "php"],
    pattern: /createHash\(\s*["'](md5|sha1)["']\s*\)|\b(md5|sha1)\s*\(/i,
    whyItMatters: "Legacy hashes such as MD5 and SHA-1 are no longer appropriate for security-sensitive uses like signatures, passwords, or integrity guarantees.",
    suggestedFix: "Replace weak hashes with modern primitives such as SHA-256 or Argon2/bcrypt depending on the security use case."
  },
  {
    id: "open-redirect",
    title: "Potential open redirect using untrusted input",
    severity: "medium",
    confidence: "needs_review",
    category: "open_redirect",
    cwe: "CWE-601",
    owasp: "A01:2021 Broken Access Control",
    source: "custom_rules",
    appliesTo: ["javascript", "typescript", "python", "php"],
    pattern:
      /(redirect|res\.redirect)\(\s*(req|request)\.(query|body|params)|return\s+redirect\(\s*(request\.(args|form)|req\.(query|body|params))/i,
    whyItMatters: "Open redirects can be chained into phishing, token theft, or access-control bypass flows.",
    suggestedFix: "Allow only known internal redirect destinations or map short server-side identifiers to trusted URLs."
  }
];

function lineNumberFor(content: string, index: number) {
  return content.slice(0, index).split("\n").length;
}

function makeGlobal(pattern: RegExp) {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return new RegExp(pattern.source, flags);
}

function evidenceSnippet(content: string, start: number, length: number) {
  const snippet = content.slice(start, start + Math.max(length, 1)).replace(/\s+/g, " ").trim();
  return snippet.slice(0, 220);
}

export function scanRuleMatches(files: RepoFile[]) {
  const findings: Finding[] = [];

  for (const file of files) {
    for (const rule of RULES) {
      if (!rule.appliesTo.includes(file.language)) continue;
      const matcher = makeGlobal(rule.pattern);
      const seenLines = new Set<number>();
      let match: RegExpExecArray | null;

      while ((match = matcher.exec(file.content)) !== null) {
        const line = lineNumberFor(file.content, match.index);
        if (seenLines.has(line)) {
          continue;
        }

        seenLines.add(line);
        findings.push({
          id: createId(rule.id),
          title: rule.title,
          severity: rule.severity,
          confidence: rule.confidence,
          category: rule.category,
          cwe: rule.cwe,
          owasp: rule.owasp,
          file: file.path,
          line,
          evidence: evidenceSnippet(file.content, match.index, match[0].length),
          whyItMatters: rule.whyItMatters,
          suggestedFix: rule.suggestedFix,
          source: rule.source,
          language: file.language
        });

        if (match.index === matcher.lastIndex) {
          matcher.lastIndex += 1;
        }
      }
    }
  }

  return findings;
}
