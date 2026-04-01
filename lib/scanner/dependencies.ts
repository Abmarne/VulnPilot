import { Finding, RepoFile } from "@/lib/types";
import { createId } from "@/lib/utils";

const FLAGGED_DEPENDENCIES: Array<{
  packageName: string;
  ecosystems: Array<"npm" | "pip">;
  vulnerableBelow: string;
  severity: Finding["severity"];
  title: string;
  whyItMatters: string;
  suggestedFix: string;
}> = [
  {
    packageName: "lodash",
    ecosystems: ["npm"],
    vulnerableBelow: "4.17.21",
    severity: "high",
    title: "Known vulnerable lodash version",
    whyItMatters: "Older lodash releases have known prototype-pollution and command-injection style risks in some usage patterns.",
    suggestedFix: "Upgrade lodash to the latest 4.17.x patch release or newer and verify lockfiles are refreshed."
  },
  {
    packageName: "axios",
    ecosystems: ["npm"],
    vulnerableBelow: "1.8.2",
    severity: "medium",
    title: "Potentially outdated axios release detected",
    whyItMatters: "Older axios releases have had SSRF and request-handling issues that deserve verification during review.",
    suggestedFix: "Upgrade axios to a patched release and validate any server-side outbound request use cases."
  },
  {
    packageName: "pyyaml",
    ecosystems: ["pip"],
    vulnerableBelow: "5.4",
    severity: "medium",
    title: "Outdated PyYAML version detected",
    whyItMatters: "Older PyYAML versions have had unsafe loader and parsing issues that make review important.",
    suggestedFix: "Upgrade PyYAML and use safe loaders by default."
  },
  {
    packageName: "jinja2",
    ecosystems: ["pip"],
    vulnerableBelow: "3.1.5",
    severity: "medium",
    title: "Potentially outdated Jinja2 release detected",
    whyItMatters: "Older Jinja2 releases have had sandbox escape and template injection related fixes that are worth validating.",
    suggestedFix: "Upgrade Jinja2 to a patched release and avoid rendering attacker-controlled templates."
  }
];

export function scanDependencies(files: RepoFile[]) {
  const findings: Finding[] = [];

  for (const file of files) {
    const lowerPath = file.path.toLowerCase();

    for (const entry of FLAGGED_DEPENDENCIES) {
      const match = findDependencyMatch(file, entry.packageName, entry.ecosystems, entry.vulnerableBelow);
      if (!match) continue;

      const language =
        lowerPath.endsWith("requirements.txt") || lowerPath.endsWith("pyproject.toml") ? "python" : file.language;

      findings.push({
        id: createId("dep"),
        title: entry.title,
        severity: entry.severity,
        confidence: "likely",
        category: "vulnerable_dependency",
        cwe: "CWE-1104",
        owasp: "A06:2021 Vulnerable and Outdated Components",
        file: file.path,
        line: match.line,
        evidence: match.evidence,
        whyItMatters: entry.whyItMatters,
        suggestedFix: entry.suggestedFix,
        source: "dependency_audit",
        language
      });
    }
  }

  return findings;
}

function findDependencyMatch(
  file: RepoFile,
  packageName: string,
  ecosystems: Array<"npm" | "pip">,
  vulnerableBelow: string
) {
  const lowerPath = file.path.toLowerCase();

  if (ecosystems.includes("npm") && isNodeDependencyFile(lowerPath)) {
    const npmMatch = findVersionedLineMatch(
      file.content,
      new RegExp(`["']${escapeRegExp(packageName)}["']\\s*[:@]\\s*["'^~<>= ]*([0-9][0-9A-Za-z.+-]*)`, "i"),
      vulnerableBelow
    );
    if (npmMatch) {
      return npmMatch;
    }
  }

  if (ecosystems.includes("pip") && isPythonDependencyFile(lowerPath)) {
    const pipMatch = findVersionedLineMatch(
      file.content,
      new RegExp(
        `^\\s*${escapeRegExp(packageName)}(?:\\[[^\\]]+\\])?\\s*(?:==|>=|<=|~=|>|<)?\\s*([0-9][0-9A-Za-z.+-]*)`,
        "im"
      ),
      vulnerableBelow
    );
    if (pipMatch) {
      return pipMatch;
    }
  }

  return null;
}

function isNodeDependencyFile(path: string) {
  return (
    path.endsWith("package.json") ||
    path.endsWith("package-lock.json") ||
    path.endsWith("yarn.lock") ||
    path.endsWith("pnpm-lock.yaml")
  );
}

function isPythonDependencyFile(path: string) {
  return path.endsWith("requirements.txt") || path.endsWith("pyproject.toml");
}

function findLineMatch(content: string, pattern: RegExp) {
  const lines = content.split("\n");

  for (let index = 0; index < lines.length; index += 1) {
    if (!pattern.test(lines[index])) continue;
    return {
      line: index + 1,
      evidence: lines[index].trim().slice(0, 220)
    };
  }

  return null;
}

function findVersionedLineMatch(content: string, pattern: RegExp, vulnerableBelow: string) {
  const lines = content.split("\n");

  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(pattern);
    if (!match?.[1]) continue;

    const detectedVersion = normalizeVersion(match[1]);
    if (!detectedVersion || compareVersions(detectedVersion, vulnerableBelow) >= 0) {
      continue;
    }

    return {
      line: index + 1,
      evidence: lines[index].trim().slice(0, 220)
    };
  }

  return null;
}

function normalizeVersion(version: string) {
  const match = version.match(/\d+(?:\.\d+){0,3}/);
  return match?.[0] ?? null;
}

function compareVersions(left: string, right: string) {
  const leftParts = left.split(".").map((part) => Number.parseInt(part, 10));
  const rightParts = right.split(".").map((part) => Number.parseInt(part, 10));
  const length = Math.max(leftParts.length, rightParts.length);

  for (let index = 0; index < length; index += 1) {
    const leftValue = leftParts[index] ?? 0;
    const rightValue = rightParts[index] ?? 0;

    if (leftValue !== rightValue) {
      return leftValue - rightValue;
    }
  }

  return 0;
}

function escapeRegExp(input: string) {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
