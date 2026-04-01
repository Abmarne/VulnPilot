import JSZip from "jszip";
import { RepoFile, RepoSnapshot } from "@/lib/types";

const MAX_FILES = 300;
const MAX_BYTES = 1_500_000;
const TEXT_EXTENSIONS = new Set([
  "js",
  "jsx",
  "ts",
  "tsx",
  "py",
  "java",
  "php",
  "rb",
  "go",
  "rs",
  "json",
  "yml",
  "yaml",
  "toml",
  "env",
  "md",
  "sql",
  "graphql",
  "sh"
]);

const SKIP_PATTERNS = [
  /^node_modules\//,
  /^dist\//,
  /^build\//,
  /^coverage\//,
  /^\.next\//,
  /^vendor\//,
  /^\.git\//
];

export function parseGitHubRepoUrl(input: string) {
  try {
    const url = new URL(input);
    if (url.hostname !== "github.com") {
      throw new Error("Only public GitHub repositories are supported in v1.");
    }

    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 2) {
      throw new Error("GitHub URL must include owner and repository name.");
    }

    return {
      owner: parts[0],
      name: parts[1].replace(/\.git$/, "")
    };
  } catch {
    throw new Error("Enter a valid public GitHub repository URL.");
  }
}

function detectLanguage(path: string) {
  const fileName = path.split("/").pop() ?? "";
  if (fileName === "package.json") return "javascript";
  if (fileName === "requirements.txt") return "python";
  if (fileName === "pom.xml") return "java";

  const extension = fileName.includes(".") ? fileName.split(".").pop()?.toLowerCase() : "";
  switch (extension) {
    case "ts":
    case "tsx":
      return "typescript";
    case "js":
    case "jsx":
      return "javascript";
    case "py":
      return "python";
    case "java":
      return "java";
    case "php":
      return "php";
    case "rb":
      return "ruby";
    case "go":
      return "go";
    case "rs":
      return "rust";
    case "sql":
      return "sql";
    default:
      return "text";
  }
}

function isTextFile(path: string) {
  const fileName = path.split("/").pop() ?? "";
  if (fileName.startsWith(".")) {
    return fileName === ".env" || fileName.endsWith(".json");
  }

  const extension = fileName.includes(".") ? fileName.split(".").pop()?.toLowerCase() : "";
  return Boolean(extension && TEXT_EXTENSIONS.has(extension));
}

function detectFrameworks(files: RepoFile[]) {
  const frameworks = new Set<string>();

  for (const file of files) {
    if (file.path.endsWith("package.json")) {
      const content = file.content.toLowerCase();
      if (content.includes("\"next\"")) frameworks.add("next.js");
      if (content.includes("\"react\"")) frameworks.add("react");
      if (content.includes("\"express\"")) frameworks.add("express");
      if (content.includes("\"nestjs\"")) frameworks.add("nestjs");
    }

    if (file.path.endsWith("requirements.txt")) {
      const content = file.content.toLowerCase();
      if (content.includes("django")) frameworks.add("django");
      if (content.includes("flask")) frameworks.add("flask");
      if (content.includes("fastapi")) frameworks.add("fastapi");
    }

    if (file.path.endsWith("pom.xml")) {
      const content = file.content.toLowerCase();
      if (content.includes("spring-boot")) frameworks.add("spring boot");
    }
  }

  return [...frameworks];
}

export async function fetchGitHubRepoSnapshot(repoUrl: string, branch?: string): Promise<RepoSnapshot> {
  const repo = parseGitHubRepoUrl(repoUrl);
  const metadataResponse = await fetch(`https://api.github.com/repos/${repo.owner}/${repo.name}`, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "VulnPilot"
    },
    cache: "no-store"
  });

  if (!metadataResponse.ok) {
    throw new Error("Unable to fetch repository metadata. Verify the repo is public and available.");
  }

  const metadata = (await metadataResponse.json()) as { default_branch: string };
  const selectedBranch = branch?.trim() || metadata.default_branch;
  const zipUrl = `https://codeload.github.com/${repo.owner}/${repo.name}/zip/refs/heads/${selectedBranch}`;
  const zipResponse = await fetch(zipUrl, { cache: "no-store" });

  if (!zipResponse.ok) {
    throw new Error(`Unable to download repository archive for branch "${selectedBranch}".`);
  }

  const archive = await zipResponse.arrayBuffer();
  const zip = await JSZip.loadAsync(archive);
  const files: RepoFile[] = [];
  let totalBytes = 0;

  for (const [entryName, entry] of Object.entries(zip.files)) {
    if (entry.dir) continue;

    const normalized = entryName.split("/").slice(1).join("/");
    if (!normalized || SKIP_PATTERNS.some((pattern) => pattern.test(normalized))) continue;
    if (!isTextFile(normalized)) continue;

    const content = await entry.async("string");
    totalBytes += content.length;

    if (totalBytes > MAX_BYTES) {
      throw new Error("Repository exceeds the v1 scan size limit. Try a smaller repo or trim generated files.");
    }

    files.push({
      path: normalized,
      content,
      language: detectLanguage(normalized)
    });

    if (files.length > MAX_FILES) {
      throw new Error("Repository exceeds the v1 file limit. Try scanning a smaller target.");
    }
  }

  const languages = [...new Set(files.map((file) => file.language).filter((language) => language !== "text"))];

  return {
    repo: {
      owner: repo.owner,
      name: repo.name,
      branch: selectedBranch,
      defaultBranch: metadata.default_branch,
      url: repoUrl
    },
    files,
    languages,
    frameworks: detectFrameworks(files),
    stats: {
      totalFiles: files.length,
      totalBytes
    }
  };
}
