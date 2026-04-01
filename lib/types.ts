export type ScanStatus = "queued" | "analyzing" | "report_ready" | "failed";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "confirmed" | "likely" | "needs_review";
export type FindingSource = "llm";

export interface ScanRequestInput {
  repoUrl: string;
  branch?: string;
}

export interface RepoFile {
  path: string;
  content: string;
  language: string;
}

export interface RepoSnapshot {
  repo: {
    owner: string;
    name: string;
    branch: string;
    defaultBranch: string;
    url: string;
  };
  files: RepoFile[];
  languages: string[];
  frameworks: string[];
  stats: {
    totalFiles: number;
    totalBytes: number;
  };
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  cwe: string;
  owasp: string;
  file: string;
  line: number;
  evidence: string;
  triageNote?: string;
  whyItMatters: string;
  suggestedFix: string;
  source: FindingSource;
  language: string;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanRecord {
  id: string;
  status: ScanStatus;
  createdAt: string;
  updatedAt: string;
  input: ScanRequestInput;
  repoUrl: string;
  repoName?: string;
  summary: ScanSummary;
  findings: Finding[];
  repo?: RepoSnapshot["repo"];
  frameworks: string[];
  languages: string[];
  notes: string[];
  error?: string;
}

export interface AnalysisResult {
  findings: Finding[];
  frameworks: string[];
  languages: string[];
  notes: string[];
}
