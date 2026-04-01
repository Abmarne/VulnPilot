"use client";

import { useEffect, useMemo, useState } from "react";
import type { Finding, ScanRecord, Severity } from "@/lib/types";

const emptySummary = {
  total: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0
};

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export function Dashboard({ initialScans }: { initialScans: ScanRecord[] }) {
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [scans, setScans] = useState<ScanRecord[]>(initialScans);
  const [activeScanId, setActiveScanId] = useState<string | null>(initialScans[0]?.id ?? null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const activeScan = scans.find((scan) => scan.id === activeScanId) ?? scans[0] ?? null;

  useEffect(() => {
    if (!activeScan || !["queued", "analyzing"].includes(activeScan.status)) {
      return;
    }

    const interval = window.setInterval(async () => {
      const response = await fetch(`/api/scans/${activeScan.id}`, { cache: "no-store" });
      if (response.status === 404) {
        setStatusMessage("The scan record was lost after a server reload. Please start the scan again.");
        setScans((current) => current.filter((entry) => entry.id !== activeScan.id));
        setActiveScanId((current) => (current === activeScan.id ? null : current));
        window.clearInterval(interval);
        return;
      }

      if (!response.ok) return;

      const { scan } = (await response.json()) as { scan: ScanRecord };
      setScans((current) => {
        const next = current.map((entry) => (entry.id === scan.id ? scan : entry));
        if (!next.some((entry) => entry.id === scan.id)) {
          next.unshift(scan);
        }
        return next;
      });
    }, 2500);

    return () => window.clearInterval(interval);
  }, [activeScan]);

  const filteredFindings = useMemo(() => {
    const findings = activeScan?.findings ?? [];
    return findings
      .filter((finding) => severityFilter === "all" || finding.severity === severityFilter)
      .sort((left, right) => severityRank(left.severity) - severityRank(right.severity));
  }, [activeScan, severityFilter]);

  async function submitScan(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsSubmitting(true);
    setStatusMessage("Queueing repository for passive analysis...");

    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repoUrl,
          branch: branch || undefined
        })
      });

      const payload = (await response.json()) as { error?: string; scan?: ScanRecord };
      if (!response.ok || !payload.scan) {
        throw new Error(payload.error ?? "Unable to create scan.");
      }

      setScans((current) => [payload.scan!, ...current]);
      setActiveScanId(payload.scan.id);
      setStatusMessage("Scan queued. The report will refresh automatically as analysis completes.");
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : "Unable to create scan.");
    } finally {
      setIsSubmitting(false);
    }
  }

  function exportReport(format: "json" | "md") {
    if (!activeScan) return;
    window.open(`/api/scans/${activeScan.id}/export?format=${format}`, "_blank", "noopener,noreferrer");
  }

  const summary = activeScan?.summary ?? emptySummary;

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brandLockup">
          <div className="brandIcon" aria-hidden="true">
            <span />
            <span />
          </div>
          <div>
            <strong>VulnPilot</strong>
            <p>Passive code vulnerability review for public GitHub repositories</p>
          </div>
        </div>

        <div className="topbarMeta">
          <span className="metaPill">LLM-first scanning</span>
          <span className="metaPill">Shared server model</span>
        </div>
      </header>

      <section className="appGrid">
        <aside className="sidebar panel">
          <div className="sectionIntro">
            <h1>New scan</h1>
            <p>Paste a public repository URL and review the resulting report on the right.</p>
          </div>

          <form className="form" onSubmit={submitScan}>
            <div className="field">
              <label htmlFor="repo-url">Repository URL</label>
              <input
                id="repo-url"
                type="url"
                required
                placeholder="https://github.com/owner/repo"
                value={repoUrl}
                onChange={(event) => setRepoUrl(event.target.value)}
              />
            </div>

            <div className="field">
              <label htmlFor="branch">Branch</label>
              <input
                id="branch"
                placeholder="Optional branch override"
                value={branch}
                onChange={(event) => setBranch(event.target.value)}
              />
            </div>

            <div className="buttonRow">
              <button className="button buttonPrimary" disabled={isSubmitting} type="submit">
                {isSubmitting ? "Queueing..." : "Start scan"}
              </button>
              <button
                className="button buttonSecondary"
                type="button"
                onClick={() => {
                  setRepoUrl("https://github.com/octocat/Hello-World");
                  setBranch("master");
                }}
              >
                Use example
              </button>
            </div>
          </form>

          {statusMessage ? <div className="notice">{statusMessage}</div> : null}

          <div className="ruleBox">
            <strong>Usage note</strong>
            <p>Only scan repositories you own or are authorized to review. This app does not probe live targets.</p>
          </div>

          <div className="ruleBox">
            <strong>LLM mode</strong>
            <p>The scanner uses one server-configured model for repository analysis. End users do not supply model settings or API keys.</p>
          </div>

          <div className="sectionTitle">
            <h2>Recent scans</h2>
          </div>

          <div className="scanList">
            {scans.length ? (
              scans.slice(0, 8).map((scan) => (
                <button
                  className={`scanRow ${scan.id === activeScan?.id ? "scanRowActive" : ""}`}
                  key={scan.id}
                  type="button"
                  onClick={() => setActiveScanId(scan.id)}
                >
                  <span className="scanRowTitle">{scan.repoName ?? scan.repoUrl}</span>
                  <span className="scanRowMeta">
                    <span>{getStatusLabel(scan.status)}</span>
                    <span>{scan.summary.total} findings</span>
                  </span>
                </button>
              ))
            ) : (
              <div className="emptyBlock">No scans yet.</div>
            )}
          </div>
        </aside>

        <section className="report panel">
          <div className="reportHead">
            <div>
              <div className="sectionTitle">
                <h2>Report</h2>
              </div>
              <h3 className="reportTitle">
                {activeScan?.repoName ?? "No report selected"}
              </h3>
              <p className="reportSubtitle">
                {activeScan
                  ? activeScan.repo
                    ? `${activeScan.repo.owner}/${activeScan.repo.name} | ${activeScan.repo.branch}`
                    : activeScan.repoUrl
                  : "Run or select a scan to review the findings."}
              </p>
            </div>

            <div className="reportActions">
              <button className="button buttonSecondary" type="button" onClick={() => exportReport("json")} disabled={!activeScan}>
                Export JSON
              </button>
              <button className="button buttonSecondary" type="button" onClick={() => exportReport("md")} disabled={!activeScan}>
                Export Markdown
              </button>
            </div>
          </div>

          {activeScan ? (
            <>
              <div className="statusBar">
                <div className="statusGroup">
                  <span className={`statusDot status-${activeScan.status}`} />
                  <strong>{getStatusLabel(activeScan.status)}</strong>
                </div>

                <div className="statusTags">
                  {activeScan.frameworks.map((framework) => (
                    <span className="tag" key={framework}>
                      {framework}
                    </span>
                  ))}
                  {activeScan.languages.map((language) => (
                    <span className="tag tagMuted" key={language}>
                      {language}
                    </span>
                  ))}
                </div>
              </div>

              <div className="summaryGrid">
                <SummaryCard label="Total" value={summary.total} />
                <SummaryCard label="Critical" value={summary.critical} tone="critical" />
                <SummaryCard label="High" value={summary.high} tone="high" />
                <SummaryCard label="Medium" value={summary.medium} tone="medium" />
              </div>

              <div className="summaryNote">
                {buildExecutiveSummary(summary)}
              </div>

              <div className="filters">
                <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                  <option value="all">All severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>

              {activeScan.error ? <div className="notice noticeError">{activeScan.error}</div> : null}

              <div className="findingList">
                {filteredFindings.map((finding) => (
                  <FindingCard key={finding.id} finding={finding} />
                ))}
              </div>

              {!filteredFindings.length && activeScan.status === "report_ready" ? (
                <div className="emptyBlock">No findings matched the current filters.</div>
              ) : null}

              {activeScan.notes.length ? (
                <section className="notesPanel">
                  <h4>Scan notes</h4>
                  <ul className="notesList">
                    {activeScan.notes.map((note) => (
                      <li key={note}>{note}</li>
                    ))}
                  </ul>
                </section>
              ) : null}
            </>
          ) : (
            <div className="emptyState">
              <h3>No report selected</h3>
              <p>Run a scan from the left side to generate a structured report.</p>
            </div>
          )}
        </section>
      </section>
    </main>
  );
}

function SummaryCard({
  label,
  value,
  tone
}: {
  label: string;
  value: number;
  tone?: "critical" | "high" | "medium";
}) {
  return (
    <div className={`summaryCard ${tone ? `summary-${tone}` : ""}`}>
      <span className="summaryLabel">{label}</span>
      <span className="summaryValue">{value}</span>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className={`findingCard severityBorder-${finding.severity}`}>
      <div className="findingHeader">
        <div>
          <div className="findingMeta">
            <span className={`severityPill severity-${finding.severity}`}>{formatSeverity(finding.severity)}</span>
            <span className="tag tagMuted">{formatConfidence(finding.confidence)}</span>
            <span className="tag tagMuted">{formatSource(finding.source)}</span>
          </div>
          <h4>{finding.title}</h4>
        </div>

        <div className="findingPath">
          <span>{finding.file}</span>
          <strong>Line {finding.line}</strong>
        </div>
      </div>

      <div className="findingContent">
        <section>
          <span className="label">Why this matters</span>
          <p>{finding.whyItMatters}</p>
        </section>

        <section>
          <span className="label">Recommended fix</span>
          <p>{finding.suggestedFix}</p>
        </section>
      </div>

      <div className="evidenceBlock">
        <div className="evidenceHead">
          <span>Evidence</span>
          <div className="evidenceTags">
            <span>{finding.cwe}</span>
            <span>{finding.owasp}</span>
            <span>{finding.language}</span>
          </div>
        </div>
        <pre className="codeBlock">
          <code>{finding.evidence}</code>
        </pre>
      </div>
    </article>
  );
}

function severityRank(severity: Severity) {
  return severityOrder.indexOf(severity);
}

function formatSeverity(severity: Severity) {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

function formatConfidence(confidence: Finding["confidence"]) {
  switch (confidence) {
    case "needs_review":
      return "Needs review";
    case "confirmed":
      return "Confirmed";
    default:
      return "Likely";
  }
}

function formatSource(source: Finding["source"]) {
  return source === "llm" ? "LLM analysis" : source;
}

function getStatusLabel(status: ScanRecord["status"]) {
  switch (status) {
    case "queued":
      return "Queued";
    case "analyzing":
      return "Analyzing";
    case "report_ready":
      return "Report ready";
    case "failed":
      return "Failed";
  }
}

function buildExecutiveSummary(summary: typeof emptySummary) {
  if (summary.total === 0) {
    return "No findings are shown yet. If the scan has finished, the repository may be clean or the model may not have found a concrete vulnerability in the reviewed code.";
  }

  const parts = [];
  if (summary.critical) parts.push(`${summary.critical} critical`);
  if (summary.high) parts.push(`${summary.high} high`);
  if (summary.medium) parts.push(`${summary.medium} medium`);
  if (!parts.length && summary.total) parts.push(`${summary.total} low-priority`);
  return `This report contains ${parts.join(", ")} findings. Review the highest-severity items first and work through the remediation guidance below.`;
}
