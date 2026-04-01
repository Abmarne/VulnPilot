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
  const summary = activeScan?.summary ?? emptySummary;

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

  return (
    <main className="shell">
      <header className="hero panel">
        <div className="heroMain">
          <div className="brandLockup">
            <div className="brandLogo" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
                <circle cx="12" cy="11" r="3" />
                <path d="M12 8v2" />
                <path d="M12 12v2" />
                <path d="M9 11h2" />
                <path d="M13 11h2" />
              </svg>
            </div>
            <div className="brandText">
              <strong className="brandTitle">VulnPilot</strong>
            </div>
          </div>

          <h1 className="heroTitle">Professional repository scanning with one shared model and a cleaner review workflow.</h1>
          <p className="heroCopy">
            Submit a public GitHub repository, let the backend model inspect the code, then review prioritized findings,
            evidence, and remediation guidance in a structured report.
          </p>
        </div>

        <div className="heroMeta">
          <MetaCard label="Mode" value="Passive only" />
          <MetaCard label="Analysis" value="LLM powered" />
          <MetaCard label="Reports" value="JSON and Markdown" />
        </div>
      </header>

      <section className="appGrid">
        <aside className="sidebarStack">
          <section className="panel sidebar">
            <div className="sectionIntro">
              <span className="sectionKicker">Launch Scan</span>
              <h2>Inspect a repository</h2>
              <p>Paste a public GitHub repository URL and optionally choose a branch to start a passive review.</p>
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

            <div className="infoGrid">
              <div className="infoCard">
                <strong>Usage note</strong>
                <p>Only scan repositories you own or are authorized to review. This app does not probe live targets.</p>
              </div>
              <div className="infoCard">
                <strong>Model setup</strong>
                <p>The scanner uses one server-configured model. End users never enter API keys or model settings.</p>
              </div>
            </div>
          </section>

          <section className="panel sidebar recentPanel">
            <div className="sectionTitle">
              <span className="sectionKicker">History</span>
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
          </section>
        </aside>

        <section className="panel report">
          <div className="reportHead">
            <div className="reportIntro">
              <span className="sectionKicker">Assessment</span>
              <h2 className="reportTitle">{activeScan?.repoName ?? "No report selected"}</h2>
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
                  <div>
                    <span className="statusLabel">Scan status</span>
                    <strong>{getStatusLabel(activeScan.status)}</strong>
                  </div>
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

              <div className="summaryNote">{buildExecutiveSummary(summary)}</div>

              <div className="filters">
                <div className="field filterField">
                  <label htmlFor="severity-filter">Severity</label>
                  <select id="severity-filter" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                    <option value="all">All severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </div>
              </div>

              {activeScan.error ? <div className="notice noticeError">{activeScan.error}</div> : null}

              <div className="findingList">
                {filteredFindings.map((finding) => (
                  <FindingCard key={finding.id} finding={finding} />
                ))}
              </div>

              {!filteredFindings.length && activeScan.status === "report_ready" ? (
                <div className="emptyBlock">No findings matched the current filter.</div>
              ) : null}

              {activeScan.notes.length ? (
                <section className="notesPanel">
                  <h3>Scan notes</h3>
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
              <span className="sectionKicker">Waiting</span>
              <h3>No report selected</h3>
              <p>Start a scan from the left side to generate an aligned, exportable security review.</p>
            </div>
          )}
        </section>
      </section>
    </main>
  );
}

function MetaCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="metaCard">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
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
        <div className="findingLead">
          <div className="findingMeta">
            <span className={`severityPill severity-${finding.severity}`}>{formatSeverity(finding.severity)}</span>
            <span className="tag tagMuted">{formatConfidence(finding.confidence)}</span>
            <span className="tag tagMuted">{formatSource(finding.source)}</span>
          </div>
          <h3>{finding.title}</h3>
        </div>

        <div className="findingPath">
          <span>{finding.file}</span>
          <strong>Line {finding.line}</strong>
        </div>
      </div>

      <div className="findingContent">
        {finding.triageNote ? (
          <section className="contentCard contentCardFull">
            <span className="label">Why this is worth reviewing</span>
            <p>{finding.triageNote}</p>
          </section>
        ) : null}

        <section className="contentCard">
          <span className="label">Why this matters</span>
          <p>{finding.whyItMatters}</p>
        </section>

        <section className="contentCard">
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
