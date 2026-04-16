"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { ArenaModal } from "./components/ArenaModal";

const API_BASE = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/api/scan/ws";

type LogEntry = { message: string; stage: string };
type ProgressState = { stage: string; percent: number };
type ProfileSummary = {
  id: number;
  name: string;
  target: string;
  source_type: string;
  request_count: number;
};
type EvidenceRequest = {
  method?: string;
  url?: string;
  params?: Record<string, string>;
  headers?: Record<string, string>;
  body?: unknown;
};
type Finding = {
  vulnerability_type?: string;
  severity?: string;
  explanation?: string;
  tutor_explanation?: string;
  url?: string;
  url_pattern?: string;
  file_path?: string;
  manual_poc?: string;
  poc_script?: string;
  remediation_code?: string;
  remediation_steps?: string;
  is_verified?: boolean;
  evidence?: {
    source?: string;
    baseline_request?: EvidenceRequest;
    mutated_request?: EvidenceRequest;
    baseline_status?: number | string | null;
    mutated_status?: number | string | null;
    delta_reason?: string;
    replay_curl?: string;
  };
};

export default function Home() {
  const [target, setTarget] = useState("");
  const [sessionCookie, setSessionCookie] = useState("");
  const [loading, setLoading] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [progress, setProgress] = useState<ProgressState>({ stage: "init", percent: 0 });
  const [errorInfo, setErrorInfo] = useState<string | null>(null);
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [useProfileRequests, setUseProfileRequests] = useState(true);
  const [harFile, setHarFile] = useState<File | null>(null);
  const [curlCommand, setCurlCommand] = useState("");
  const [openapiFile, setOpenapiFile] = useState<File | null>(null);
  const [importMessage, setImportMessage] = useState<string | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const [fixingUrls, setFixingUrls] = useState<Record<string, boolean>>({});
  const [fixStatus, setFixStatus] = useState<Record<string, "success" | "error" | null>>({});
  const [arenaFinding, setArenaFinding] = useState<Finding | null>(null);

  const ws = useRef<WebSocket | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const stages = useMemo(() => ["init", "profile", "recon", "sca", "sast", "logic", "dast", "analysis", "complete"], []);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  useEffect(() => {
    if (!target.trim()) {
      setProfiles([]);
      setSelectedProfileId("");
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const response = await fetch(`${API_BASE}/api/profiles?target=${encodeURIComponent(target.trim())}`);
        const data = (await response.json()) as { profiles: ProfileSummary[] };
        setProfiles(data.profiles || []);
      } catch {
        setProfiles([]);
      }
    }, 250);
    return () => clearTimeout(timer);
  }, [target]);

  const stageClass = (stage: string) => {
    const current = stages.indexOf(progress.stage);
    const idx = stages.indexOf(stage);
    if (idx < current || progress.stage === "complete") return "border-emerald-400 bg-emerald-500 text-neutral-950";
    if (idx === current) return "border-emerald-500 text-emerald-400";
    return "border-neutral-800 text-neutral-500";
  };

  const refreshProfiles = async () => {
    if (!target.trim()) return;
    const response = await fetch(`${API_BASE}/api/profiles?target=${encodeURIComponent(target.trim())}`);
    const data = (await response.json()) as { profiles: ProfileSummary[] };
    setProfiles(data.profiles || []);
    if ((data.profiles || []).length > 0) setSelectedProfileId(String(data.profiles[0].id));
  };

  const startScan = (event: FormEvent) => {
    event.preventDefault();
    if (loading) return;

    ws.current?.close();
    setLoading(true);
    setFindings([]);
    setLogs([]);
    setProgress({ stage: "init", percent: 0 });
    setErrorInfo(null);

    const socket = new WebSocket(WS_URL);
    ws.current = socket;

    socket.onopen = () => {
      socket.send(JSON.stringify({
        type: "START_SCAN",
        target,
        session_cookie: sessionCookie || null,
        profile_id: selectedProfileId ? Number(selectedProfileId) : null,
        use_profile_requests: useProfileRequests && !!selectedProfileId,
      }));
    };

    socket.onmessage = (eventMessage) => {
      const data = JSON.parse(eventMessage.data) as { type: string; [key: string]: unknown };
      if (data.type === "log") {
        setLogs((prev) => [...prev, { message: String(data.message || ""), stage: String(data.stage || "") }]);
      } else if (data.type === "progress") {
        const next = { stage: String(data.stage || ""), percent: Number(data.percent || 0) };
        setProgress(next);
        if (next.stage === "complete") setLoading(false);
      } else if (data.type === "finding") {
        setFindings((prev) => [...prev, data.data as Finding]);
      } else if (data.type === "fix_status") {
        const key = String(data.url || "");
        setFixingUrls((prev) => ({ ...prev, [key]: false }));
        setFixStatus((prev) => ({ ...prev, [key]: data.success ? "success" : "error" }));
      }
    };

    socket.onerror = () => {
      setErrorInfo("WebSocket connection failed. Ensure backend is running.");
      setLoading(false);
    };

    socket.onclose = () => setLoading(false);
  };

  const importHar = async (event: FormEvent) => {
    event.preventDefault();
    if (!harFile || !target.trim()) {
      setImportError("Select a HAR file and target first.");
      return;
    }
    try {
      setImportError(null);
      setImportMessage(null);
      const formData = new FormData();
      formData.append("file", harFile);
      formData.append("target", target.trim());
      formData.append("name", harFile.name.replace(/\.[^.]+$/, ""));
      const response = await fetch(`${API_BASE}/api/profiles/import-har`, { method: "POST", body: formData });
      const data = (await response.json()) as { detail?: string; profile?: ProfileSummary };
      if (!response.ok) throw new Error(data.detail || "HAR import failed.");
      setImportMessage(`Imported ${data.profile?.name || "HAR profile"}.`);
      setHarFile(null);
      await refreshProfiles();
    } catch (error) {
      setImportError((error as Error).message);
    }
  };

  const importOpenapi = async (event: FormEvent) => {
    event.preventDefault();
    if (!openapiFile || !target.trim()) {
      setImportError("Select an OpenAPI file and target first.");
      return;
    }
    try {
      setImportError(null);
      setImportMessage(null);
      const formData = new FormData();
      formData.append("file", openapiFile);
      formData.append("target", target.trim());
      formData.append("name", openapiFile.name.replace(/\.[^.]+$/, ""));
      const response = await fetch(`${API_BASE}/api/profiles/import-openapi`, { method: "POST", body: formData });
      const data = (await response.json()) as { detail?: string; profile?: ProfileSummary };
      if (!response.ok) throw new Error(data.detail || "OpenAPI import failed.");
      setImportMessage(`Imported ${data.profile?.name || "OpenAPI profile"}.`);
      setOpenapiFile(null);
      await refreshProfiles();
    } catch (error) {
      setImportError((error as Error).message);
    }
  };

  const importCurl = async (event: FormEvent) => {
    event.preventDefault();
    if (!curlCommand.trim() || !target.trim()) {
      setImportError("Paste a cURL command and target first.");
      return;
    }
    try {
      setImportError(null);
      setImportMessage(null);
      const response = await fetch(`${API_BASE}/api/profiles/import-curl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim(), curl: curlCommand.trim(), name: "Imported cURL" }),
      });
      const data = (await response.json()) as { detail?: string; profile?: ProfileSummary };
      if (!response.ok) throw new Error(data.detail || "cURL import failed.");
      setImportMessage(`Imported ${data.profile?.name || "cURL profile"}.`);
      setCurlCommand("");
      await refreshProfiles();
    } catch (error) {
      setImportError((error as Error).message);
    }
  };

  const applyFix = (finding: Finding) => {
    if (!ws.current || ws.current.readyState !== WebSocket.OPEN) return;
    const key = finding.url || finding.url_pattern || finding.file_path || "unknown";
    setFixingUrls((prev) => ({ ...prev, [key]: true }));
    ws.current.send(JSON.stringify({ type: "APPLY_FIX", target, finding }));
  };

  const renderEvidence = (title: string, request?: EvidenceRequest) => {
    if (!request) return null;
    return (
      <div className="rounded border border-neutral-800 bg-neutral-950 p-3">
        <div className="mb-2 text-[10px] font-bold uppercase tracking-widest text-teal-400">{title}</div>
        <pre className="overflow-x-auto whitespace-pre-wrap text-[11px] text-neutral-300">{JSON.stringify(request, null, 2)}</pre>
      </div>
    );
  };

  return (
    <>
    <main className="min-h-screen bg-neutral-950 p-8 text-neutral-200">
      <div className="mx-auto max-w-6xl space-y-8">
        <header className="space-y-2 text-center">
          <h1 className="text-6xl font-black tracking-tighter text-emerald-400">VulnPilot</h1>
          <p className="text-neutral-400">Real-time hybrid security analysis with authenticated attack profiles.</p>
        </header>

        <section className="grid gap-6 rounded-2xl border border-neutral-800 bg-neutral-900/60 p-6 xl:grid-cols-3">
          <form onSubmit={importHar} className="space-y-3">
            <h2 className="text-sm font-bold uppercase tracking-widest text-teal-400">Import HAR Profile</h2>
            <input type="file" accept=".har,.json" onChange={(event) => setHarFile(event.target.files?.[0] || null)} className="w-full rounded border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm" />
            <button type="submit" className="w-full rounded bg-teal-500 px-4 py-2 text-sm font-bold uppercase tracking-widest text-neutral-950">Import HAR</button>
          </form>
          <form onSubmit={importCurl} className="space-y-3">
            <h2 className="text-sm font-bold uppercase tracking-widest text-emerald-400">Import cURL Profile</h2>
            <textarea rows={5} value={curlCommand} onChange={(event) => setCurlCommand(event.target.value)} placeholder='curl "https://target/app" -H "Cookie: session=..."' className="w-full rounded border border-neutral-800 bg-neutral-950 px-3 py-2 font-mono text-sm" />
            <button type="submit" className="w-full rounded bg-emerald-500 px-4 py-2 text-sm font-bold uppercase tracking-widest text-neutral-950">Import cURL</button>
          </form>
          <form onSubmit={importOpenapi} className="space-y-3">
            <h2 className="text-sm font-bold uppercase tracking-widest text-indigo-400">Import OpenAPI/Swagger</h2>
            <input type="file" accept=".yaml,.yml,.json" onChange={(event) => setOpenapiFile(event.target.files?.[0] || null)} className="w-full rounded border border-neutral-800 bg-neutral-950 px-3 py-2 text-sm" />
            <button type="submit" className="w-full rounded bg-indigo-500 px-4 py-2 text-sm font-bold uppercase tracking-widest text-neutral-950">Import Spec</button>
          </form>
          {(importMessage || importError) && <div className={`xl:col-span-3 rounded border px-4 py-3 text-sm ${importError ? "border-red-500/30 bg-red-500/10 text-red-400" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"}`}>{importError || importMessage}</div>}
        </section>

        <form onSubmit={startScan} className="space-y-4 rounded-2xl border border-neutral-800 bg-neutral-900/60 p-6">
          <div className="grid gap-4 md:grid-cols-2">
            <input value={target} onChange={(event) => setTarget(event.target.value)} required placeholder="Target URL, GitHub, or local path" className="rounded border border-neutral-800 bg-neutral-950 px-3 py-3 text-sm" />
            <input value={sessionCookie} onChange={(event) => setSessionCookie(event.target.value)} placeholder="session=xyz... (optional)" className="rounded border border-neutral-800 bg-neutral-950 px-3 py-3 text-sm" />
          </div>
          <div className="grid gap-4 md:grid-cols-[2fr,1fr]">
            <select value={selectedProfileId} onChange={(event) => setSelectedProfileId(event.target.value)} className="rounded border border-neutral-800 bg-neutral-950 px-3 py-3 text-sm">
              <option value="">No saved attack profile</option>
              {profiles.map((profile) => (
                <option key={`profile-${profile.id}`} value={profile.id}>
                  {profile.name} ({profile.request_count} requests, {profile.source_type})
                </option>
              ))}
            </select>
            <label className="flex items-center gap-3 rounded border border-neutral-800 bg-neutral-950 px-3 py-3 text-sm">
              <input type="checkbox" checked={useProfileRequests} onChange={(event) => setUseProfileRequests(event.target.checked)} className="accent-emerald-500" />
              Use profile requests
            </label>
          </div>
          <button type="submit" disabled={loading} className="w-full rounded bg-emerald-500 px-4 py-3 text-sm font-black uppercase tracking-widest text-neutral-950 disabled:opacity-50">
            {loading ? "Scanning..." : "Launch Real-time Scan"}
          </button>
          {errorInfo && <div className="rounded border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">{errorInfo}</div>}
        </form>

        {(loading || logs.length > 0) && (
          <section className="grid gap-6 lg:grid-cols-3">
            <div className="rounded-2xl border border-neutral-800 bg-neutral-900/60 p-6">
              <h3 className="mb-4 text-xs font-bold uppercase tracking-widest text-neutral-500">Mission Progress</h3>
              <div className="space-y-3">
                {stages.filter((stage) => stage !== "complete").map((stage, index) => (
                  <div key={`stage-${stage}`} className="flex items-center gap-3">
                    <div className={`flex h-8 w-8 items-center justify-center rounded-full border text-[10px] font-bold ${stageClass(stage)}`}>{index + 1}</div>
                    <div className="flex-1">
                      <div className="text-[10px] uppercase tracking-widest text-neutral-400">{stage}</div>
                      <div className="mt-1 h-1 rounded bg-neutral-950">
                        <div className="h-1 rounded bg-emerald-500" style={{ width: progress.stage === stage ? `${progress.percent}%` : stageClass(stage).includes("bg-emerald-500") ? "100%" : "0%" }} />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="lg:col-span-2 rounded-2xl border border-neutral-800 bg-neutral-900/60 p-4">
              <div className="mb-3 text-xs font-bold uppercase tracking-widest text-neutral-500">engine_output.log</div>
              <div className="h-80 space-y-1 overflow-y-auto rounded border border-neutral-800 bg-neutral-950 p-3 font-mono text-xs">
                {logs.map((log, index) => (
                  <div key={`log-${index}`} className={log.message.startsWith("[!]") ? "text-red-400" : log.message.startsWith("[*]") ? "text-emerald-400" : "text-neutral-300"}>
                    [{new Date().toLocaleTimeString([], { hour12: false })}] {log.message}
                  </div>
                ))}
                <div ref={terminalEndRef} />
              </div>
            </div>
          </section>
        )}

        {findings.length > 0 && (
          <section className="space-y-6">
            <div className="flex items-center justify-between border-b border-neutral-800 pb-4">
              <h2 className="text-2xl font-bold text-emerald-400">Active Finding Stream</h2>
              <div className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-500">{findings.length} findings</div>
            </div>
            {[...findings].sort((left, right) => {
              const order: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
              return (order[(right.severity || "").toLowerCase()] || 0) - (order[(left.severity || "").toLowerCase()] || 0);
            }).map((finding, index) => {
              const key = finding.url || finding.url_pattern || finding.file_path || `finding-${index}`;
              return (
                <article key={`f-${index}-${key}`} className="space-y-4 rounded-2xl border border-neutral-800 bg-neutral-900/60 p-6">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <h3 className="text-xl font-bold text-white">{finding.vulnerability_type || "Untitled Finding"}</h3>
                      {finding.is_verified && <div className="mt-2 w-fit rounded border border-emerald-400/30 bg-emerald-400/10 px-2 py-1 text-[10px] font-bold uppercase tracking-widest text-emerald-400">Verified Proof</div>}
                    </div>
                    <div className="rounded border border-neutral-700 px-2 py-1 text-xs uppercase tracking-widest text-neutral-300">{finding.severity || "Unknown"}</div>
                  </div>
                  <div className="rounded border border-emerald-900/30 bg-emerald-950/20 p-3 font-mono text-xs text-emerald-400">{finding.url || finding.file_path || finding.url_pattern || "General Surface"}</div>
                  
                  {finding.tutor_explanation ? (
                    <div className="rounded-lg border border-purple-500/30 bg-purple-950/20 p-4">
                      <div className="mb-2 flex items-center gap-2 text-[10px] font-black uppercase tracking-widest text-purple-400">
                        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" /></svg>
                        AI Security Tutor Analysis
                      </div>
                      <p className="text-sm leading-relaxed text-purple-100">{finding.tutor_explanation}</p>
                    </div>
                  ) : (
                    <p className="text-sm leading-relaxed text-neutral-300">{finding.explanation}</p>
                  )}

                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="rounded border border-neutral-800 bg-neutral-950 p-3">
                      <div className="mb-2 text-[10px] font-bold uppercase tracking-widest text-emerald-400">Manual Validation</div>
                      <p className="whitespace-pre-wrap text-xs text-neutral-300">{finding.manual_poc}</p>
                    </div>
                    {finding.poc_script && (
                      <div className="rounded border border-neutral-800 bg-neutral-950 p-3">
                        <div className="mb-2 flex items-center justify-between text-[10px] font-bold uppercase tracking-widest text-teal-400">
                          <span>Auto-PoC Script</span>
                          <button onClick={() => navigator.clipboard.writeText(finding.poc_script || "")} className="rounded border border-neutral-800 px-2 py-1 text-[9px] text-neutral-400">Copy</button>
                        </div>
                        <pre className="overflow-x-auto text-[11px] text-neutral-300">{finding.poc_script}</pre>
                      </div>
                    )}
                  </div>
                  {finding.evidence && (
                    <div className="space-y-4 border-t border-neutral-800 pt-4">
                      <div className="flex items-center justify-between">
                        <div className="text-[10px] font-bold uppercase tracking-widest text-teal-400">Replayable Evidence</div>
                        <div className="text-[10px] uppercase tracking-widest text-neutral-500">Source: {finding.evidence.source || "crawler"}</div>
                      </div>
                      <div className="grid gap-4 md:grid-cols-2">
                        {renderEvidence("Baseline Request", finding.evidence.baseline_request)}
                        {renderEvidence("Mutated Request", finding.evidence.mutated_request)}
                      </div>
                      <div className="grid gap-4 md:grid-cols-[1fr,2fr]">
                        <div className="rounded border border-neutral-800 bg-neutral-950 p-3">
                          <div className="mb-2 text-[10px] font-bold uppercase tracking-widest text-neutral-500">Status Delta</div>
                          <div className="text-sm text-neutral-200">
                            {String(finding.evidence.baseline_status ?? "n/a")} {"->"} {String(finding.evidence.mutated_status ?? "n/a")}
                          </div>
                          <div className="mt-2 text-xs text-neutral-400">{finding.evidence.delta_reason}</div>
                        </div>
                        <div className="rounded border border-neutral-800 bg-neutral-950 p-3">
                          <div className="mb-2 flex items-center justify-between text-[10px] font-bold uppercase tracking-widest text-neutral-500">
                            <span>Replay cURL</span>
                            <button onClick={() => navigator.clipboard.writeText(finding.evidence?.replay_curl || "")} className="rounded border border-neutral-800 px-2 py-1 text-[9px] text-neutral-400">Copy</button>
                          </div>
                          <pre className="overflow-x-auto whitespace-pre-wrap text-[11px] text-neutral-300">{finding.evidence.replay_curl}</pre>
                        </div>
                      </div>
                    </div>
                  )}
                  {(finding.remediation_code || finding.remediation_steps) && (
                    <div className="space-y-4 border-t border-neutral-800 pt-4">
                      <div className="text-[10px] font-bold uppercase tracking-widest text-emerald-400">Secure Implementation & Remediation</div>
                      <div className="grid gap-4 md:grid-cols-[1fr,2fr]">
                        <div className="rounded border border-neutral-800 bg-neutral-950 p-3 text-xs text-neutral-300">{finding.remediation_steps}</div>
                        <div className="rounded border border-emerald-500/20 bg-emerald-950/20 p-3">
                          <div className="mb-2 flex items-center justify-between text-[10px] font-bold uppercase tracking-widest text-emerald-400">
                            <span>Safe Code Snippet</span>
                            <button onClick={() => navigator.clipboard.writeText(finding.remediation_code || "")} className="rounded bg-emerald-500 px-2 py-1 text-[9px] text-neutral-950">Copy</button>
                          </div>
                          <pre className="overflow-x-auto whitespace-pre-wrap text-[11px] text-emerald-50">{finding.remediation_code}</pre>
                          <button onClick={() => applyFix(finding)} disabled={fixingUrls[key]} className="mt-3 rounded border border-emerald-500/40 px-3 py-2 text-[10px] font-bold uppercase tracking-widest text-emerald-400 disabled:opacity-50">
                            {fixingUrls[key] ? "Refactoring..." : "Apply Fix to File"}
                          </button>
                          {fixStatus[key] === "success" && <div className="mt-2 text-[10px] font-bold uppercase tracking-widest text-emerald-400">Fix Applied Successfully</div>}
                          {fixStatus[key] === "error" && <div className="mt-2 text-[10px] font-bold uppercase tracking-widest text-red-400">Auto-Fix Failed</div>}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Adversarial Arena launch button */}
                  <div className="border-t border-neutral-800 pt-4">
                    <button
                      onClick={() => setArenaFinding(finding)}
                      className="w-full rounded-lg border border-orange-500/40 bg-gradient-to-r from-red-900/20 to-orange-900/20 px-4 py-3 text-[10px] font-black uppercase tracking-widest text-orange-400 hover:from-red-900/40 hover:to-orange-900/40 transition-all flex items-center justify-center gap-2"
                    >
                      <span>⚔</span>
                      <span>Launch AI Adversarial Arena</span>
                      <span className="rounded border border-orange-500/30 px-1.5 py-0.5 text-[9px] text-orange-500">Red vs Blue + Honey-Patch</span>
                    </button>
                  </div>
                </article>
              );
            })}
          </section>
        )}
      </div>
    </main>
    {arenaFinding && <ArenaModal finding={arenaFinding} target={target} onClose={() => setArenaFinding(null)} />}
    </>
  );
}
