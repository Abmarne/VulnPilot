"use client";

import { useState } from "react";

export default function Home() {
  const [targetUrl, setTargetUrl] = useState("");
  const [codebasePath, setCodebasePath] = useState("");
  const [sessionCookie, setSessionCookie] = useState("");
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [errorInfo, setErrorInfo] = useState<string | null>(null);

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setScanResult(null);
    setErrorInfo(null);

    try {
      const res = await fetch("http://localhost:8000/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
           target_url: targetUrl, 
           codebase_path: codebasePath || null,
           session_cookie: sessionCookie || null 
        }),
      });
      
      const data = await res.json();
      if (!res.ok) {
         throw new Error(data.detail || "Error from engine");
      }
      setScanResult(data);
    } catch (error: any) {
      console.error(error);
      setErrorInfo(error.message || "Failed to reach orchestrator backend. Make sure the Python server is running.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-200 p-8 flex flex-col items-center font-sans tracking-wide">
      <div className="max-w-4xl w-full mt-4">
        <div className="text-center mb-10">
          <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-br from-emerald-400 to-teal-600 mb-4 tracking-tighter">
            VulnPilot
          </h1>
          <p className="text-neutral-400 text-lg font-light tracking-wide">
            Hybrid Context-Aware Security Analysis (DAST + SAST)
          </p>
        </div>

        <form onSubmit={startScan} className="bg-neutral-900 border border-neutral-800 rounded-2xl p-8 shadow-2xl relative overflow-hidden mb-8">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[200%] h-1 bg-gradient-to-r from-transparent via-emerald-500 to-transparent opacity-20"></div>
          
          <div className="space-y-6 relative z-10">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-semibold mb-2 text-neutral-300 tracking-wide uppercase">Target Running App (DAST)</label>
                  <input
                    type="url"
                    required
                    placeholder="http://localhost:3000"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:border-emerald-500 transition-all font-mono text-sm"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-semibold mb-2 text-neutral-300 tracking-wide uppercase flex items-center justify-between">
                    <span>Source Code (SAST)</span>
                    <span className="text-emerald-500 font-normal text-xs normal-case bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">New (Hybrid Engine)</span>
                  </label>
                  <input
                    type="text"
                    placeholder="https://github.com/... OR C:\my-app"
                    value={codebasePath}
                    onChange={(e) => setCodebasePath(e.target.value)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:border-emerald-500 transition-all font-mono text-sm"
                  />
                </div>
            </div>

            <div>
              <label className="block text-sm font-semibold mb-2 text-neutral-300 tracking-wide uppercase">
                Session Cookie (Optional)
              </label>
              <textarea
                placeholder="Connect as authenticated user..."
                value={sessionCookie}
                onChange={(e) => setSessionCookie(e.target.value)}
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:border-emerald-500 transition-all font-mono text-sm h-16 resize-none"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-emerald-500 hover:bg-emerald-400 text-neutral-950 font-black tracking-widest uppercase text-base py-4 rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center shadow-[0_0_20px_-5px_rgba(16,185,129,0.4)]"
            >
              {loading ? <span className="animate-pulse">Running Hybrid Scan...</span> : "Launch Global Scan"}
            </button>
          </div>
        </form>

        {errorInfo && (
           <div className="p-4 bg-red-500/10 border border-red-500/20 text-red-400 rounded font-mono text-sm flex items-center mb-6">
             <span className="mr-2">❌</span> {errorInfo}
           </div>
        )}
        
        {scanResult && scanResult.findings && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-8 duration-700">
            <div className="flex items-center justify-between mb-4 border-b border-neutral-800 pb-4">
                <h2 className="text-2xl font-bold text-emerald-400 tracking-tight">Vulnerability Report</h2>
                <div className="px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 text-xs font-mono rounded-full">
                    {scanResult.findings.length} Anomalies Evaluated
                </div>
            </div>
            
            {scanResult.findings.length === 0 ? (
                <div className="p-8 bg-neutral-900 rounded-xl border border-neutral-800 text-center text-neutral-500">
                    No vulnerabilities discovered across surface and codebase.
                </div>
            ) : (
                scanResult.findings.map((finding: any, idx: number) => {
                    const sev = (finding.severity || "Unknown").toLowerCase();
                    const sevColor = sev === "critical" ? "text-purple-400 bg-purple-900/30 border-purple-800" 
                                   : sev === "high" ? "text-red-400 bg-red-900/30 border-red-800"
                                   : sev === "medium" ? "text-amber-400 bg-amber-900/30 border-amber-800"
                                   : "text-blue-400 bg-blue-900/30 border-blue-800";
                                   
                    return (
                        <div key={idx} className="bg-neutral-900 border border-neutral-800 rounded-xl p-6 relative overflow-hidden shadow-xl hover:border-neutral-700 transition-colors">
                            <div className="absolute top-0 left-0 w-1 h-full bg-emerald-500/50"></div>
                            
                            <h3 className="text-xl font-bold text-white mb-3">{finding.vulnerability_type}</h3>
                            
                            <div className="flex space-x-3 mb-5 text-xs font-mono">
                                <span className={`px-2 py-1 rounded border ${sevColor}`}>Severity: {finding.severity || "Unknown"}</span>
                                <span className="text-neutral-400 bg-neutral-950 border border-neutral-800 px-2 py-1 rounded truncate max-w-sm">Location: {finding.url || finding.file_path || "General"}</span>
                            </div>
                            
                            <div className="mb-6">
                                <h4 className="text-xs uppercase font-bold text-neutral-500 mb-1">Gemini Explanation</h4>
                                <p className="text-neutral-300 text-sm leading-relaxed">{finding.explanation}</p>
                            </div>
                            
                            <div className="bg-neutral-950 p-5 rounded-lg border border-neutral-800 shadow-inner">
                                <span className="text-xs uppercase text-emerald-500 font-bold tracking-wider mb-2 flex items-center">
                                    Manual Verification PoC & Remediation
                                </span>
                                <p className="text-sm font-mono text-neutral-300 whitespace-pre-wrap leading-relaxed">{finding.manual_poc}</p>
                            </div>
                        </div>
                    );
                })
            )}
          </div>
        )}
      </div>
    </main>
  );
}
