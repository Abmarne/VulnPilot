"use client";

import { useState, useEffect, useRef } from "react";

export default function Home() {
  const [target, setTarget] = useState("");
  const [sessionCookie, setSessionCookie] = useState("");
  const [loading, setLoading] = useState(false);
  const [findings, setFindings] = useState<any[]>([]);
  const [logs, setLogs] = useState<{ message: string; stage: string }[]>([]);
  const [progress, setProgress] = useState({ stage: "init", percent: 0 });
  const [errorInfo, setErrorInfo] = useState<string | null>(null);
  
  const ws = useRef<WebSocket | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs]);

  const startScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return;

    setLoading(true);
    setFindings([]);
    setLogs([]);
    setProgress({ stage: "init", percent: 0 });
    setErrorInfo(null);

    // Initialize WebSocket
    const socket = new WebSocket("ws://localhost:8000/api/scan/ws");
    ws.current = socket;

    socket.onopen = () => {
      socket.send(JSON.stringify({
        type: "START_SCAN",
        target: target,
        session_cookie: sessionCookie || null
      }));
    };

    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      if (data.type === "log") {
        setLogs(prev => [...prev, { message: data.message, stage: data.stage }]);
      } else if (data.type === "progress") {
        setProgress({ stage: data.stage, percent: data.percent });
      } else if (data.type === "finding") {
        setFindings(prev => [...prev, data.data]);
      }
    };

    socket.onclose = () => {
      setLoading(false);
      setProgress(prev => ({ ...prev, percent: 100 }));
    };

    socket.onerror = (err) => {
      console.error("WS Error:", err);
      setErrorInfo("WebSocket connection failed. Ensure backend is running.");
      setLoading(false);
    };
  };

  const getStageColor = (stage: string) => {
    const stages = ["init", "recon", "sast", "fuzzing", "analysis", "complete"];
    const currentIdx = stages.indexOf(progress.stage);
    const stageIdx = stages.indexOf(stage);
    
    if (stageIdx < currentIdx || progress.stage === "complete") return "bg-emerald-500 border-emerald-400 text-neutral-950";
    if (stageIdx === currentIdx) return "bg-emerald-500/20 border-emerald-500 text-emerald-400 animate-pulse";
    return "bg-neutral-900 border-neutral-800 text-neutral-500";
  };

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-200 p-8 flex flex-col items-center font-sans tracking-wide">
      <div className="max-w-5xl w-full mt-4">
        {/* Header */}
        <div className="text-center mb-10">
          <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-br from-emerald-400 to-teal-600 mb-4 tracking-tighter">
            VulnPilot
          </h1>
          <p className="text-neutral-400 text-lg font-light tracking-wide">
            Real-time Hybrid Context-Aware Security Analysis
          </p>
        </div>

        {/* Input Form */}
        <form onSubmit={startScan} className="bg-neutral-900/50 backdrop-blur-xl border border-neutral-800 rounded-2xl p-8 shadow-2xl relative overflow-hidden mb-8">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[200%] h-1 bg-gradient-to-r from-transparent via-emerald-500 to-transparent opacity-20"></div>
          
          <div className="space-y-6 relative z-10">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-xs font-bold mb-2 text-neutral-500 tracking-widest uppercase">Target Application</label>
                <input
                  type="text"
                  required
                  placeholder="URL, GitHub, or Local Path"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="w-full bg-neutral-950/50 border border-neutral-800 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:border-emerald-500/50 transition-all font-mono text-sm"
                />
              </div>
              <div>
                <label className="block text-xs font-bold mb-2 text-neutral-500 tracking-widest uppercase">Auth Credentials (Cookie)</label>
                <input
                  type="text"
                  placeholder="session=xyz... (Optional)"
                  value={sessionCookie}
                  onChange={(e) => setSessionCookie(e.target.value)}
                  className="w-full bg-neutral-950/50 border border-neutral-800 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:border-emerald-500/50 transition-all font-mono text-sm"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-emerald-500 hover:bg-emerald-400 text-neutral-950 font-black tracking-widest uppercase text-sm py-4 rounded-lg transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_30px_-10px_rgba(16,185,129,0.5)]"
            >
              {loading ? "Engaging Hybrid Engine..." : "Launch Real-time Scan"}
            </button>
          </div>
        </form>

        {errorInfo && (
           <div className="p-4 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl font-mono text-xs flex items-center mb-6 animate-shake">
             <span className="mr-2">⚠️</span> {errorInfo}
           </div>
        )}

        {/* Real-time Dashboard */}
        {(loading || logs.length > 0) && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12 animate-in fade-in zoom-in duration-500">
            {/* Progress & Status */}
            <div className="lg:col-span-1 space-y-6">
              <div className="bg-neutral-900 border border-neutral-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
                <h3 className="text-xs font-bold text-neutral-500 uppercase tracking-widest mb-6 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
                  Mission Progress
                </h3>
                
                <div className="space-y-4">
                  {["init", "recon", "sast", "fuzzing", "analysis"].map((s) => (
                    <div key={s} className="flex items-center gap-4">
                      <div className={`w-8 h-8 rounded-full border-2 flex items-center justify-center text-[10px] font-bold transition-all duration-500 ${getStageColor(s)}`}>
                        {s === "init" ? "1" : s === "recon" ? "2" : s === "sast" ? "3" : s === "fuzzing" ? "4" : "5"}
                      </div>
                      <div className="flex-1">
                        <div className="text-[10px] uppercase font-bold tracking-wider text-neutral-400">{s}</div>
                        <div className="h-1 w-full bg-neutral-950 rounded-full mt-1 overflow-hidden">
                          <div 
                            className="h-full bg-emerald-500 transition-all duration-1000 ease-out"
                            style={{ width: progress.stage === s ? `${progress.percent}%` : (getStageColor(s).includes("bg-emerald-500") ? "100%" : "0%") }}
                          ></div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Live Terminal */}
            <div className="lg:col-span-2 bg-neutral-900 border border-neutral-800 rounded-2xl shadow-xl overflow-hidden flex flex-col h-[320px]">
              <div className="bg-neutral-950/50 border-b border-neutral-800 px-4 py-2 flex items-center justify-between">
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-500/20 border border-red-500/40"></div>
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-500/20 border border-amber-500/40"></div>
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/20 border border-emerald-500/40"></div>
                </div>
                <span className="text-[10px] font-mono text-neutral-500 uppercase tracking-widest">engine_output.log</span>
              </div>
              <div className="p-4 font-mono text-xs overflow-y-auto space-y-1 flex-1 scrollbar-thin scrollbar-thumb-neutral-800">
                {logs.map((log, i) => (
                  <div key={i} className="flex gap-3 animate-in slide-in-from-left-2 duration-300">
                    <span className="text-neutral-600 shrink-0">[{new Date().toLocaleTimeString([], { hour12: false })}]</span>
                    <span className={log.message.startsWith("[!]") ? "text-red-400" : log.message.startsWith("[*]") ? "text-emerald-400" : "text-neutral-400"}>
                      {log.message}
                    </span>
                  </div>
                ))}
                <div ref={terminalEndRef} />
              </div>
            </div>
          </div>
        )}

        {/* Findings List */}
        {findings.length > 0 && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-8 duration-700">
            <div className="flex items-center justify-between mb-4 border-b border-neutral-800 pb-4">
                <h2 className="text-2xl font-bold text-emerald-400 tracking-tight">Active Finding Stream</h2>
                <div className="px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 text-xs font-mono rounded-full">
                    {findings.length} Vulnerabilities Detected
                </div>
            </div>
            
            {findings
              .sort((a, b) => {
                const order: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
                return (order[b.severity?.toLowerCase()] || 0) - (order[a.severity?.toLowerCase()] || 0);
              })
              .map((finding: any, idx: number) => {
                const sev = (finding.severity || "Unknown").toLowerCase();
                const sevColor = sev === "critical" ? "text-purple-400 bg-purple-900/30 border-purple-800" 
                               : sev === "high" ? "text-red-400 bg-red-900/30 border-red-800"
                               : sev === "medium" ? "text-amber-400 bg-amber-900/30 border-amber-800"
                               : "text-blue-400 bg-blue-900/30 border-blue-800";
                               
                return (
                    <div key={idx} className="bg-neutral-900 border border-neutral-800 rounded-xl p-6 relative overflow-hidden shadow-xl hover:border-neutral-700 transition-all hover:translate-x-1 duration-300 group">
                        <div className={`absolute top-0 left-0 w-1 h-full ${sev === 'critical' ? 'bg-purple-500' : sev === 'high' ? 'bg-red-500' : 'bg-emerald-500'}`}></div>
                        
                        <div className="flex justify-between items-start mb-4">
                          <div className="flex flex-col gap-1">
                            <h3 className="text-xl font-bold text-white">{finding.vulnerability_type}</h3>
                            {finding.is_verified && (
                              <div className="flex items-center gap-1.5 text-[10px] font-black text-emerald-400 uppercase tracking-tighter bg-emerald-400/10 border border-emerald-400/20 px-2 py-0.5 rounded-md w-fit animate-pulse">
                                <span className="text-xs">🛡️</span> Verified Proof
                              </div>
                            )}
                          </div>
                          <span className={`px-2 py-1 rounded border text-[10px] font-bold uppercase tracking-widest ${sevColor}`}>
                            {finding.severity || "Unknown"}
                          </span>
                        </div>
                        
                        <div className="mb-6 space-y-4">
                            <div>
                              <h4 className="text-[10px] uppercase font-bold text-neutral-500 mb-1 tracking-widest">Location / Sink</h4>
                              <p className="text-emerald-500 font-mono text-xs bg-emerald-950/30 p-2 rounded border border-emerald-900/20">
                                {finding.url || finding.file_path || "General Surface"}
                              </p>
                            </div>
                            <div>
                              <h4 className="text-[10px] uppercase font-bold text-neutral-500 mb-1 tracking-widest">Intelligence Commentary</h4>
                              <p className="text-neutral-400 text-sm leading-relaxed">{finding.explanation}</p>
                            </div>
                        </div>
                        
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="bg-neutral-950 p-4 rounded-lg border border-neutral-800 shadow-inner">
                              <span className="text-[10px] uppercase text-emerald-500 font-bold tracking-widest mb-2 block">Manual Validation</span>
                              <p className="text-xs font-mono text-neutral-300 whitespace-pre-wrap">{finding.manual_poc}</p>
                          </div>

                          {finding.poc_script && (
                            <div className="bg-neutral-950 p-4 rounded-lg border border-neutral-800 shadow-inner relative overflow-hidden">
                                <div className="flex items-center justify-between mb-2">
                                    <span className="text-[10px] uppercase text-teal-400 font-bold tracking-widest">Auto-PoC script</span>
                                    <button 
                                        onClick={() => navigator.clipboard.writeText(finding.poc_script)}
                                        className="text-[9px] text-neutral-500 hover:text-teal-400 transition-all uppercase font-bold tracking-widest bg-neutral-900 px-2 py-1 rounded border border-neutral-800"
                                    >
                                        Copy
                                    </button>
                                </div>
                                <pre className="text-[11px] font-mono text-neutral-300 overflow-x-auto p-2 bg-neutral-900/50 rounded border border-emerald-900/10">
                                    <code>{finding.poc_script}</code>
                                </pre>
                            </div>
                          )}
                        </div>

                        {/* New Remediation Section */}
                        {(finding.remediation_code || finding.remediation_steps) && (
                          <div className="mt-8 pt-6 border-t border-neutral-800/50 animate-in slide-in-from-top-4 duration-500">
                             <h4 className="text-[10px] uppercase font-bold text-emerald-400 mb-4 tracking-widest flex items-center gap-2">
                               <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></span>
                               🛡️ Secure Implementation & Remediation
                             </h4>
                             
                             <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                               {/* Steps / Plan */}
                               <div className="md:col-span-1 space-y-3">
                                  <span className="text-[9px] uppercase text-neutral-500 font-bold tracking-tighter block mb-2">Resolution Plan</span>
                                  <div className="text-xs text-neutral-300 space-y-2 font-light">
                                    {finding.remediation_steps?.split('\n').map((step: string, i: number) => (
                                      <div key={i} className="flex gap-2 leading-relaxed">
                                        <span className="text-emerald-500 font-bold shrink-0">{i + 1}.</span>
                                        <p>{step.trim().replace(/^\d+\.\s*/, '')}</p>
                                      </div>
                                    ))}
                                  </div>
                               </div>

                               {/* Secure Code */}
                               <div className="md:col-span-2">
                                  <div className="bg-emerald-950/20 rounded-xl border border-emerald-500/20 p-5 relative group overflow-hidden">
                                     <div className="absolute top-0 right-0 p-3 opacity-0 group-hover:opacity-100 transition-opacity">
                                        <button 
                                          onClick={() => navigator.clipboard.writeText(finding.remediation_code)}
                                          className="bg-emerald-500 text-neutral-950 px-3 py-1 rounded text-[10px] font-black uppercase tracking-widest shadow-xl hover:bg-emerald-400 transition-all"
                                        >
                                          Copy Fix
                                        </button>
                                     </div>
                                     <span className="text-[9px] uppercase text-emerald-500/70 font-bold tracking-tighter block mb-3">Safe Code Snippet</span>
                                     <pre className="text-xs font-mono text-emerald-50 overflow-x-auto scrollbar-thin scrollbar-thumb-emerald-900/50">
                                       <code>{finding.remediation_code}</code>
                                     </pre>
                                  </div>
                               </div>
                             </div>
                          </div>
                        )}
                    </div>
                );
            })}
          </div>
        )}
      </div>
    </main>
  );
}
