"use client";

import { useState, useEffect } from "react";
import { Search, Shield, Activity, List, LayoutPanelLeft, Clock, Zap, AlertTriangle, ShieldCheck, X } from "lucide-react";
import { MissionConsole } from "./components/MissionConsole";
import { ModelSettings, LLMConfig } from "./components/ModelSettings";
import { SourceHub } from "./components/SourceHub";

const getApiBase = () => {
  if (typeof window === "undefined") return "http://localhost:8000";
  // If we are on localhost:3000 (Next.js default), assume backend is on 8000
  if (window.location.hostname === "localhost") return "http://localhost:8000";
  return window.location.origin;
};

const API_BASE = getApiBase();

export default function Home() {
  const [target, setTarget] = useState("");
  const [sessionCookie] = useState("");
  const [showAutopilot, setShowAutopilot] = useState(false);
  const [showSourceHub, setShowSourceHub] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [pastScans, setPastScans] = useState<{
    id: string;
    timestamp: string;
    target: string;
    finding_count: number;
    [key: string]: unknown;
  }[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [selectedScan, setSelectedScan] = useState<any>(null);

  // LLM Configuration (Defaults to Groq as approved)
  const [llmConfig, setLlmConfig] = useState<LLMConfig>({
    provider: "default",
    model: "auto",
    api_key: ""
  });

  const handleLlmConfigChange = (newConfig: LLMConfig) => {
    setLlmConfig(newConfig);
    localStorage.setItem("vp_llm_config", JSON.stringify(newConfig));
  };

  const fetchHistory = async () => {
    setIsLoadingHistory(true);
    try {
      const response = await fetch(`${API_BASE}/api/history`);
      const data = await response.json();
      setPastScans(data.scans || []);
    } catch (err) {
      console.error("Failed to fetch history", err);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  // Load persistence
  useEffect(() => {
    const saved = localStorage.getItem("vp_llm_config");
    if (saved) {
      try {
        setLlmConfig(JSON.parse(saved));
      } catch (e) {
        console.error("Failed to load LLM config", e);
      }
    }
    fetchHistory();

    const handleRefresh = () => fetchHistory();
    window.addEventListener("scan_completed", handleRefresh);
    return () => window.removeEventListener("scan_completed", handleRefresh);
  }, []);

  const handleImport = async (type: string, data: string | File) => {
    if (!target.trim()) {
      alert("Please enter a target project name or URL first.");
      return;
    }
    
    setIsImporting(true);
    try {
      const formData = new FormData();
      if (type === "har" || type === "openapi") {
        formData.append("file", data);
        formData.append("target", target.trim());
        formData.append("name", (data as File).name || type);
        
        const endpoint = type === "har" ? "import-har" : "import-openapi";
        const res = await fetch(`${API_BASE}/api/profiles/${endpoint}`, { method: "POST", body: formData });
        if (!res.ok) throw new Error(`Failed to import ${type}`);
      } else if (type === "curl") {
         const res = await fetch(`${API_BASE}/api/profiles/import-curl`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: target.trim(), curl: data, name: "Single Event Study" }),
        });
        if (!res.ok) throw new Error("Failed to import cURL");
      }
      setShowSourceHub(false);
    } catch (err) {
      console.error(err);
      alert(err instanceof Error ? err.message : "An error occurred during import");
    } finally {
      setIsImporting(false);
    }
  };

  const handleViewScan = async (scanId: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/history/${scanId}`);
      if (!res.ok) throw new Error("Failed to load scan details");
      const data = await res.json();
      setSelectedScan(data);
    } catch (err) {
      console.error(err);
      alert("Could not load mission details.");
    }
  };

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-200 selection:bg-emerald-500/30 font-sans">
      {/* Background Glow */}
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-full h-[500px] bg-emerald-500/5 blur-[120px] pointer-events-none" />

      {/* Nav */}
      <nav className="relative z-50 border-b border-white/5 bg-neutral-950/50 backdrop-blur-md px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-400 to-teal-600 flex items-center justify-center shadow-lg shadow-emerald-500/20">
              <Shield className="w-6 h-6 text-neutral-950" />
            </div>
            <div>
              <h1 className="text-xl font-black tracking-tighter text-white uppercase">VulnPilot</h1>
              <p className="text-[10px] font-bold text-emerald-500/60 uppercase tracking-[0.2em] -mt-1">Advisor Mode</p>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <ModelSettings onConfigChange={handleLlmConfigChange} initialConfig={llmConfig} />
            <button 
              onClick={() => setHistoryOpen(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-neutral-900 border border-neutral-800 hover:border-emerald-500/50 transition-all group"
            >
              <Clock className="w-4 h-4 text-neutral-500 group-hover:text-emerald-400" />
              <span className="text-sm font-bold text-neutral-400 group-hover:text-white uppercase tracking-wider">Archive</span>
            </button>
          </div>
        </div>
      </nav>

      <div className="relative z-10 max-w-4xl mx-auto px-6 py-20 lg:py-32">
        {/* Simple Hero Section */}
        <header className="text-center space-y-4 mb-20 animate-in fade-in slide-in-from-top-4 duration-700">
           <h2 className="text-5xl lg:text-7xl font-black tracking-tighter text-white leading-tight">
            Security audit your project <br /> 
            <span className="text-neutral-500">with expert AI help.</span>
          </h2>
          <p className="text-lg text-neutral-400 max-w-2xl mx-auto leading-relaxed">
            Enter your project URL or code path below. Our AI consultant will autonomously analyze, test, and verify security risks for you.
          </p>
        </header>

        {/* The Clean Audit Bar */}
        <div className="relative group animate-in fade-in slide-in-from-bottom-4 duration-1000 delay-200">
          <div className="absolute -inset-1 bg-gradient-to-r from-emerald-500/20 to-teal-500/20 rounded-2xl blur opacity-25 group-hover:opacity-100 transition duration-1000 group-hover:duration-200" />
          <div className="relative flex flex-col md:flex-row items-stretch gap-2 bg-neutral-900/80 border border-neutral-800 rounded-2xl p-2.5 shadow-2xl backdrop-blur-xl">
             <div className="flex-1 relative flex items-center">
                <Search className="absolute left-5 w-6 h-6 text-neutral-500 group-hover:text-emerald-400 transition-colors" />
                <input 
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="Paste Website URL or Code Path..."
                  className="w-full h-16 bg-transparent pl-14 pr-6 text-lg font-medium text-white placeholder:text-neutral-600 focus:outline-none"
                />
             </div>
              <button 
                onClick={() => {
                  setShowAutopilot(true);
                  setTimeout(() => {
                    document.getElementById("mission-hub")?.scrollIntoView({ behavior: "smooth", block: "start" });
                  }, 100);
                }}
                disabled={!target.trim() || showAutopilot || isImporting}
                className="h-16 px-10 rounded-xl bg-emerald-500 text-neutral-950 font-black uppercase tracking-widest text-sm hover:scale-[1.02] active:scale-[0.98] transition-all shadow-xl shadow-emerald-500/10 disabled:opacity-50 disabled:grayscale disabled:hover:scale-100 flex items-center justify-center gap-3"
              >
                {isImporting ? (
                  <div className="w-5 h-5 border-2 border-neutral-950 border-t-transparent animate-spin rounded-full" />
                ) : (
                  <Zap className="w-5 h-5" />
                )}
                {isImporting ? "Processing..." : "Launch Safety Audit"}
              </button>
          </div>
          
          <div className="mt-6 flex flex-wrap justify-center items-center gap-6">
            <button 
              onClick={() => setShowSourceHub(true)}
              className="flex items-center gap-2 text-xs font-bold text-neutral-500 hover:text-white uppercase tracking-widest transition-colors"
            >
              <Zap className="w-4 h-4 text-teal-400" />
              Upload Advanced Context
            </button>
            <div className="h-1 w-1 rounded-full bg-neutral-800" />
            <div className="text-xs font-bold text-neutral-600 uppercase tracking-widest flex items-center gap-2">
               <ShieldCheck className="w-4 h-4" />
               Certified for Non-IT Users
            </div>
          </div>
        </div>

        {/* Mission View (Integrated AI Feed) */}
        {showAutopilot && (
          <section id="mission-hub" className="mt-32 space-y-12 animate-in fade-in duration-500">
            <div className="grid lg:grid-cols-[1fr, 350px] gap-8 items-start">
               {/* Main Experience Feed */}
               <div className="space-y-8">
                  <div className="flex items-center justify-between border-b border-neutral-800 pb-4">
                    <h3 className="text-sm font-black uppercase tracking-[0.2em] text-emerald-500 flex items-center gap-2">
                      <Activity className="w-4 h-4 animate-pulse" />
                      Auditor Intelligence
                    </h3>
                  </div>
                  
                  <div className="h-[800px]">
                    <MissionConsole 
                      target={target} 
                      sessionCookie={sessionCookie} 
                      llmConfig={llmConfig}
                      onClose={() => setShowAutopilot(false)}
                       autoStart={true}
                    />
                  </div>
               </div>

               {/* Guidelines & Safety Status */}
               <aside className="hidden lg:block space-y-6">
                  <div className="rounded-2xl border border-neutral-800 bg-neutral-900/40 p-6 space-y-4">
                    <h4 className="text-xs font-black uppercase tracking-widest text-neutral-500">How we audit</h4>
                    <div className="space-y-4">
                        <div className="flex gap-4">
                           <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center shrink-0">
                             <List className="w-4 h-4 text-emerald-500" />
                           </div>
                           <div className="text-xs leading-relaxed text-neutral-400">
                              <span className="font-bold text-neutral-200 block mb-1">Mapping</span>
                              The AI maps out every page and feature in your project.
                           </div>
                        </div>
                        <div className="flex gap-4">
                           <div className="w-8 h-8 rounded-lg bg-teal-500/10 flex items-center justify-center shrink-0">
                             <LayoutPanelLeft className="w-4 h-4 text-teal-500" />
                           </div>
                           <div className="text-xs leading-relaxed text-neutral-400">
                              <span className="font-bold text-neutral-200 block mb-1">Testing</span>
                              It tries millions of unexpected actions to see if any cause errors.
                           </div>
                        </div>
                         <div className="flex gap-4">
                           <div className="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0">
                             <Zap className="w-4 h-4 text-red-500" />
                           </div>
                           <div className="text-xs leading-relaxed text-neutral-400">
                              <span className="font-bold text-neutral-200 block mb-1">Alerting</span>
                              Real issues are flagged immediately with clear fixes.
                           </div>
                        </div>
                    </div>
                  </div>

                  <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-6 flex flex-col items-center text-center space-y-2">
                     <AlertTriangle className="w-8 h-8 text-amber-500 mb-2" />
                     <h4 className="text-sm font-bold text-amber-200 uppercase tracking-tighter">Safety Warning</h4>
                     <p className="text-[10px] text-amber-500/80 uppercase tracking-widest font-black leading-relaxed">
                        Avoid running audits on production environments without backups.
                     </p>
                  </div>
               </aside>
            </div>
          </section>
        )}
      </div>

      {/* Side Components */}
      <SourceHub 
        isOpen={showSourceHub} 
        onClose={() => setShowSourceHub(false)} 
        target={target}
        onImport={handleImport}
      />

      {/* History Sidebar */}
      {historyOpen && (
        <div className="fixed inset-0 z-[100] flex justify-end bg-black/80 backdrop-blur-sm animate-in fade-in duration-300">
          <div className="h-full w-full max-w-md border-l border-neutral-800 bg-neutral-950 p-8 shadow-2xl flex flex-col animate-in slide-in-from-right duration-300">
            <div className="flex items-center justify-between mb-10">
              <h2 className="text-2xl font-black text-white uppercase tracking-tighter">Mission Archive</h2>
              <button onClick={() => setHistoryOpen(false)} className="p-2 hover:bg-neutral-800 rounded-lg transition-colors">
                 <X className="w-6 h-6 text-neutral-500 hover:text-white" />
              </button>
            </div>
            
            <div className="flex-1 overflow-y-auto space-y-4">
              {isLoadingHistory ? (
                <div className="flex flex-col gap-4 animate-pulse">
                  {[1, 2, 3].map((i) => (
                    <div key={i} className="h-24 bg-neutral-900/50 rounded-xl border border-neutral-800" />
                  ))}
                </div>
              ) : pastScans.length === 0 ? (
                <div className="text-center py-20 text-neutral-600 italic text-sm">No missions archived yet.</div>
              ) : (
                pastScans.map((scan) => (
                  <div 
                    key={scan.id} 
                    onClick={() => handleViewScan(scan.id)}
                    className="group rounded-xl border border-neutral-800 bg-neutral-900/40 p-4 hover:border-emerald-500/50 transition-all cursor-pointer"
                  >
                    <div className="font-mono text-[10px] text-neutral-600 uppercase mb-2">{new Date(scan.timestamp).toLocaleString()}</div>
                    <div className="font-bold text-white truncate mb-1">{scan.target}</div>
                    <div className="text-xs text-emerald-500 font-bold uppercase tracking-widest">{scan.finding_count} Security Alerts Found</div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Selected Scan View Overlay */}
      {selectedScan && (
        <div className="fixed inset-0 z-[60] bg-black/90 backdrop-blur-md flex items-center justify-center p-4 md:p-8 animate-in fade-in duration-300">
          <div className="w-full max-w-5xl h-[90vh] bg-neutral-950 border border-neutral-800 rounded-3xl overflow-hidden flex flex-col shadow-2xl">
            <div className="p-6 border-b border-neutral-800 flex items-center justify-between bg-neutral-900/30">
              <div>
                <h2 className="text-xl font-black text-white uppercase tracking-tighter">Mission Debrief</h2>
                <p className="text-[10px] text-neutral-500 uppercase tracking-widest font-bold">Project: {selectedScan.target}</p>
              </div>
              <button 
                onClick={() => setSelectedScan(null)}
                className="p-2 hover:bg-neutral-800 rounded-lg transition-colors"
              >
                <X className="w-6 h-6 text-neutral-400" />
              </button>
            </div>
            <div className="flex-1 overflow-hidden p-6">
              <MissionConsole 
                target={selectedScan.target} 
                onClose={() => setSelectedScan(null)} 
                llmConfig={llmConfig}
                readOnlyData={selectedScan}
              />
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
