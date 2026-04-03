"use client";

import { useState } from "react";

export default function Home() {
  const [targetUrl, setTargetUrl] = useState("");
  const [sessionCookie, setSessionCookie] = useState("");
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<string | null>(null);

  const startScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setScanResult(null);

    try {
      // In MVP, we just simulate the API handoff
      // const res = await fetch("http://localhost:8000/api/scan/start", { ... })
      
      setTimeout(() => {
        setScanResult(`Target locked: ${targetUrl}. Crawler mapping surface...`);
        setLoading(false);
      }, 1500);

    } catch (error) {
      console.error(error);
      setScanResult("Failed to reach orchestrator backend.");
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-neutral-950 text-neutral-200 p-8 flex flex-col items-center justify-center font-sans">
      <div className="max-w-2xl w-full mt-[-10vh]">
        <div className="text-center mb-12">
          <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-br from-emerald-400 to-teal-600 mb-4 tracking-tighter">
            VulnPilot
          </h1>
          <p className="text-neutral-400 text-lg font-light tracking-wide">
            Intelligent Black-Box Analysis & PoC Generation
          </p>
        </div>

        <form onSubmit={startScan} className="bg-neutral-900 border border-neutral-800 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
          {/* Decorative glow */}
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[200%] h-1 bg-gradient-to-r from-transparent via-emerald-500 to-transparent opacity-20"></div>
          
          <div className="space-y-6 relative z-10">
            <div>
              <label className="block text-sm font-semibold mb-2 text-neutral-300 tracking-wide uppercase">Target URL</label>
              <input
                type="url"
                required
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-all font-mono text-sm placeholder:text-neutral-600"
              />
            </div>

            <div>
              <label className="block text-sm font-semibold mb-2 text-neutral-300 tracking-wide uppercase flex items-center justify-between">
                <span>Session Cookie</span>
                <span className="text-neutral-600 font-normal text-xs normal-case bg-neutral-950 px-2 py-0.5 rounded border border-neutral-800">Optional for authenticated routes</span>
              </label>
              <textarea
                placeholder="session_id=123a.456b.789c..."
                value={sessionCookie}
                onChange={(e) => setSessionCookie(e.target.value)}
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-all font-mono text-sm h-24 resize-none placeholder:text-neutral-600"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-emerald-500 hover:bg-emerald-400 text-neutral-950 font-black tracking-widest uppercase text-base py-4 rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center shadow-[0_0_20px_-5px_rgba(16,185,129,0.4)] hover:shadow-[0_0_25px_-5px_rgba(16,185,129,0.6)]"
            >
              {loading ? (
                <span className="animate-pulse">Initializing Engine...</span>
              ) : (
                "Launch Scan"
              )}
            </button>
          </div>
        </form>

        {scanResult && (
          <div className="mt-8 p-6 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-emerald-400 font-mono text-sm animate-in fade-in slide-in-from-bottom-4 shadow-[0_0_20px_-10px_rgba(16,185,129,0.2)]">
            <span className="text-emerald-500 mr-2">{"❯"}</span> {scanResult}
          </div>
        )}
      </div>
    </main>
  );
}
