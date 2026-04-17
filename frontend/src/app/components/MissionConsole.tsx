"use client";

import { useEffect, useRef, useState } from "react";

const AUTOPILOT_WS = "ws://localhost:8000/api/autopilot/ws";

type MissionEvent = {
  id: string;
  type: "thought" | "action" | "finding" | "system";
  message: string;
  payload?: any;
  timestamp: string;
};

type MissionConsoleProps = {
  target: string;
  sessionCookie?: string;
  onClose?: () => void;
  llmConfig?: import("./ModelSettings").LLMConfig;
};

export function MissionConsole({ target, sessionCookie, onClose, llmConfig }: MissionConsoleProps) {
  const [events, setEvents] = useState<MissionEvent[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [missionGoal, setMissionGoal] = useState("Find and verify high-severity vulnerabilities.");
  const [error, setError] = useState<string | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events]);

  const addEvent = (type: MissionEvent["type"], message: string, payload?: any) => {
    setEvents((prev) => [
      ...prev,
      {
        id: crypto.randomUUID(),
        type,
        message,
        payload,
        timestamp: new Date().toLocaleTimeString([], { hour12: false }),
      },
    ]);
  };

  const startMission = () => {
    if (isRunning) return;
    
    ws.current?.close();
    setEvents([]);
    setError(null);
    setIsRunning(true);

    const socket = new WebSocket(AUTOPILOT_WS);
    ws.current = socket;

    socket.onopen = () => {
      addEvent("system", `🚀 Mission Autopilot engaged for target: ${target}`);
      socket.send(JSON.stringify({ 
        type: "START_MISSION", 
        target, 
        goal: missionGoal, 
        session_cookie: sessionCookie,
        llm_config: llmConfig
      }));
    };

    socket.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.type === "thought") {
        addEvent("thought", data.message);
      } else if (data.type === "action") {
        addEvent("action", `Executing ${data.tool}...`, data.params);
      } else if (data.type === "finding") {
        addEvent("finding", `Vulnerability Discovered: ${data.data.vulnerability_type}`, data.data);
      } else if (data.type === "mission_complete") {
        addEvent("system", "🏁 Mission objective completed.");
        setIsRunning(false);
      } else if (data.type === "autopilot_error") {
        setError(data.error);
        setIsRunning(false);
      }
    };

    socket.onerror = () => {
      setError("WebSocket connection failed.");
      setIsRunning(false);
    };
    socket.onclose = () => setIsRunning(false);
  };

  return (
    <div className="flex flex-col h-full bg-neutral-900/50 backdrop-blur-xl border border-neutral-800 rounded-2xl overflow-hidden shadow-2xl">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-neutral-800 bg-neutral-900/80">
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${isRunning ? "bg-emerald-500 animate-pulse" : "bg-neutral-600"}`} />
          <h2 className="text-lg font-black tracking-tighter text-emerald-400 uppercase">Mission Autopilot</h2>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-[10px] font-bold uppercase tracking-widest text-neutral-500">
            Target: <span className="text-neutral-300 font-mono">{target}</span>
          </span>
          {onClose && (
            <button onClick={onClose} className="text-neutral-500 hover:text-white transition-colors">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>
      </div>

      {/* Mission Feed */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {events.length === 0 && !isRunning && (
          <div className="flex flex-col items-center justify-center h-full text-center space-y-4">
            <div className="w-16 h-16 rounded-full bg-emerald-500/10 flex items-center justify-center">
              <svg className="w-8 h-8 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <div className="space-y-1">
              <h3 className="text-xl font-bold text-emerald-400">Autopilot Offline</h3>
              <p className="text-sm text-neutral-500 max-w-xs">Enter your mission objective and engage the autopilot to begin autonomous analysis.</p>
            </div>
          </div>
        )}

        {events.map((ev) => (
          <div key={ev.id} className="group animate-in fade-in slide-in-from-bottom-2 duration-300">
            {ev.type === "thought" ? (
              <div className="flex gap-4">
                <div className="w-1 bg-emerald-500/30 rounded-full" />
                <div className="flex-1 space-y-1">
                  <div className="text-[10px] font-bold uppercase tracking-widest text-emerald-500/60">Reasoning</div>
                  <p className="text-sm text-neutral-200 leading-relaxed italic">{ev.message}</p>
                </div>
              </div>
            ) : ev.type === "action" ? (
              <div className="flex gap-4">
                <div className="w-1 bg-teal-500/30 rounded-full" />
                <div className="flex-1 space-y-1">
                  <div className="text-[10px] font-bold uppercase tracking-widest text-teal-500/60">Execution</div>
                  <div className="flex items-center gap-3">
                    <span className="text-sm text-teal-400 font-bold">{ev.message}</span>
                    {ev.payload && (
                      <span className="text-[10px] font-mono bg-neutral-800 text-neutral-400 px-1.5 py-0.5 rounded border border-neutral-700">
                        {JSON.stringify(ev.payload)}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ) : ev.type === "finding" ? (
              <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/30 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                    <span className="text-xs font-black uppercase tracking-widest text-red-500">Critical Finding Verified</span>
                  </div>
                  <span className="text-[10px] text-neutral-500">{ev.timestamp}</span>
                </div>
                <div>
                  <h4 className="text-lg font-bold text-white">{ev.payload?.vulnerability_type}</h4>
                  <p className="text-sm text-neutral-300 mt-1">{ev.payload?.explanation}</p>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-3 text-neutral-500">
                <div className="h-[1px] flex-1 bg-neutral-800" />
                <span className="text-[10px] uppercase font-bold tracking-widest whitespace-nowrap">{ev.message}</span>
                <div className="h-[1px] flex-1 bg-neutral-800" />
              </div>
            )}
          </div>
        ))}
        <div ref={scrollRef} />
      </div>

      {/* Control Panel */}
      <div className="p-6 border-t border-neutral-800 bg-neutral-900/60 transition-all duration-300">
        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400">
            <strong>Engine Error:</strong> {error}
          </div>
        )}
        
        <div className="flex flex-col gap-4">
          <div className="relative">
            <input
              value={missionGoal}
              onChange={(e) => setMissionGoal(e.target.value)}
              disabled={isRunning}
              placeholder="Define mission objective (e.g. Find SQLi in /api)..."
              className="w-full bg-neutral-950/50 border border-neutral-800 rounded-xl px-4 py-4 text-sm focus:outline-none focus:border-emerald-500/50 transition-colors disabled:opacity-50"
            />
            <div className="absolute right-4 top-1/2 -translate-y-1/2 text-[10px] font-bold uppercase tracking-widest text-neutral-500">
              {isRunning ? "Mission Active" : "Mission Goal"}
            </div>
          </div>
          
          <button
            onClick={startMission}
            disabled={isRunning || !target}
            className={`w-full py-4 rounded-xl font-black uppercase tracking-widest text-sm transition-all shadow-lg ${
              isRunning 
                ? "bg-neutral-800 text-neutral-500 cursor-not-allowed" 
                : "bg-gradient-to-r from-emerald-600 to-teal-600 text-white hover:scale-[1.01] active:scale-[0.99] hover:shadow-emerald-500/20"
            }`}
          >
            {isRunning ? (
              <div className="flex items-center justify-center gap-3">
                <svg className="animate-spin h-4 w-4 text-emerald-500" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                <span>Mission in Progress</span>
              </div>
            ) : "Engage Mission Autopilot"}
          </button>
        </div>
      </div>
    </div>
  );
}
