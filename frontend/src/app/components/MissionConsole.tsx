"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { Zap, X, Shield, Activity } from "lucide-react";
import type { LLMConfig } from "./ModelSettings";

const getWsUrl = (mode: "autopilot" | "standard" = "autopilot") => {
  if (typeof window === "undefined") return `ws://localhost:8000/api/${mode}/ws`;
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.hostname === "localhost" ? "localhost:8000" : window.location.host;
  return `${protocol}//${host}/api/${mode}/ws`;
};

const AUTOPILOT_WS = getWsUrl("autopilot");
const SCAN_WS = getWsUrl("standard");

type MissionPayload = {
  severity?: string;
  vulnerability_type?: string;
  explanation?: string;
  impact?: string;
  exploit_scenario?: string;
  manual_poc?: string;
  remediation_steps?: string;
  [key: string]: unknown;
};

type MissionEvent = {
  id: string;
  type: "thought" | "action" | "finding" | "system" | "blackboard_note" | "hitl_request";
  message: string;
  payload?: MissionPayload;
  timestamp: string;
};

type MissionConsoleProps = {
  target: string;
  sessionCookie?: string;
  onClose?: () => void;
  llmConfig?: LLMConfig;
  autoStart?: boolean;
  readOnlyData?: any;
  mode?: "autopilot" | "standard";
};

export function MissionConsole({ 
  target, 
  sessionCookie, 
  onClose, 
  llmConfig, 
  autoStart, 
  readOnlyData, 
  mode = "autopilot" 
}: MissionConsoleProps) {
  const [events, setEvents] = useState<MissionEvent[]>([]);
  const [lastAction, setLastAction] = useState<string>(readOnlyData ? "Mission Debrief" : "Initializing...");
  const [blackboardNotes, setBlackboardNotes] = useState<string[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hitlRequest, setHitlRequest] = useState<{ id: string; question: string } | null>(null);
  const [hitlAnswer, setHitlAnswer] = useState("");
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [missionGoal] = useState("Full vulnerability assessment");

  const ws = useRef<WebSocket | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);
  const isAtBottomRef = useRef(true);

  // Cleanup WebSocket on unmount
  // Handle readOnlyData or autoStart
  useEffect(() => {
    if (readOnlyData) {
      // Map logs and findings to events
      const historicEvents: MissionEvent[] = [];
      
      (readOnlyData.logs || []).forEach((log: any, idx: number) => {
        historicEvents.push({
          id: `log-${idx}`,
          type: log.stage === "autopilot" ? "thought" : (log.stage === "error" ? "thought" : "system"),
          message: log.message,
          timestamp: ""
        });
        
        if (log.message.startsWith("[System] Blackboard updated:")) {
           const note = log.message.replace("[System] Blackboard updated: ", "").replace(/['"]/g, "");
           setBlackboardNotes(prev => prev.includes(note) ? prev : [...prev, note]);
        }
      });
      
      (readOnlyData.findings || []).forEach((f: any, idx: number) => {
        historicEvents.push({
          id: `finding-${idx}`,
          type: "finding",
          message: f.vulnerability_type || "Finding",
          payload: f,
          timestamp: ""
        });
      });
      
      setEvents(historicEvents);
      setIsRunning(false);
    } else if (target && (autoStart || events.length === 0)) {
       startMission();
    }
  }, [target, readOnlyData]);

  // Smart scroll: only snap to bottom if user was already at bottom
  const scrollToBottom = useCallback(() => {
    const el = feedRef.current;
    if (!el) return;
    if (isAtBottomRef.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, []);

  const handleScroll = useCallback(() => {
    const el = feedRef.current;
    if (!el) return;
    isAtBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [events, scrollToBottom]);

  const addEvent = (type: MissionEvent["type"], message: string, payload?: MissionPayload) => {
    setEvents((prev) => [
      ...prev,
      {
        id: Math.random().toString(36).substring(2, 11),
        type,
        message,
        payload,
        timestamp: new Date().toLocaleTimeString([], { hour12: false }),
      },
    ]);
  };

  const startMission = useCallback(() => {
    if (!target) return;
    setIsRunning(true);
    setEvents([]);
    setBlackboardNotes([]);
    setError(null);
    setLastAction("Connecting to engine...");

    const socketUrl = mode === "autopilot" ? AUTOPILOT_WS : SCAN_WS;
    const socket = new WebSocket(socketUrl);
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
        setLastAction(data.message.length > 60 ? data.message.substring(0, 57) + "..." : data.message);
      } else if (data.type === "action") {
        addEvent("action", `Executing ${data.tool}...`, data.params);
        setLastAction(`Tool Call: ${data.tool}`);
      } else if (data.type === "finding") {
        addEvent("finding", `Vulnerability Discovered: ${data.data.vulnerability_type}`, data.data);
        setLastAction("Critical finding identified!");
      } else if (data.type === "blackboard_note") {
        const note = data.message.replace("[System] Blackboard updated: ", "").replace(/['"]/g, "");
        setBlackboardNotes((prev) => {
          // Avoid duplicate notes
          if (prev.includes(note)) return prev;
          return [...prev, note];
        });
        addEvent("blackboard_note", data.message);
      } else if (data.type === "hitl_request") {
        setHitlRequest({ id: Math.random().toString(36).substring(2, 11), question: data.question || "The agent needs your input to continue." });
        addEvent("hitl_request", `Human Intercept Requested: ${data.question}`);
        setLastAction("Waiting for user input...");
      } else if (data.type === "mission_complete") {
        addEvent("system", `🏁 Mission complete. Total findings: ${data.finding_count || 0}. Saved to archive.`);
        setIsRunning(false);
        setLastAction("Mission Complete.");
        // Refresh history if callback provided
        if (typeof window !== "undefined") {
          window.dispatchEvent(new CustomEvent("scan_completed"));
        }
      } else if (data.type === "autopilot_error") {
        setError(data.error);
        setIsRunning(false);
        setLastAction("Error encountered.");
        addEvent("system", `🚨 Error: ${data.error}`);
      }
    };

    socket.onerror = () => {
      setError("WebSocket connection failed.");
      setIsRunning(false);
    };
    socket.onclose = () => setIsRunning(false);
  }, [target, mode, llmConfig, sessionCookie, missionGoal, addEvent]);

  // Auto-start when launched from parent
  useEffect(() => {
    let active = true;
    if (autoStart && target) {
      // Small delay to let StrictMode finish its remount cycle before connecting
      const timer = setTimeout(() => {
        if (active) startMission();
      }, 150);
      return () => {
        active = false;
        clearTimeout(timer);
      };
    }
  }, [autoStart, target, startMission]);

  const toggleFinding = (id: string) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const submitHitlAnswer = () => {
    if (!ws.current || !hitlRequest || !hitlAnswer.trim()) return;
    ws.current.send(JSON.stringify({ type: "HITL_RESPONSE", answer: hitlAnswer }));
    addEvent("system", `Human Responded: ${hitlAnswer}`);
    setHitlRequest(null);
    setHitlAnswer("");
  };


  return (
    <div className="flex h-full gap-4">
      {/* Main Console */}
      <div className="flex-1 flex flex-col h-full bg-neutral-900/50 backdrop-blur-xl border border-neutral-800 rounded-2xl overflow-hidden shadow-2xl relative">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-neutral-800 bg-neutral-900/80">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full ${isRunning ? "bg-emerald-500 animate-pulse" : "bg-neutral-600"}`} />
            <Shield className="w-5 h-5 text-emerald-400" />
            <h2 className="text-lg font-black tracking-tighter text-emerald-400 uppercase">Security Consultant</h2>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-[10px] font-bold uppercase tracking-widest text-neutral-500">
              Target: <span className="text-neutral-300 font-mono">{target}</span>
            </span>
            {onClose && (
              <button onClick={onClose} className="text-neutral-500 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            )}
          </div>
        </div>

        {/* HITL Overlay */}
        {hitlRequest && (
          <div className="absolute inset-0 z-50 bg-neutral-950/80 backdrop-blur-md flex flex-col items-center justify-center p-6">
            <div className="w-full max-w-lg bg-orange-500/10 border border-orange-500/50 rounded-2xl p-6 shadow-2xl shadow-orange-500/20 animate-in zoom-in-95 duration-300">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-full bg-orange-500/20 flex items-center justify-center animate-pulse">
                  <svg className="w-5 h-5 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-lg font-black text-white tracking-tight uppercase">Human Assistance Required</h3>
                  <p className="text-xs text-orange-400/80 uppercase font-bold tracking-widest">Agent is blocked</p>
                </div>
              </div>
              <div className="bg-neutral-950/50 rounded-xl p-4 border border-orange-500/20 text-neutral-300 mb-6 font-mono text-sm">
                {hitlRequest.question}
              </div>
              <div className="space-y-4">
                <input
                  type="text"
                  value={hitlAnswer}
                  onChange={(e) => setHitlAnswer(e.target.value)}
                  placeholder="Provide guidance to unblock..."
                  className="w-full bg-neutral-900 border border-neutral-700 rounded-xl px-4 py-3 text-sm text-white placeholder-neutral-500 focus:outline-none focus:border-orange-500 transition-colors"
                  onKeyDown={(e) => e.key === 'Enter' && submitHitlAnswer()}
                  autoFocus
                />
                <button
                  onClick={submitHitlAnswer}
                  disabled={!hitlAnswer.trim()}
                  className="w-full py-3 rounded-xl bg-gradient-to-r from-orange-500 to-red-500 text-white font-black uppercase tracking-widest text-sm hover:scale-[1.02] active:scale-[0.98] transition-all disabled:opacity-50 disabled:grayscale"
                >
                  Submit Guidance
                </button>
              </div>
            </div>
          </div>
        )}
        {/* Status HUD Overlay */}
        {isRunning && (
          <div className="px-6 py-3 bg-neutral-950/40 border-b border-neutral-800 backdrop-blur-md flex items-center justify-between sticky top-0 z-20">
            <div className="flex items-center gap-4 flex-1">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.6)]" />
                <span className="text-[10px] font-black uppercase tracking-[0.2em] text-emerald-500">Live Mission</span>
              </div>
              <div className="h-4 w-px bg-neutral-800" />
              <div className="flex-1 overflow-hidden">
                <p className="text-[10px] font-bold text-neutral-400 uppercase tracking-widest truncate animate-in slide-in-from-left-2 duration-500">
                  <span className="text-neutral-600 mr-2">Current Activity:</span>
                  {lastAction}
                </p>
                <div className="h-1 w-32 bg-neutral-800 rounded-full mt-1 overflow-hidden">
                  <div 
                    className="h-full bg-emerald-500 transition-all duration-1000 ease-in-out" 
                    style={{ width: `${Math.min(10 + (events.length * 2), 95)}%` }}
                  />
                </div>
              </div>
            </div>
            <div className="flex items-center gap-6 ml-4">
              <div className="flex flex-col items-end">
                <span className="text-[8px] font-black uppercase tracking-widest text-neutral-600">Findings Found</span>
                <span className="text-xs font-black text-emerald-400">{events.filter(e => e.type === "finding").length}</span>
              </div>
              <div className="flex flex-col items-end">
                <span className="text-[8px] font-black uppercase tracking-widest text-neutral-600">Audit Phase</span>
                <span className="text-xs font-black text-white uppercase tracking-tighter">
                   {events.filter(e => e.type === "finding").length > 0 ? "Verifying" : "Scanning"}
                </span>
              </div>
            </div>
          </div>
        )}

      <div
          ref={feedRef}
          onScroll={handleScroll}
          className="flex-1 overflow-y-auto p-6 space-y-6"
        >
        {/* Empty State / Offline */}
        {events.length === 0 && !isRunning && !error && (
          <div className="flex flex-col items-center justify-center h-full text-center space-y-4">
            <div className="w-16 h-16 rounded-full bg-emerald-500/10 flex items-center justify-center">
              <Activity className="w-8 h-8 text-emerald-500" />
            </div>
            <div className="space-y-1">
              <h3 className="text-xl font-bold text-emerald-400">Autopilot Offline</h3>
              <p className="text-sm text-neutral-500 max-w-xs">Enter your mission objective and engage the autopilot to begin autonomous analysis.</p>
              <button 
                onClick={startMission}
                className="mt-4 px-6 py-2 rounded-lg bg-emerald-500 text-neutral-950 text-xs font-black uppercase tracking-widest hover:scale-105 transition-all"
              >
                Engage Autopilot
              </button>
            </div>
          </div>
        )}

        {/* Loading / Thinking State */}
        {isRunning && events.filter(ev => ["finding", "system", "hitl_request"].includes(ev.type)).length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center space-y-4 animate-pulse">
            <div className="w-12 h-12 rounded-full border-2 border-emerald-500/20 border-t-emerald-500 animate-spin" />
            <p className="text-xs font-bold text-emerald-500/60 uppercase tracking-[0.3em]">Strategizing...</p>
          </div>
        )}

        {/* Event List */}
        {events
          .filter(ev => ["finding", "system", "hitl_request", "thought", "action", "blackboard_note"].includes(ev.type))
          .map((ev) => (
            <div key={ev.id} className="group animate-in fade-in slide-in-from-bottom-2 duration-300">
            {ev.type === "system" ? (
              ev.message.startsWith("🚀") || ev.message.startsWith("🏁") || ev.message.startsWith("🚨") ? (
                <div className="flex items-center gap-3 py-2">
                  <div className="h-px flex-1 bg-neutral-800" />
                  <span className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest px-3">{ev.message}</span>
                  <div className="h-px flex-1 bg-neutral-800" />
                </div>
              ) : (
                <div className="flex text-neutral-400 bg-neutral-900/30 p-3 rounded-lg border border-white/5 italic">
                  <span className="text-[10px] font-mono tracking-tight break-words whitespace-pre-wrap opacity-60">{ev.message}</span>
                </div>
              )
            ) : ev.type === "finding" ? (
              <div
                className={`group/card bg-gradient-to-br border rounded-2xl p-4 transition-all duration-500 overflow-hidden ${
                  ev.payload?.severity === "Critical"
                    ? "from-red-500/20 to-red-600/5 border-red-500/40 shadow-lg shadow-red-500/10"
                    : ev.payload?.severity === "High"
                    ? "from-orange-500/15 to-orange-600/5 border-orange-500/30 shadow-md shadow-orange-500/5"
                    : ev.payload?.severity === "Medium"
                    ? "from-yellow-500/10 to-yellow-600/5 border-yellow-500/20"
                    : "from-blue-500/10 to-blue-600/5 border-blue-500/20"
                }`}
              >
                {/* Finding Header */}
                <div
                  className="flex items-center justify-between cursor-pointer select-none"
                  onClick={() => toggleFinding(ev.id)}
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={`px-3 py-1 rounded-lg text-[9px] font-black uppercase tracking-widest shadow-inner ${
                        ev.payload?.severity === "Critical"
                          ? "bg-red-500 text-white"
                          : ev.payload?.severity === "High"
                          ? "bg-orange-500 text-white"
                          : ev.payload?.severity === "Medium"
                          ? "bg-yellow-500 text-neutral-900"
                          : "bg-blue-500 text-white"
                      }`}
                    >
                      {ev.payload?.severity || "Warning"}
                    </div>
                    <h4 className="text-base font-bold text-white tracking-tight group-hover/card:text-red-400 transition-colors">
                      {ev.payload?.vulnerability_type}
                    </h4>
                    {ev.payload?.manual_poc && (
                      <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-teal-500/20 border border-teal-500/30 text-[9px] font-black text-teal-400 uppercase tracking-tighter animate-pulse">
                        <Zap className="w-2.5 h-2.5 fill-teal-400" />
                        PoC Verified
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-neutral-500 font-mono tracking-tighter opacity-70">
                      {ev.timestamp}
                    </span>
                    <div
                      className={`p-1 rounded-full bg-white/5 border border-white/5 transition-transform duration-500 ${
                        expandedFindings.has(ev.id) ? "rotate-180" : ""
                      }`}
                    >
                      <svg className="w-4 h-4 text-neutral-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M19 9l-7 7-7-7" />
                      </svg>
                    </div>
                  </div>
                </div>

                {/* Impact Preview */}
                {!expandedFindings.has(ev.id) && (
                  <div className="mt-3 text-sm text-neutral-400 line-clamp-2 animate-in fade-in duration-500 pl-1 border-l-2 border-white/5 ml-1">
                    {ev.payload?.explanation}
                  </div>
                )}

                {/* Expanded Details */}
                {expandedFindings.has(ev.id) && (
                  <div className="mt-5 space-y-5 animate-in fade-in slide-in-from-top-4 duration-700">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Left Column: Description & Impact */}
                      <div className="space-y-4">
                        <div className="space-y-1.5">
                          <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-neutral-500">
                            <div className="w-1.5 h-1.5 rounded-full bg-white/20" />
                            Discovery Detail
                          </div>
                          <p className="text-sm text-neutral-200 leading-relaxed bg-white/5 p-3 rounded-xl border border-white/5">
                            {ev.payload?.explanation}
                          </p>
                        </div>
                        {ev.payload?.impact && (
                          <div className="space-y-1.5">
                            <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-red-400/80">
                              <div className="w-1.5 h-1.5 rounded-full bg-red-400/50" />
                              Critical Impact
                            </div>
                            <p className="text-sm text-neutral-300 leading-relaxed italic bg-red-500/5 p-3 rounded-xl border border-red-500/10">
                              {ev.payload.impact}
                            </p>
                          </div>
                        )}
                      </div>

                      {/* Right Column: Exploit & PoC */}
                      <div className="space-y-4">
                        {ev.payload?.exploit_scenario && (
                          <div className="space-y-1.5">
                            <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-orange-400/80">
                              <div className="w-1.5 h-1.5 rounded-full bg-orange-400/50" />
                              Attack Scenario
                            </div>
                            <p className="text-xs text-neutral-400 leading-relaxed bg-white/5 p-3 rounded-xl border border-white/5">
                              {ev.payload.exploit_scenario}
                            </p>
                          </div>
                        )}
                        {ev.payload?.manual_poc && (
                          <div className="space-y-1.5">
                            <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-teal-400/80">
                              <div className="w-1.5 h-1.5 rounded-full bg-teal-400/50" />
                              Proof of Exploitation (PoC)
                            </div>
                            <div className="group/code relative">
                              <pre className="bg-neutral-950/90 p-4 rounded-xl text-[11px] font-mono text-emerald-400 overflow-x-auto border border-emerald-500/20 max-h-[150px] scrollbar-thin scrollbar-thumb-white/10">
                                {ev.payload.manual_poc}
                              </pre>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  if (ev.payload?.manual_poc) {
                                    navigator.clipboard.writeText(ev.payload.manual_poc);
                                  }
                                }}
                                className="absolute top-2 right-2 p-1.5 rounded-lg bg-white/10 opacity-0 group-hover/code:opacity-100 transition-opacity hover:bg-emerald-500/20 text-emerald-400"
                                title="Copy PoC"
                              >
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                    strokeWidth={2}
                                    d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"
                                  />
                                </svg>
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Footer Actions: Remediation */}
                    {ev.payload?.remediation_steps && (
                      <div className="pt-4 border-t border-white/5 space-y-2">
                        <div className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-widest text-blue-400/80">
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={3}
                              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.040L3 6.247a13.438 13.438 0 001.259 20.835 11.954 11.954 0 0017.482 0A13.438 13.438 0 0021 6.247l-.382-.719z"
                            />
                          </svg>
                          Remediation Advice
                        </div>
                        <p className="text-sm text-neutral-300 bg-blue-500/5 p-4 rounded-xl border border-blue-500/20 border-dashed">
                          {ev.payload.remediation_steps}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : ev.type === "hitl_request" ? (
              <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 space-y-3">
                <div className="flex items-center gap-2 text-amber-400">
                  <Shield className="w-4 h-4" />
                  <span className="text-[10px] font-black uppercase tracking-widest">Human Intercept Required</span>
                </div>
                <p className="text-sm text-neutral-200">{ev.message}</p>
                <div className="flex gap-2">
                  <input 
                    type="text"
                    value={hitlAnswer}
                    onChange={(e) => setHitlAnswer(e.target.value)}
                    placeholder="Provide information..."
                    className="flex-1 h-9 bg-black/40 border border-white/10 rounded-lg px-3 text-xs text-white focus:outline-none focus:border-amber-500/50"
                  />
                  <button 
                    onClick={() => {
                      if (ws.current) {
                        ws.current.send(JSON.stringify({ type: "HITL_RESPONSE", answer: hitlAnswer }));
                        setEvents(prev => prev.map(e => e.type === "hitl_request" && e.message === ev.message ? { ...e, type: "system", message: `RESOLVED: ${ev.message}\nAnswer: ${hitlAnswer}` } : e));
                        setHitlAnswer("");
                        setHitlRequest(null);
                      }
                    }}
                    className="px-4 h-9 bg-amber-500 text-neutral-950 text-[10px] font-black uppercase rounded-lg"
                  >
                    Send
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex text-neutral-500 bg-neutral-900/50 p-3 rounded-lg border border-neutral-800/50">
                <span className="text-[11px] font-mono tracking-tight break-words whitespace-pre-wrap">{ev.message}</span>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Control Panel - show only when not running */}
      {!isRunning && (
        <div className="p-4 border-t border-neutral-800 bg-neutral-900/60">
          {error && (
            <div className="mb-3 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400">
              <strong>Engine Error:</strong> {error}
            </div>
          )}
          <button
            onClick={startMission}
            disabled={isRunning || !target}
            className="w-full py-3 rounded-xl font-black uppercase tracking-widest text-sm bg-gradient-to-r from-emerald-600 to-teal-600 text-white hover:scale-[1.01] active:scale-[0.99] transition-all shadow-lg"
          >
            {events.length > 0 ? "Re-run Audit" : "Start Security Audit"}
          </button>
        </div>
      )}
      {isRunning && error && (
        <div className="p-4 border-t border-neutral-800">
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400">
            <strong>Engine Error:</strong> {error}
          </div>
        </div>
      )}
      </div>{/* closes main console flex-col div */}
      
    {/* Strategic Blackboard Panel */}
      {blackboardNotes.length > 0 && (
        <div className="w-[320px] hidden lg:flex flex-col h-full bg-neutral-900/40 backdrop-blur-md border border-neutral-800 rounded-2xl overflow-hidden shadow-xl animate-in fade-in slide-in-from-right-4 duration-500">
          <div className="px-5 py-4 border-b border-neutral-800 bg-neutral-900/60 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
              <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-neutral-300">Strategic Blackboard</h3>
            </div>
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-3 scrollbar-thin scrollbar-thumb-white/10">
            {blackboardNotes.map((note, idx) => (
              <div key={idx} className="group/note bg-neutral-950/40 border border-white/5 rounded-xl p-3 text-xs text-neutral-400 shadow-inner hover:border-emerald-500/20 transition-colors animate-in fade-in slide-in-from-top-1 duration-300">
                <div className="flex gap-2">
                  <span className="text-emerald-500/40 font-mono mt-0.5">»</span>
                  <span className="leading-relaxed group-hover/note:text-neutral-200 transition-colors">{note}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
