"use client";

import { useEffect, useRef, useState, useCallback } from "react";

const AUTOPILOT_WS = "ws://localhost:8000/api/autopilot/ws";

type MissionEvent = {
  id: string;
  type: "thought" | "action" | "finding" | "system" | "blackboard_note" | "hitl_request";
  message: string;
  payload?: any;
  timestamp: string;
};

type MissionConsoleProps = {
  target: string;
  sessionCookie?: string;
  onClose?: () => void;
  llmConfig?: import("./ModelSettings").LLMConfig;
  autoStart?: boolean;
};

export function MissionConsole({ target, sessionCookie, onClose, llmConfig, autoStart }: MissionConsoleProps) {
  const [events, setEvents] = useState<MissionEvent[]>([]);
  const [blackboardNotes, setBlackboardNotes] = useState<string[]>([]);
  const [hitlRequest, setHitlRequest] = useState<{ id: string, question: string } | null>(null);
  const [hitlAnswer, setHitlAnswer] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [missionGoal] = useState("Find and verify high-severity vulnerabilities.");
  const [error, setError] = useState<string | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const ws = useRef<WebSocket | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);
  const isAtBottomRef = useRef(true);
  const hasAutoStarted = useRef(false); // guard against StrictMode double-mount

  // Cleanup WebSocket on unmount
  useEffect(() => {
    return () => {
      ws.current?.close();
    };
  }, []);

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

  const startMission = useCallback(() => {
    if (isRunning) return;
    
    // Only close if already open — don't close a still-connecting socket
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.close();
    }
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
      } else if (data.type === "blackboard_note") {
        const note = data.message.replace("[System] Blackboard updated: ", "").replace(/['"]/g, "");
        setBlackboardNotes((prev) => [...prev, note]);
        addEvent("blackboard_note", data.message);
      } else if (data.type === "hitl_request") {
        setHitlRequest({ id: crypto.randomUUID(), question: data.question });
        addEvent("hitl_request", `Human Intercept Requested: ${data.question}`);
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
  }, [target, missionGoal, sessionCookie, llmConfig]);

  // Auto-start when launched from parent — guard against StrictMode double-mount
  useEffect(() => {
    if (autoStart && target && !hasAutoStarted.current) {
      hasAutoStarted.current = true;
      // Small delay to let StrictMode finish its remount cycle before connecting
      const timer = setTimeout(() => startMission(), 150);
      return () => clearTimeout(timer);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart]);

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
            <h2 className="text-lg font-black tracking-tighter text-emerald-400 uppercase">Security Consultant</h2>
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

      <div
          ref={feedRef}
          onScroll={handleScroll}
          className="flex-1 overflow-y-auto p-6 space-y-6"
        >
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
                  <div className="text-[10px] font-bold uppercase tracking-widest text-emerald-500/60">Consultant Note</div>
                  <p className="text-sm text-neutral-200 leading-relaxed italic">{ev.message}</p>
                </div>
              </div>
            ) : ev.type === "action" ? (
              <div className="flex gap-4">
                <div className="w-1 bg-teal-500/30 rounded-full" />
                <div className="flex-1 space-y-1">
                  <div className="text-[10px] font-bold uppercase tracking-widest text-teal-500/60">Activity</div>
                  <div className="flex items-center gap-3">
                    <span className="text-sm text-teal-400 font-bold">{ev.message}</span>
                  </div>
                </div>
              </div>
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
                              Proof of Concept (PoC)
                            </div>
                            <div className="group/code relative">
                              <pre className="bg-neutral-950/90 p-4 rounded-xl text-[11px] font-mono text-emerald-400 overflow-x-auto border border-emerald-500/20 max-h-[150px] scrollbar-thin scrollbar-thumb-white/10">
                                {ev.payload.manual_poc}
                              </pre>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  navigator.clipboard.writeText(ev.payload.manual_poc);
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
            ) : (
              <div className="flex items-center gap-3 text-neutral-500">
                <div className="h-[1px] flex-1 bg-neutral-800" />
                <span className="text-[10px] uppercase font-bold tracking-widest whitespace-nowrap">{ev.message}</span>
                <div className="h-[1px] flex-1 bg-neutral-800" />
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
        <div className="w-[300px] hidden md:flex flex-col h-full bg-neutral-900/40 backdrop-blur-md border border-neutral-800 rounded-2xl overflow-hidden shadow-xl animate-in fade-in slide-in-from-right-4 duration-500">
          <div className="px-5 py-4 border-b border-neutral-800 bg-neutral-900/60 flex items-center gap-2">
            <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            <h3 className="text-xs font-black uppercase tracking-widest text-neutral-300">Strategic Blackboard</h3>
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-3 scrollbar-thin scrollbar-thumb-white/10">
            {blackboardNotes.map((note, idx) => (
              <div key={idx} className="bg-white/5 border border-white/5 rounded-xl p-3 text-sm text-neutral-300 shadow-inner">
                {note}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
