"use client";

import { useEffect, useRef, useState } from "react";

const ARENA_WS = "ws://localhost:8000/api/arena/ws";

type BattleEvent = {
  id: string;
  event: string;
  agent: "red" | "blue" | "system";
  message: string;
  payload?: Record<string, unknown>;
  timestamp: string;
};

type ArenaResult = {
  status: string;
  vuln_type: string;
  surface: string;
  rounds_fought: number;
  final_patched_code: string;
  is_honey_patch: boolean;
  is_provably_secure: boolean;
};

type Finding = {
  vulnerability_type?: string;
  url?: string;
  file_path?: string;
  url_pattern?: string;
  poc_script?: string;
  remediation_code?: string;
  explanation?: string;
};

type ArenaModalProps = {
  finding: Finding;
  target: string;
  onClose: () => void;
};

export function ArenaModal({ finding, target, onClose }: ArenaModalProps) {
  const [events, setEvents] = useState<BattleEvent[]>([]);
  const [result, setResult] = useState<ArenaResult | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events]);

  const addEvent = (event: string, agent: "red" | "blue" | "system", message: string, payload?: Record<string, unknown>) => {
    setEvents((prev) => [
      ...prev,
      {
        id: crypto.randomUUID(),
        event,
        agent,
        message,
        payload,
        timestamp: new Date().toLocaleTimeString([], { hour12: false }),
      },
    ]);
  };

  const startArena = () => {
    ws.current?.close();
    setEvents([]);
    setResult(null);
    setError(null);
    setIsRunning(true);

    const socket = new WebSocket(ARENA_WS);
    ws.current = socket;

    socket.onopen = () => {
      addEvent("arena_start", "system", `⚔️  Arena started for: ${finding.vulnerability_type}`);
      socket.send(JSON.stringify({ type: "START_ARENA", finding, target }));
    };

    socket.onmessage = (e) => {
      const data = JSON.parse(e.data) as { type: string; event?: string; result?: ArenaResult; error?: string; [key: string]: unknown };

      if (data.type === "arena_event") {
        const ev = data.event || "";

        if (ev === "red_thinking") {
          addEvent(ev, "red", data.message as string ?? "🔴 Red Agent is analyzing...");
        } else if (ev === "red_result") {
          const bypassed = data.bypassed as boolean;
          addEvent(ev, "red", bypassed
            ? `🔴 BYPASS FOUND! Technique: ${data.technique ?? "unknown"} | Payload: ${data.payload ?? "n/a"}`
            : "🔴 Red Agent: No bypass found. Code appears secure.",
            data as Record<string, unknown>
          );
        } else if (ev === "blue_thinking") {
          addEvent(ev, "blue", data.message as string ?? "🔵 Blue Agent is engineering a stronger patch...");
        } else if (ev === "blue_result") {
          addEvent(ev, "blue",
            data.is_honey_patch
              ? `🍯 HONEY-PATCH deployed! Trap returns fake: ${data.fake_data_returned ?? "data"}`
              : `🔵 Blue Agent produced a new patch. Explanation: ${(data.explanation as string ?? "").slice(0, 120)}...`,
            data as Record<string, unknown>
          );
        } else if (ev === "blue_wins") {
          addEvent(ev, "system", `✅ ${data.message ?? "Code is PROVABLY SECURE!"}`);
        } else if (ev === "honey_deployed") {
          addEvent(ev, "system", `🍯 ${data.message ?? "Honey-Patch deployed!"}`);
        } else if (ev === "round_start") {
          addEvent(ev, "system", `─────── Round ${data.round as number} ───────`);
        } else if (ev === "arena_error") {
          setError(data.error as string ?? "Arena error");
          setIsRunning(false);
        }
      } else if (data.type === "arena_complete") {
        setResult(data.result as ArenaResult);
        setIsRunning(false);
      } else if (data.type === "arena_error") {
        setError(data.error as string ?? "Arena error");
        setIsRunning(false);
      }
    };

    socket.onerror = () => {
      setError("WebSocket error. Is the backend running at localhost:8000?");
      setIsRunning(false);
    };
    socket.onclose = () => setIsRunning(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-5xl rounded-2xl border border-neutral-700 bg-neutral-950 shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-neutral-800 p-5">
          <div>
            <h2 className="text-xl font-black text-white flex items-center gap-2">
              <span className="text-red-400">⚔</span>
              <span className="bg-gradient-to-r from-red-400 via-orange-400 to-yellow-400 bg-clip-text text-transparent">
                ADVERSARIAL ARENA
              </span>
            </h2>
            <p className="text-xs text-neutral-500 mt-1">
              🔴 <strong className="text-red-400">Red Agent</strong> (Qwen2.5-Coder) vs{" "}
              🔵 <strong className="text-blue-400">Blue Agent</strong> (Mistral-7B) — Powered by HuggingFace (Free)
            </p>
          </div>
          <button onClick={onClose} className="rounded-lg border border-neutral-700 px-3 py-1 text-xs text-neutral-400 hover:bg-neutral-800">
            Close
          </button>
        </div>

        {/* Target info */}
        <div className="border-b border-neutral-800 px-5 py-3 grid grid-cols-2 gap-4 bg-neutral-900/40 text-xs">
          <div>
            <span className="text-neutral-500 uppercase tracking-widest">Target Vuln:</span>
            <span className="ml-2 font-bold text-orange-400">{finding.vulnerability_type ?? "Unknown"}</span>
          </div>
          <div>
            <span className="text-neutral-500 uppercase tracking-widest">Surface:</span>
            <span className="ml-2 text-neutral-300 font-mono">{finding.url ?? finding.file_path ?? "Unknown"}</span>
          </div>
        </div>

        <div className="flex flex-1 overflow-hidden">
          {/* Battle log */}
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-neutral-500 border-b border-neutral-800">
              Live Battle Feed
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-2 font-mono text-xs">
              {events.length === 0 && !isRunning && (
                <div className="text-neutral-600 text-center mt-8">
                  Press &quot;Launch Arena&quot; to start the AI battle.
                </div>
              )}
              {events.map((ev) => (
                <div
                  key={ev.id}
                  className={`flex gap-2 items-start rounded px-3 py-2 ${
                    ev.agent === "red"
                      ? "bg-red-950/30 border border-red-900/40 text-red-300"
                      : ev.agent === "blue"
                      ? "bg-blue-950/30 border border-blue-900/40 text-blue-300"
                      : "bg-neutral-900 border border-neutral-800 text-neutral-400"
                  }`}
                >
                  <span className="text-[10px] text-neutral-600 shrink-0 mt-0.5">{ev.timestamp}</span>
                  <span>{ev.message}</span>
                </div>
              ))}
              {isRunning && (
                <div className="flex gap-2 items-center text-neutral-500 animate-pulse">
                  <div className="w-2 h-2 rounded-full bg-orange-400 animate-bounce" />
                  <div className="w-2 h-2 rounded-full bg-orange-400 animate-bounce [animation-delay:0.15s]" />
                  <div className="w-2 h-2 rounded-full bg-orange-400 animate-bounce [animation-delay:0.3s]" />
                  <span>AI agents fighting...</span>
                </div>
              )}
              <div ref={logEndRef} />
            </div>

            {/* Result code */}
            {result && result.final_patched_code && (
              <div className="border-t border-neutral-800 p-4 max-h-64 overflow-y-auto">
                <div className="mb-2 flex items-center justify-between text-[10px] font-bold uppercase tracking-widest">
                  <span className={result.is_honey_patch ? "text-yellow-400" : "text-emerald-400"}>
                    {result.is_honey_patch ? "🍯 Honey-Patch Code" : "✅ Provably Secure Code"}
                  </span>
                  <button
                    onClick={() => navigator.clipboard.writeText(result.final_patched_code)}
                    className="rounded border border-neutral-700 px-2 py-1 text-neutral-400 hover:bg-neutral-800"
                  >
                    Copy
                  </button>
                </div>
                <pre className="text-[11px] text-emerald-100 whitespace-pre-wrap overflow-x-auto">
                  {result.final_patched_code}
                </pre>
              </div>
            )}
          </div>

          {/* Right sidebar: Result summary */}
          <div className="w-64 border-l border-neutral-800 flex flex-col">
            <div className="px-4 py-2 text-[10px] font-bold uppercase tracking-widest text-neutral-500 border-b border-neutral-800">
              Arena Status
            </div>
            <div className="flex-1 p-4 space-y-4">
              {!result && !error && (
                <div className="text-xs text-neutral-500">
                  <p>Max Rounds: <strong className="text-white">3</strong></p>
                  <p className="mt-2">🔴 Red Agent tries to bypass fixes</p>
                  <p className="mt-2">🔵 Blue Agent produces harder patches</p>
                  <p className="mt-2">🍯 If all rounds pass, a Honey-Patch trap is deployed</p>
                </div>
              )}

              {result && (
                <div className="space-y-3 text-xs">
                  <div className={`rounded-lg p-3 font-bold text-sm text-center ${
                    result.is_provably_secure
                      ? "bg-emerald-900/40 border border-emerald-500/30 text-emerald-400"
                      : result.is_honey_patch
                      ? "bg-yellow-900/40 border border-yellow-500/30 text-yellow-400"
                      : "bg-neutral-800 text-neutral-400"
                  }`}>
                    {result.is_provably_secure ? "✅ PROVABLY SECURE" : result.is_honey_patch ? "🍯 HONEY-PATCH DEPLOYED" : result.status.toUpperCase()}
                  </div>
                  <p>Rounds fought: <strong className="text-white">{result.rounds_fought}</strong></p>
                  <p>Outcome: <span className="text-orange-400">{result.status}</span></p>
                </div>
              )}

              {error && (
                <div className="rounded border border-red-500/30 bg-red-900/20 p-3 text-xs text-red-400 space-y-2">
                  <p className="font-bold">Arena Error</p>
                  <p>{error}</p>
                  {error.includes("HF_API_KEY") && (
                    <div className="rounded border border-yellow-500/30 bg-yellow-900/20 p-2 text-yellow-300">
                      <p className="font-bold mb-1">Setup (1 minute):</p>
                      <ol className="list-decimal list-inside space-y-1">
                        <li>Go to <a href="https://huggingface.co/settings/tokens" target="_blank" rel="noreferrer" className="underline">huggingface.co/settings/tokens</a></li>
                        <li>Create a free &quot;Read&quot; token</li>
                        <li>Add to your <code className="bg-black px-1">backend/.env</code>: <code className="bg-black px-1">HF_API_KEY=hf_...</code></li>
                        <li>Restart backend</li>
                      </ol>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="p-4 border-t border-neutral-800">
              <button
                onClick={startArena}
                disabled={isRunning}
                className="w-full rounded-lg bg-gradient-to-r from-red-600 to-orange-600 px-4 py-3 text-sm font-black uppercase tracking-widest text-white disabled:opacity-50 hover:from-red-500 hover:to-orange-500 transition-all"
              >
                {isRunning ? "Battle in Progress..." : "⚔ Launch Arena"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
