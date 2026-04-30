"use client";

import { useState, useEffect } from "react";
import { Settings, Brain, Key, Check, AlertCircle, X } from "lucide-react";

export type LLMConfig = {
  provider: "huggingface" | "gemini" | "groq" | "openai" | "anthropic" | "ollama" | "default";
  model: string;
  api_key: string;
};

const PROVIDERS = [
  { id: "default", name: "System Default (Auto)", isFree: true, defaultModel: "auto" },
  { id: "ollama", name: "Ollama (Local)", isFree: true, defaultModel: "llama3" },
  { id: "huggingface", name: "Hugging Face (Free)", isFree: true, defaultModel: "mistralai/Mistral-7B-Instruct-v0.3" },
  { id: "gemini", name: "Google Gemini", isFree: false, defaultModel: "gemini-2.0-flash" },
  { id: "groq", name: "Groq", isFree: false, defaultModel: "llama-3.3-70b-versatile" },
  { id: "openai", name: "OpenAI", isFree: false, defaultModel: "gpt-4o" },
  { id: "anthropic", name: "Anthropic", isFree: false, defaultModel: "claude-3-5-sonnet-20240620" },
];

export function ModelSettings({ 
  onConfigChange, 
  initialConfig 
}: { 
  onConfigChange: (config: LLMConfig) => void;
  initialConfig?: LLMConfig;
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [config, setConfig] = useState<LLMConfig>(initialConfig || {
    provider: "default",
    model: "auto",
    api_key: ""
  });

  useEffect(() => {
    onConfigChange(config);
  }, [config, onConfigChange]);

  const handleProviderChange = (providerId: string) => {
    const provider = PROVIDERS.find(p => p.id === providerId);
    setConfig({
      ...config,
      provider: providerId as LLMConfig["provider"],
      model: provider?.defaultModel || ""
    });
  };

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 transition-all text-sm group"
        title="LLM Settings"
      >
        <Settings className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-90' : ''}`} />
        <span className="text-white/70 group-hover:text-white">AI Config</span>
      </button>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
          <div className="absolute right-0 top-12 w-80 z-50 p-4 rounded-xl bg-black/80 backdrop-blur-xl border border-white/20 shadow-2xl animate-in fade-in zoom-in duration-200">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Brain className="w-5 h-5 text-blue-400" />
                <h3 className="font-semibold text-white">LLM Configuration</h3>
              </div>
              <button onClick={() => setIsOpen(false)} className="p-1 hover:bg-white/10 rounded-full transition-colors">
                <X className="w-4 h-4 text-white/50" />
              </button>
            </div>

            <div className="space-y-4">
              {/* Provider Selection */}
              <div>
                <label className="block text-xs font-medium text-white/50 mb-1.5 uppercase tracking-wider">Provider</label>
                <select
                  value={config.provider}
                  onChange={(e) => handleProviderChange(e.target.value)}
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-blue-500/50"
                >
                  {PROVIDERS.map(p => (
                    <option key={p.id} value={p.id} className="bg-neutral-900">
                      {p.name} {p.isFree ? "(Free)" : ""}
                    </option>
                  ))}
                </select>
              </div>

              {/* Model Selection */}
              <div>
                <label className="block text-xs font-medium text-white/50 mb-1.5 uppercase tracking-wider">Model</label>
                <input
                  type="text"
                  value={config.model}
                  onChange={(e) => setConfig({ ...config, model: e.target.value })}
                  placeholder="Model name..."
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-blue-500/50"
                />
              </div>

              {/* API Key */}
              <div>
                <label className="block text-xs font-medium text-white/50 mb-1.5 uppercase tracking-wider">API Key</label>
                <div className="relative">
                  <Key className="absolute left-3 top-2.5 w-4 h-4 text-white/30" />
                  <input
                    type="password"
                    value={config.api_key}
                    onChange={(e) => setConfig({ ...config, api_key: e.target.value })}
                    placeholder={config.provider === 'huggingface' ? "Optional for HF..." : "Paste key here..."}
                    className="w-full bg-white/5 border border-white/10 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:ring-1 focus:ring-blue-500/50 placeholder:text-white/20"
                  />
                </div>
                {config.provider !== 'huggingface' && !config.api_key && (
                  <div className="flex items-center gap-1.5 mt-2 text-[10px] text-amber-400/80">
                    <AlertCircle className="w-3 h-3" />
                    <span>Key required for this provider</span>
                  </div>
                )}
              </div>

              <div className="pt-2 border-t border-white/10 mt-2">
                <div className="flex items-center gap-2 text-[10px] text-white/40">
                  <Check className="w-3 h-3 text-green-500" />
                  <span>Configured keys are kept in-browser</span>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
