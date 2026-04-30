"use client";

import { useState } from "react";
import { Upload, Terminal, FileCode, X, Search } from "lucide-react";

type SourceHubProps = {
  onImport: (type: "har" | "curl" | "openapi", data: string | File) => void;
  isOpen: boolean;
  onClose: () => void;
  target: string;
};

export function SourceHub({ onImport, isOpen, onClose, target }: SourceHubProps) {
  const [curl, setCurl] = useState("");

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-96 z-[100] bg-neutral-900 border-l border-neutral-800 shadow-2xl flex flex-col animate-in slide-in-from-right duration-300">
      <div className="p-6 border-b border-neutral-800 flex items-center justify-between">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Search className="w-5 h-5 text-emerald-400" />
          Advanced Context
        </h2>
        <button onClick={onClose} className="p-2 hover:bg-neutral-800 rounded-lg">
          <X className="w-5 h-5 text-neutral-500" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-8">
        <p className="text-sm text-neutral-400 leading-relaxed">
          Help the AI understand your project better by uploading network traffic or API specifications.
        </p>

        {/* HAR Upload */}
        <section className="space-y-3">
          <h3 className="text-xs font-black uppercase tracking-widest text-emerald-500">Network Traffic (HAR)</h3>
          <label className="flex flex-col items-center justify-center border-2 border-dashed border-neutral-800 rounded-xl p-6 hover:border-emerald-500/50 hover:bg-emerald-500/5 transition-all cursor-pointer group">
            <Upload className="w-8 h-8 text-neutral-600 group-hover:text-emerald-500 mb-2" />
            <span className="text-xs text-neutral-500 group-hover:text-neutral-300 font-medium">Upload .har file</span>
            <input 
              type="file" 
              className="hidden" 
              accept=".har" 
              onChange={(e) => e.target.files?.[0] && onImport("har", e.target.files[0])}
            />
          </label>
        </section>

        {/* cURL Import */}
        <section className="space-y-3">
          <h3 className="text-xs font-black uppercase tracking-widest text-teal-500">Single Action (cURL)</h3>
          <div className="relative group">
            <textarea
              value={curl}
              onChange={(e) => setCurl(e.target.value)}
              placeholder='curl "https://example.com/api" ...'
              className="w-full bg-neutral-950 border border-neutral-800 rounded-xl p-3 text-xs font-mono min-h-[100px] focus:outline-none focus:border-teal-500/50 transition-colors"
            />
            <button 
              onClick={() => { onImport("curl", curl); setCurl(""); }}
              className="absolute right-2 bottom-2 p-1.5 bg-teal-500 text-neutral-950 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity"
            >
              <Terminal className="w-4 h-4" />
            </button>
          </div>
        </section>

        {/* OpenAPI Export */}
        <section className="space-y-3">
          <h3 className="text-xs font-black uppercase tracking-widest text-indigo-500">API Documentation</h3>
          <label className="flex items-center gap-3 p-4 border border-neutral-800 rounded-xl hover:bg-neutral-800/50 transition-all cursor-pointer">
            <FileCode className="w-6 h-6 text-indigo-500" />
            <div className="flex-1">
              <div className="text-sm font-bold">Import OpenAPI</div>
              <div className="text-[10px] text-neutral-500 uppercase tracking-tight">Swagger, YAML or JSON</div>
            </div>
            <input 
              type="file" 
              className="hidden" 
              accept=".json,.yaml,.yml"
              onChange={(e) => e.target.files?.[0] && onImport("openapi", e.target.files[0])}
            />
          </label>
        </section>
      </div>

      <div className="p-6 bg-neutral-800/20 border-t border-neutral-800">
        <div className="text-[10px] text-neutral-600 uppercase font-black tracking-widest text-center">
          Active Target: {target || "None"}
        </div>
      </div>
    </div>
  );
}
