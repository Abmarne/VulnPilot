import asyncio
import json
from typing import List, Dict, Any, Optional, Callable, Awaitable
from crawler import ReconCrawler
from fuzzer import Fuzzer
import llm
from sast_engine import SastEngine
from header_analyzer import analyze_headers
from dependency_scanner import DependencyScanner
from logic_auditor import LogicAuditor
import os

class ScannerEngine:
    def __init__(
        self, 
        target: str, 
        session_cookie: Optional[str] = None,
        on_log: Optional[Callable[[str, str], Awaitable[None]]] = None,
        on_progress: Optional[Callable[[str, int], Awaitable[None]]] = None,
        on_finding: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None
    ):
        self.target = target
        self.session_cookie = session_cookie
        self.on_log = on_log
        self.on_progress = on_progress
        self.on_finding = on_finding
        self.all_findings = []

    async def _emit_log(self, text: str, stage: str = "general"):
        if self.on_log:
            await self.on_log(text, stage)
        else:
            print(f"[{stage.upper()}] {text}")

    async def _emit_progress(self, stage: str, percent: int):
        if self.on_progress:
            await self.on_progress(stage, percent)

    async def _emit_finding(self, finding: Dict[str, Any]):
        self.all_findings.append(finding)
        if self.on_finding:
            await self.on_finding(finding)

    async def run(self):
        """Main orchestration loop: Recon -> SAST -> DAST -> Analysis"""
        await self._emit_log("--- [ SCAN INITIATED ] ---", "init")
        await self._emit_progress("init", 5)

        # Parse Inputs
        input_targets = [t.strip() for t in self.target.split(",") if t.strip()]
        target_url = None
        codebase_path = None
        
        for t in input_targets:
            is_github = "github.com" in t.lower()
            is_http = t.lower().startswith(("http://", "https://"))
            
            if is_github:
                if not is_http: t = "https://" + t
                codebase_path = t
                await self._emit_log(f"[*] Detected GitHub: {codebase_path}", "init")
            elif is_http:
                target_url = t
                await self._emit_log(f"[*] Detected Web App: {target_url}", "init")
            elif "." in t and "/" not in t and "\\" not in t:
                target_url = "http://" + t
                await self._emit_log(f"[*] Detected Domain: {target_url}", "init")
            else:
                codebase_path = t
                await self._emit_log(f"[*] Detected Local Code: {codebase_path}", "init")

        await self._emit_progress("recon", 10)
        
        # 1. Recon (DAST Surface Discovery)
        endpoints = []
        if target_url:
            await self._emit_log(f"[*] Recon: Crawling {target_url}...", "recon")
            crawler = ReconCrawler(target_url, self.session_cookie)
            discovery_data = crawler.map_surface()
            endpoints = discovery_data.get("endpoints", [])
            js_urls = discovery_data.get("js_urls", [])
            
            await self._emit_log(f"[*] Recon: Found {len(endpoints)} surface endpoints and {len(js_urls)} scripts.", "recon")
            
            # 1b. Semantic API Reconstruction
            if js_urls:
                await self._emit_log("[*] Recon: Analyzing JavaScript for hidden API routes...", "recon")
                ghost_count = 0
                for js_url in js_urls[:5]:
                    await self._emit_log(f"  [>] Analyzing {js_url.split('/')[-1]}...", "recon")
                    js_content = crawler.fetch_js_content(js_url)
                    if js_content:
                        discovered_api = llm.reconstruct_api_schema(js_content)
                        for ep in discovered_api:
                            if ep["url"].startswith("/"):
                                ep["url"] = target_url + ep["url"]
                            if not any(e["url"] == ep["url"] for e in endpoints):
                                endpoints.append(ep)
                                ghost_count += 1
                                await self._emit_log(f"  [+] GHOST ENDPOINT: {ep['method']} {ep['url']}", "recon")
                if ghost_count > 0:
                    await self._emit_log(f"[*] Recon: Added {ghost_count} hidden 'Ghost Endpoints' to attack surface.", "recon")

        await self._emit_progress("sast", 30)
                
        # 2. Codebase Extraction & Sink Discovery (SAST)
        code_context = ""
        guided_insights = []
        if codebase_path:
            await self._emit_log("[*] SAST: Extracting source code...", "sast")
            sast = SastEngine(codebase_path)
            sast.prepare_codebase()
            code_context = sast.extract_critical_files()
            await self._emit_log("[*] SAST: Running AI Sink Analysis...", "sast")
            guided_insights = llm.identify_sinks(code_context)
            await self._emit_log(f"[*] SAST: Found {len(guided_insights)} potential code sinks.", "sast")
            
            # 2b. Taint-Chasing
            for sink in guided_insights:
                deps = sink.get("required_context", [])
                if deps:
                    await self._emit_log(f"[*] SAST: Taint-Chasing dependencies for {sink['url_pattern']}...", "sast")
                    extra_code = ""
                    for dep_path in deps:
                        content = sast.get_file_content(dep_path)
                        if content:
                            extra_code += f"\n--- DEPENDENCY PATH: {dep_path} ---\n{content}\n"
                            await self._emit_log(f"  [>] Fetched context: {dep_path}", "sast")
                    if extra_code:
                        verdict = llm.deep_taint_audit(sink, extra_code)
                        if verdict:
                            sink.update(verdict)
                            if verdict.get("verdict") == "False Positive":
                                await self._emit_log(f"  [-] Logic Check: Verified False Positive for {sink['url_pattern']}", "sast")
                            elif verdict.get("verdict") == "Verified":
                                await self._emit_log(f"  [!] Logic Check: PROVEN VULNERABLE for {sink['url_pattern']}", "sast")
            sast.cleanup()
        # 5. Final LLM Analysis
        await self._emit_log("[*] Finalizing Hybrid Analysis with Gemini...", "analysis")
        llm_findings = llm.analyze_hybrid(raw_anomalies, code_context)
        for f in llm_findings:
            await self._emit_finding(f)
        
        await self._emit_progress("complete", 100)
        await self._emit_log("--- [ SCAN COMPLETE ] ---", "complete")
        return self.all_findings

    async def apply_remediation(self, finding: Dict[str, Any]) -> bool:
        """Tries to fix a vulnerability by refactoring the source file."""
        rel_path = finding.get("url") or finding.get("url_pattern")
        if not rel_path or "/" not in rel_path and "\\" not in rel_path and "." not in rel_path:
            # If it's a URL pattern (e.g. /api/search), we can't easily map to file without more info
            # Usually SAST findings have a clear 'url' as filename
            await self._emit_log(f"[!] Cannot auto-fix: Finding is not tied to a specific local file.", "error")
            return False

        # Build codebase context for the specific file
        # We need a SastEngine instance to read/write
        input_targets = [t.strip() for t in self.target.split(",") if t.strip()]
        codebase_path = next((t for t in input_targets if "http" not in t.lower() or "github" not in t.lower()), None)
        
        if not codebase_path:
             await self._emit_log(f"[!] Cannot auto-fix: No local codebase path detected.", "error")
             return False

        sast = SastEngine(codebase_path)
        sast.prepare_codebase()
        original_code = sast.get_file_content(rel_path)
        
        if not original_code:
            await self._emit_log(f"[!] Cannot auto-fix: Could not read source for {rel_path}", "error")
            return False

        await self._emit_log(f"[*] Starting AI-powered refactor for {rel_path}...", "analysis")
        refactored_code = llm.get_refactored_file(original_code, finding)
        
        if refactored_code:
            success = sast.write_file_content(rel_path, refactored_code)
            if success:
                await self._emit_log(f"[🛡️] SUCCESS: Security fix applied to {rel_path}", "analysis")
                return True
        
        await self._emit_log(f"[!] FAILED: AI could not safely refactor {rel_path}", "error")
        return False
