from typing import List, Dict, Any, Optional, Callable, Awaitable

from crawler import ReconCrawler
from dependency_scanner import DependencyScanner
from fuzzer import Fuzzer
from header_analyzer import analyze_headers
from logic_auditor import LogicAuditor
from sast_engine import SastEngine
import llm


class ScannerEngine:
    def __init__(
        self,
        target: str,
        session_cookie: Optional[str] = None,
        on_log: Optional[Callable[[str, str], Awaitable[None]]] = None,
        on_progress: Optional[Callable[[str, int], Awaitable[None]]] = None,
        on_finding: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
    ):
        self.target = target
        self.session_cookie = session_cookie
        self.on_log = on_log
        self.on_progress = on_progress
        self.on_finding = on_finding
        self.all_findings: List[Dict[str, Any]] = []

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
        """Main orchestration loop: Recon -> SCA -> SAST -> Logic -> DAST -> Analysis."""
        await self._emit_log("--- [ SCAN INITIATED ] ---", "init")
        await self._emit_progress("init", 5)

        input_targets = [target.strip() for target in self.target.split(",") if target.strip()]
        target_url = None
        codebase_path = None

        for raw_target in input_targets:
            is_github = "github.com" in raw_target.lower()
            is_http = raw_target.lower().startswith(("http://", "https://"))

            if is_github:
                codebase_path = raw_target if is_http else f"https://{raw_target}"
                await self._emit_log(f"[*] Detected GitHub: {codebase_path}", "init")
            elif is_http:
                target_url = raw_target
                await self._emit_log(f"[*] Detected Web App: {target_url}", "init")
            elif "." in raw_target and "/" not in raw_target and "\\" not in raw_target:
                target_url = f"http://{raw_target}"
                await self._emit_log(f"[*] Detected Domain: {target_url}", "init")
            else:
                codebase_path = raw_target
                await self._emit_log(f"[*] Detected Local Code: {codebase_path}", "init")

        await self._emit_progress("recon", 10)

        endpoints: List[Dict[str, Any]] = []
        if target_url:
            await self._emit_log(f"[*] Recon: Crawling {target_url}...", "recon")
            crawler = ReconCrawler(target_url, self.session_cookie)
            discovery_data = crawler.map_surface()
            endpoints = discovery_data.get("endpoints", [])
            js_urls = discovery_data.get("js_urls", [])

            await self._emit_log(
                f"[*] Recon: Found {len(endpoints)} surface endpoints and {len(js_urls)} scripts.",
                "recon",
            )

            if js_urls:
                await self._emit_log("[*] Recon: Analyzing JavaScript for hidden API routes...", "recon")
                ghost_count = 0
                for js_url in js_urls[:5]:
                    await self._emit_log(f"  [>] Analyzing {js_url.split('/')[-1]}...", "recon")
                    js_content = crawler.fetch_js_content(js_url)
                    if not js_content:
                        continue

                    for endpoint in llm.reconstruct_api_schema(js_content):
                        endpoint_url = endpoint.get("url", "")
                        if not endpoint_url:
                            continue
                        if endpoint_url.startswith("/"):
                            endpoint["url"] = target_url.rstrip("/") + endpoint_url
                        if not any(existing.get("url") == endpoint.get("url") for existing in endpoints):
                            endpoints.append(endpoint)
                            ghost_count += 1
                            await self._emit_log(
                                f"  [+] GHOST ENDPOINT: {endpoint.get('method', 'GET')} {endpoint.get('url')}",
                                "recon",
                            )
                if ghost_count > 0:
                    await self._emit_log(
                        f"[*] Recon: Added {ghost_count} hidden 'Ghost Endpoints' to attack surface.",
                        "recon",
                    )

            await self._emit_log("[*] Recon: Inspecting HTTP security headers...", "recon")
            for finding in analyze_headers(target_url):
                await self._emit_finding(finding)

        await self._emit_progress("sca", 20)

        if codebase_path:
            await self._emit_log("[*] SCA: Scanning dependency manifests...", "sca")
            for finding in DependencyScanner(codebase_path).scan():
                await self._emit_finding(finding)

        await self._emit_progress("sast", 30)

        code_context = ""
        guided_insights: List[Dict[str, Any]] = []
        if codebase_path:
            await self._emit_log("[*] SAST: Extracting source code...", "sast")
            sast = SastEngine(codebase_path)
            prepared_path = sast.prepare_codebase()
            if prepared_path:
                code_context = sast.extract_critical_files()
                await self._emit_log("[*] SAST: Running AI Sink Analysis...", "sast")
                guided_insights = llm.identify_sinks(code_context)
                await self._emit_log(
                    f"[*] SAST: Found {len(guided_insights)} potential code sinks.",
                    "sast",
                )

                for sink in guided_insights:
                    deps = sink.get("required_context", [])
                    if not deps:
                        continue

                    await self._emit_log(
                        f"[*] SAST: Taint-Chasing dependencies for {sink.get('url_pattern', 'unknown sink')}...",
                        "sast",
                    )
                    extra_code = ""
                    for dep_path in deps:
                        content = sast.get_file_content(dep_path)
                        if not content:
                            continue
                        extra_code += f"\n--- DEPENDENCY PATH: {dep_path} ---\n{content}\n"
                        await self._emit_log(f"  [>] Fetched context: {dep_path}", "sast")

                    if extra_code:
                        verdict = llm.deep_taint_audit(sink, extra_code)
                        if verdict:
                            sink.update(verdict)
                            if verdict.get("verdict") == "False Positive":
                                await self._emit_log(
                                    f"  [-] Logic Check: Verified False Positive for {sink.get('url_pattern')}",
                                    "sast",
                                )
                            elif verdict.get("verdict") == "Verified":
                                await self._emit_log(
                                    f"  [!] Logic Check: PROVEN VULNERABLE for {sink.get('url_pattern')}",
                                    "sast",
                                )
            sast.cleanup()

        await self._emit_progress("logic", 50)

        if target_url and endpoints:
            await self._emit_log("[*] Logic: Auditing discovered routes for access-control flaws...", "logic")
            for finding in LogicAuditor(endpoints, self.session_cookie).run_audit():
                await self._emit_finding(finding)

        await self._emit_progress("dast", 60)

        raw_anomalies: List[Dict[str, Any]] = []
        if target_url:
            await self._emit_log(f"[*] DAST: Starting fuzzer against {target_url}...", "dast")
            fuzzer = Fuzzer(endpoints, self.session_cookie, guided_insights)
            raw_anomalies = fuzzer.run_fuzzer(base_url=target_url)
            await self._emit_log(f"[*] DAST: Fuzzer found {len(raw_anomalies)} anomalies.", "dast")

        await self._emit_progress("analysis", 80)

        await self._emit_log("[*] Finalizing Hybrid Analysis with Gemini...", "analysis")
        for finding in llm.analyze_hybrid(raw_anomalies, code_context):
            await self._emit_finding(finding)

        await self._emit_progress("complete", 100)
        await self._emit_log("--- [ SCAN COMPLETE ] ---", "complete")
        return self.all_findings

    async def apply_remediation(self, finding: Dict[str, Any]) -> bool:
        """Tries to fix a vulnerability by refactoring the source file."""
        rel_path = finding.get("url") or finding.get("url_pattern")
        if not rel_path or rel_path.startswith(("http://", "https://")):
            await self._emit_log("[!] Cannot auto-fix findings that only reference remote URLs.", "error")
            return False
        if "/" not in rel_path and "\\" not in rel_path and "." not in rel_path:
            await self._emit_log("[!] Cannot auto-fix: Finding is not tied to a specific local file.", "error")
            return False

        input_targets = [target.strip() for target in self.target.split(",") if target.strip()]
        codebase_path = next(
            (
                target
                for target in input_targets
                if "http" not in target.lower() and "github" not in target.lower()
            ),
            None,
        )

        if not codebase_path:
            await self._emit_log("[!] Cannot auto-fix: No local codebase path detected.", "error")
            return False

        sast = SastEngine(codebase_path)
        prepared_path = sast.prepare_codebase()
        if not prepared_path:
            await self._emit_log("[!] Cannot auto-fix: Failed to initialize the codebase.", "error")
            return False

        original_code = sast.get_file_content(rel_path)
        if not original_code:
            await self._emit_log(f"[!] Cannot auto-fix: Could not read source for {rel_path}", "error")
            sast.cleanup()
            return False

        await self._emit_log(f"[*] Starting AI-powered refactor for {rel_path}...", "analysis")
        refactored_code = llm.get_refactored_file(original_code, finding)

        if refactored_code and sast.write_file_content(rel_path, refactored_code):
            sast.cleanup()
            await self._emit_log(f"[SUCCESS] Security fix applied to {rel_path}", "analysis")
            return True

        sast.cleanup()
        await self._emit_log(f"[!] FAILED: AI could not safely refactor {rel_path}", "error")
        return False
