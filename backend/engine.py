from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlparse

from crawler import ReconCrawler
from dependency_scanner import DependencyScanner
from fuzzer import Fuzzer
from header_analyzer import analyze_headers
from logic_auditor import LogicAuditor
from profile_store import get_profile
from sast_engine import SastEngine
from nuclei_scanner import NucleiScanner
import llm


class ScannerEngine:
    def __init__(
        self,
        target: str,
        session_cookie: Optional[str] = None,
        profile_id: Optional[int] = None,
        use_profile_requests: bool = False,
        on_log: Optional[Callable[[str, str], Awaitable[None]]] = None,
        on_progress: Optional[Callable[[str, int], Awaitable[None]]] = None,
        on_finding: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
        llm_config: Optional[Dict[str, Any]] = None,
    ):
        self.target = target
        self.session_cookie = session_cookie
        self.profile_id = profile_id
        self.use_profile_requests = use_profile_requests
        self.on_log = on_log
        self.on_progress = on_progress
        self.on_finding = on_finding
        self.llm_config = llm_config
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

    def _request_signature(self, target: Dict[str, Any]) -> str:
        parsed = urlparse(target.get("url", ""))
        query_keys = sorted((target.get("query_params") or {}).keys())
        form_keys = sorted(target.get("form_fields") or [])
        json_keys = sorted(target.get("json_fields") or [])
        key_blob = ",".join(query_keys + form_keys + json_keys)
        return f"{target.get('method', 'GET').upper()}|{parsed.scheme}://{parsed.netloc}{parsed.path}|{key_blob}"

    def _merge_targets(self, profile_targets: List[Dict[str, Any]], crawler_targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        seen = set()

        for target in profile_targets + crawler_targets:
            signature = self._request_signature(target)
            if signature in seen:
                continue
            seen.add(signature)
            merged.append(target)
        return merged

    def _profile_request_to_target(self, profile: Dict[str, Any], request: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "url": request.get("url", ""),
            "method": request.get("method", "GET"),
            "params": list((request.get("query_json") or {}).keys()),
            "form_fields": request.get("form_fields", []),
            "json_fields": request.get("json_fields", []),
            "query_params": request.get("query_json", {}),
            "headers": request.get("headers_json", {}),
            "cookies_json": request.get("cookies_json", {}),
            "body_text": request.get("body_text", ""),
            "body_type": request.get("body_type", "none"),
            "request_name": request.get("request_name", ""),
            "fuzzable": request.get("fuzzable", True),
            "source": profile.get("source_type", "profile"),
            "profile_id": profile.get("id"),
            "profile_request_id": request.get("id"),
        }

    async def run(self):
        """Main orchestration loop: Profile -> Recon -> SCA -> SAST -> Logic -> DAST -> Analysis."""
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

        await self._emit_progress("profile", 10)

        imported_targets: List[Dict[str, Any]] = []
        if self.use_profile_requests and self.profile_id:
            profile = get_profile(self.profile_id)
            if profile:
                if not target_url:
                    target_url = profile.get("target")
                imported_targets = [
                    self._profile_request_to_target(profile, request)
                    for request in profile.get("requests", [])
                ]
                await self._emit_log(
                    f"[*] Profile: Loaded {len(imported_targets)} authenticated request(s) from profile '{profile.get('name')}'.",
                    "profile",
                )
            else:
                await self._emit_log(f"[!] Profile: Requested profile {self.profile_id} was not found.", "profile")
        else:
            await self._emit_log("[*] Profile: No authenticated request profile selected.", "profile")

        await self._emit_progress("recon", 18)

        crawler_targets: List[Dict[str, Any]] = []
        if target_url:
            await self._emit_log(f"[*] Recon: Crawling {target_url}...", "recon")
            crawler = ReconCrawler(target_url, self.session_cookie)
            discovery_data = crawler.map_surface()
            crawler_targets = discovery_data.get("endpoints", [])
            js_urls = discovery_data.get("js_urls", [])

            await self._emit_log(
                f"[*] Recon: Found {len(crawler_targets)} surface endpoints and {len(js_urls)} scripts.",
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

                    for endpoint in llm.reconstruct_api_schema(js_content, llm_config=self.llm_config):
                        endpoint_url = endpoint.get("url", "")
                        if not endpoint_url:
                            continue
                        if endpoint_url.startswith("/"):
                            endpoint["url"] = target_url.rstrip("/") + endpoint_url
                        crawler_targets.append(endpoint)
                        ghost_count += 1
                if ghost_count > 0:
                    await self._emit_log(
                        f"[*] Recon: Added {ghost_count} hidden 'Ghost Endpoints' to attack surface.",
                        "recon",
                    )

            await self._emit_log("[*] Recon: Inspecting HTTP security headers...", "recon")
            for finding in analyze_headers(target_url):
                await self._emit_finding(finding)

        endpoints = self._merge_targets(imported_targets, crawler_targets)
        if imported_targets:
            await self._emit_log(
                f"[*] Profile: Merged authenticated profile requests with crawler surface for {len(endpoints)} total targets.",
                "profile",
            )

        await self._emit_progress("sca", 28)

        if codebase_path:
            await self._emit_log("[*] SCA: Scanning dependency manifests...", "sca")
            for finding in DependencyScanner(codebase_path).scan():
                await self._emit_finding(finding)

        await self._emit_progress("sast", 40)

        code_context = ""
        guided_insights: List[Dict[str, Any]] = []
        if codebase_path:
            await self._emit_log("[*] SAST: Extracting source code...", "sast")
            sast = SastEngine(codebase_path)
            prepared_path = sast.prepare_codebase()
            if prepared_path:
                code_context = sast.extract_critical_files()
                await self._emit_log("[*] SAST: Running AI Sink Analysis...", "sast")
                guided_insights = llm.identify_sinks(code_context, llm_config=self.llm_config)
                await self._emit_log(f"[*] SAST: Found {len(guided_insights)} potential code sinks.", "sast")

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
                        verdict = llm.deep_taint_audit(sink, extra_code, llm_config=self.llm_config)
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

        # --- STEP 5: SECRETS SCANNING ---
        if codebase_path and code_context:
            await self._emit_log("[*] Secrets: Scanning for hardcoded credentials...", "secrets")
            secret_findings = llm.identify_secrets(code_context, llm_config=self.llm_config)
            for s_finding in secret_findings:
                await self._emit_finding(s_finding)
            await self._emit_log(f"[*] Secrets: Identified {len(secret_findings)} potential leaks.", "secrets")

        await self._emit_progress("logic", 55)

        if target_url and endpoints:
            await self._emit_log("[*] Logic: Auditing discovered routes for access-control flaws...", "logic")
            for finding in LogicAuditor(endpoints, self.session_cookie).run_audit():
                await self._emit_finding(finding)

        await self._emit_progress("dast", 70)

        raw_anomalies: List[Dict[str, Any]] = []
        if target_url and endpoints:
            # Extract actual application data schemas for AI contextual hacking
            schema_context = {"params": set(), "json_keys": set(), "form_fields": set()}
            for ep in endpoints:
                if ep.get("params"): schema_context["params"].update(ep["params"])
                if ep.get("json_fields"): schema_context["json_keys"].update(ep["json_fields"])
                if ep.get("form_fields"): schema_context["form_fields"].update(ep["form_fields"])
            
            schema_context_list = {
                "params": list(schema_context["params"]),
                "json_keys": list(schema_context["json_keys"]),
                "form_fields": list(schema_context["form_fields"])
            }

            await self._emit_log(f"[*] DAST: Starting fuzzer against {target_url}...", "dast")
            fuzzer = Fuzzer(endpoints, self.session_cookie, guided_insights, schema_context_list, llm_config=self.llm_config)
            raw_anomalies = fuzzer.run_fuzzer(base_url=target_url)
            await self._emit_log(f"[*] DAST: Fuzzer found {len(raw_anomalies)} anomalies.", "dast")

            await self._emit_log(f"[*] BEAST MODE: Invoking comprehensive 3rd-party signature scans (Nuclei) against {target_url}...", "dast")
            nuclei = NucleiScanner(target_url)
            if nuclei.is_installed():
                nuclei_anomalies = nuclei.attack()
                raw_anomalies.extend(nuclei_anomalies)
                await self._emit_log(f"[*] BEAST MODE: Nuclei populated {len(nuclei_anomalies)} signature hits.", "dast")
            else:
                await self._emit_log("[!] BEAST MODE Disabled: 'nuclei' binary not found in PATH. Install via 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' to enable.", "dast")

        await self._emit_progress("analysis", 85)

        await self._emit_log("[*] Finalizing Hybrid Analysis with Gemini...", "analysis")
        for finding in llm.analyze_hybrid(raw_anomalies, code_context, llm_config=self.llm_config):
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
        refactored_code = llm.get_refactored_file(original_code, finding, llm_config=self.llm_config)

        if refactored_code and sast.write_file_content(rel_path, refactored_code):
            sast.cleanup()
            await self._emit_log(f"[SUCCESS] Security fix applied to {rel_path}", "analysis")
            return True

        sast.cleanup()
        await self._emit_log(f"[!] FAILED: AI could not safely refactor {rel_path}", "error")
        return False
