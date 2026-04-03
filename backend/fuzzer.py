import concurrent.futures
import requests
from typing import List, Dict, Any

class Fuzzer:
    def __init__(self, target_endpoints: List[str], session_cookie: str = None):
        self.endpoints = target_endpoints
        self.session = requests.Session()
        
        # Inject cookie if provided for authenticated fuzzing
        if session_cookie:
            self.session.headers.update({"Cookie": session_cookie})
            
        # Benign, non-destructive payloads designed to trigger errors, not compromise data
        self.payloads = [
            "' OR 1=1 --",                          # SQLi boolean test
            "\" OR 1=1 --",                         # SQLi double quote test
            "<script>alert('VulnPilot_XSS_Test')</script>", # XSS test
            "../../../../../../../../etc/passwd",   # Path traversal test
            "`; sleep 3; `",                        # Command injection test
            "A" * 1500                              # Buffer overflow / unexpected length test
        ]
        
    def attack_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """
        Fires payloads at a specific endpoint and monitors the response for anomalies.
        """
        results = []
        for payload in self.payloads:
            # MVP Fuzzing: Simply appending to query params for GET requests.
            # A mature fuzzer would inject into forms, headers, and POST bodies.
            separator = "&" if "?" in url else "?"
            target_url = f"{url}{separator}vulnpilot_test={payload}"
            
            try:
                # print(f"[*] Fuzzing: {target_url}")
                response = self.session.get(target_url, timeout=5)
                
                # Condition 1: Unexpected 500 errors (Unhandled exceptions)
                if response.status_code >= 500:
                    results.append({
                        "url": url,
                        "payload": payload,
                        "anomaly": f"HTTP {response.status_code} Internal Server Error Tripped",
                        "response_snippet": response.text[:300]
                    })
                # Condition 2: Leaked database syntax errors
                elif any(err in response.text.lower() for err in ["syntax error", "mysql", "postgresql", "sql syntax"]):
                    results.append({
                        "url": url,
                        "payload": payload,
                        "anomaly": "Database Error Stacktrace Leaked",
                        "response_snippet": response.text[:300]
                    })
                # Condition 3: Reflection (Potential XSS)
                elif "<script>alert('VulnPilot_XSS_Test')</script>" in response.text:
                    results.append({
                        "url": url,
                        "payload": payload,
                        "anomaly": "Payload Reflected verbatim (High XSS Probability)",
                        "response_snippet": "XSS script payload found cleanly inside HTML response."
                    })
                # Condition 4: Directory Traversal Match
                elif "root:x:0:0:" in response.text:
                   results.append({
                        "url": url,
                        "payload": payload,
                        "anomaly": "Path Traversal / Local File Inclusion Detected",
                        "response_snippet": response.text[:100]
                    }) 

            except requests.exceptions.RequestException as e:
                # Timeout could indicate an induced sleep (Command injection) or a blocked request
                results.append({
                    "url": url,
                    "payload": payload,
                    "anomaly": f"Connection Event: {str(e)}",
                    "response_snippet": ""
                })
                
        return results

    def run_fuzzer(self) -> List[Dict[str, Any]]:
        """
        Runs the fuzzing asynchronously across all discovered endpoints.
        """
        all_anomalies = []
        print(f"Launching Concurrent Fuzzing Engine against {len(self.endpoints)} endpoints...")
        
        # ThreadPoolExecutor simulates async delivery to speed up fuzzing
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self.attack_endpoint, url): url for url in self.endpoints}
            
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    anomalies = future.result()
                    if anomalies:
                        all_anomalies.extend(anomalies)
                except Exception as exc:
                    url = future_to_url[future]
                    print(f"[!] Error fuzzing {url}: {exc}")
                    
        print(f"Fuzzing complete. Detected {len(all_anomalies)} anomalies to send to LLM.")
        return all_anomalies

if __name__ == "__main__":
    # Quick Test Execution
    fuzzer = Fuzzer(["http://example.com/login", "http://example.com/search"])
    anomalies_found = fuzzer.run_fuzzer()
    for a in anomalies_found:
        print(f"Anomaly: {a['anomaly']} on {a['url']}")
