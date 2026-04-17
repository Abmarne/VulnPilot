import requests
import re
from typing import List, Dict, Any
from urllib.parse import urlparse, urlunparse

class LogicAuditor:
    def __init__(self, targets: List[Dict[str, Any]], session_cookie: str = None):
        self.targets = targets
        self.session_cookie = session_cookie
        self.findings = []
        self.session = requests.Session()
        if session_cookie:
            self.session.headers.update({"Cookie": session_cookie})

    def run_audit(self) -> List[Dict[str, Any]]:
        """Main entry point for logic auditing."""
        print(f"[*] Logic Auditor: Auditing {len(self.targets)} endpoints for authorization flaws...")
        
        for target in self.targets:
            url = target["url"]
            # 1. IDOR Check (Insecure Direct Object Reference)
            if self._has_id_pattern(url):
                self._check_idor(target)
            
            # 2. Broken Access Control (Cookie Swapping / Removal)
            self._check_auth_bypass(target)
            
        return self.findings

    def _has_id_pattern(self, url: str) -> bool:
        """Heuristic to detect if a URL contains an ID (e.g., /user/123 or /api/post/abc-123)."""
        return bool(re.search(r"/\d+/?$", url)) or bool(re.search(r"/[a-f0-9-]{32,}/?$", url))

    def _check_idor(self, target: Dict[str, Any]):
        """Tests if neighbor IDs are accessible."""
        url = target["url"]
        # Simple neighbor ID test (e.g., change 123 to 122 or 124)
        match = re.search(r"/(\d+)/?$", url)
        if match:
            current_id = int(match.group(1))
            neighbor_id = current_id + 1
            neighbor_url = url.replace(str(current_id), str(neighbor_id))
            
            try:
                resp = self.session.get(neighbor_url, timeout=5)
                # If we get a 200 on a neighbor URL, it's a potential IDOR
                if resp.status_code == 200 and len(resp.text) > 100:
                    self.findings.append({
                        "vulnerability_type": "Potential IDOR (Insecure Direct Object Reference)",
                        "severity": "High",
                        "explanation": f"Neighbor resource '{neighbor_url}' returned a 200 OK. This suggests that the application does not properly validate authorization for related resources.",
                        "impact": "An attacker can view or modify data belonging to other users by simply changing an ID in the URL.",
                        "exploit_scenario": f"1. Log in as a user.\n2. Note your resource ID in the URL.\n3. Change the ID to {neighbor_id} to access another user's private data.",
                        "url": neighbor_url,
                        "manual_poc": f"Navigate to {neighbor_url} while logged in and check if you can see data that doesn't belong to you.",
                        "remediation_steps": "Implement object-level authorization checks to ensure the user has permission to access the specific ID requested."
                    })
            except:
                pass

    def _check_auth_bypass(self, target: Dict[str, Any]):
        """Tests if an endpoint is accessible without a session cookie."""
        if not self.session_cookie:
            return
            
        url = target["url"]
        try:
            # Request WITHOUT the session cookie
            resp = requests.get(url, timeout=5)
            # If a sensitive-looking URL returns 200 without auth, it's a finding
            sensitive_keywords = ["admin", "profile", "settings", "api", "dashboard", "user"]
            if resp.status_code == 200 and any(k in url.lower() for k in sensitive_keywords):
                if len(resp.text) > 500: # Heuristic: ignore simple login pages
                    self.findings.append({
                        "vulnerability_type": "Broken Access Control (Authentication Bypass)",
                        "severity": "High",
                        "explanation": f"The sensitive endpoint '{url}' is accessible without a valid session cookie, returning a full page (200 OK).",
                        "impact": "Unauthenticated users can access restricted administrative or user-specific data, leading to full account takeovers or data breaches.",
                        "exploit_scenario": "1. Identify a sensitive endpoint.\n2. Access the URL directly in a browser where you are NOT logged in.\n3. Observe that the application displays restricted data instead of redirecting to login.",
                        "url": url,
                        "manual_poc": f"Open {url} in an Incognito window and verify that it loads correctly.",
                        "remediation_steps": "Enforce strict server-side session validation for all sensitive routes."
                    })
        except:
            pass
