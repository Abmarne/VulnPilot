import requests
from typing import List, Dict, Any

def analyze_headers(url: str) -> List[Dict[str, Any]]:
    """Analyzes security headers of a target URL."""
    findings = []
    try:
        response = requests.get(url, timeout=5, verify=False)
        headers = response.headers
        
        # Check list
        checks = {
            "Content-Security-Policy": "Prevents XSS and various injection attacks.",
            "Strict-Transport-Security": "Enforces HTTPS connections (HSTS).",
            "X-Frame-Options": "Prevents Clickjacking attacks.",
            "X-Content-Type-Options": "Prevents MIME-sniffing based attacks.",
            "Referrer-Policy": "Controls how much referrer information is sent with requests."
        }
        
        for header, description in checks.items():
            if header not in headers:
                findings.append({
                    "vulnerability_type": f"Missing Security Header: {header}",
                    "severity": "Medium" if header != "Referrer-Policy" else "Low",
                    "url": url,
                    "explanation": f"The '{header}' header is missing. {description}",
                    "impact": f"Lack of {header} makes the application vulnerable to certain classes of web attacks like {header.replace('X-', '').replace('-Options', '')}.",
                    "exploit_scenario": f"An attacker can exploit the absence of this header to perform attacks such as Clickjacking (if X-Frame-Options is missing) or Cross-Site Scripting (if CSP is missing).",
                    "manual_poc": f"Run 'curl -I {url}' and observe that the '{header}' header is not present in the response.",
                    "poc_script": f"import requests\nr = requests.get('{url}')\nprint(f'{{ \"{header}\" in r.headers }}')"
                })
        
        # Check for Information Leakage
        server = headers.get("Server")
        if server:
            findings.append({
                "vulnerability_type": "Server Version Leakage",
                "severity": "Low",
                "url": url,
                "explanation": f"The 'Server' header reveals the backend technology: {server}. This helps attackers target specific software versions.",
                "impact": "Knowing the server version allows an attacker to search for specific exploits and vulnerabilities targeting that version.",
                "exploit_scenario": f"1. Attacker sends a request to {url}.\n2. Attacker reads the 'Server' header.\n3. Attacker uses a database like Exploit-DB to find vulnerabilities for that specific server version.",
                "manual_poc": f"Check the HTTP response headers for the 'Server' field.",
                "poc_script": f"import requests\nr = requests.get('{url}')\nprint('Server:', r.headers.get('Server'))"
            })
            
    except Exception as e:
        print(f"[!] Header analysis failed: {e}")
        
    return findings
