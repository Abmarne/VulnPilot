import os
import json
import re
from typing import List, Dict, Any
import llm

class DependencyScanner:
    def __init__(self, root_dir: str):
        self.root_dir = root_dir
        self.findings = []

    def scan(self) -> List[Dict[str, Any]]:
        """Scans manifest files for vulnerable dependencies."""
        print(f"[*] SCA: Scanning dependencies in {self.root_dir}...")
        
        # 1. Look for package.json (Node.js)
        pkg_json = os.path.join(self.root_dir, "package.json")
        if os.path.exists(pkg_json):
            self._scan_npm(pkg_json)

        # 2. Look for requirements.txt (Python)
        req_txt = os.path.join(self.root_dir, "requirements.txt")
        if os.path.exists(req_txt):
            self._scan_python(req_txt)
            
        return self.findings

    def _scan_npm(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                if deps:
                    self._check_with_ai("NPM/Node.js", deps)
        except:
            pass

    def _scan_python(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                deps = {}
                for line in content.splitlines():
                    match = re.match(r"^([a-zA-Z0-9_\-]+)([=<>!~]+[0-9\.]*)?", line.strip())
                    if match:
                        name, version = match.groups()
                        deps[name] = version or "latest"
                if deps:
                    self._check_with_ai("Python/PIP", deps)
        except:
            pass

    def _check_with_ai(self, ecosystem: str, dependencies: Dict[str, str]):
        """Uses Gemini to identify known vulnerabilities in the dependency list."""
        prompt = f"""
        --- SYSTEM ---
        You are a Security Software Composition Analysis (SCA) engine.
        
        --- CONTEXT ---
        Ecosystem: {ecosystem}
        Dependencies: {json.dumps(dependencies)}

        --- TASK ---
        Identify any dependencies with KNOWN security vulnerabilities (CVEs) or major security risks in these versions.
        For each finding, provide:
        1. Library Name
        2. Version
        3. Severity (High, Medium, Low, Critical)
        4. Explanation of the risk/CVE.
        5. Recommendation (e.g., upgrade to version X).

        Return ONLY a JSON list of objects. No explanation.
        """
        
        try:
            text = llm._call_llm(prompt)
            vulns = llm._parse_gemini_json(text)
            
            for v in vulns:
                self.findings.append({
                    "vulnerability_type": f"Vulnerable Dependency ({v.get('Library Name') or v.get('library_name') or v.get('name', 'Unknown')})",
                    "severity": v.get("Severity") or v.get("severity", "Medium"),
                    "explanation": v.get("Explanation") or v.get("explanation", ""),
                    "url": f"Manifest: {ecosystem}",
                    "remediation_steps": v.get("Recommendation") or v.get("recommendation", "Update the library to the latest secure version.")
                })
        except Exception as e:
            print(f"[!] SCA AI Check failed: {e}")
