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
        """Scans manifest files for vulnerable dependencies across multiple ecosystems."""
        print(f"[*] SCA: Scanning dependencies in {self.root_dir}...")
        
        # 1. Node.js (package.json)
        pkg_json = os.path.join(self.root_dir, "package.json")
        if os.path.exists(pkg_json):
            self._scan_npm(pkg_json)

        # 2. Python (requirements.txt)
        req_txt = os.path.join(self.root_dir, "requirements.txt")
        if os.path.exists(req_txt):
            self._scan_python(req_txt)

        # 3. Go (go.mod)
        go_mod = os.path.join(self.root_dir, "go.mod")
        if os.path.exists(go_mod):
            self._scan_go(go_mod)

        # 4. Java (pom.xml)
        pom_xml = os.path.join(self.root_dir, "pom.xml")
        if os.path.exists(pom_xml):
            self._scan_java(pom_xml)
            
        # 5. Rust (Cargo.toml)
        cargo_toml = os.path.join(self.root_dir, "Cargo.toml")
        if os.path.exists(cargo_toml):
            self._scan_rust(cargo_toml)

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
                    # Match: name==version, name>=version, or just name
                    match = re.match(r"^([a-zA-Z0-9_\-]+)([=<>!~]+[0-9\.]*)?", line.strip())
                    if match:
                        name, version = match.groups()
                        deps[name] = version or "latest"
                if deps:
                    self._check_with_ai("Python/PIP", deps)
        except:
            pass

    def _scan_go(self, path: str):
        """Parses go.mod files for dependencies."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                deps = {}
                # Match: require name vVersion
                # require ( ... ) blocks are also common, but simple regex handles most cases
                matches = re.findall(r"require\s+([^\s]+)\s+([^\s]+)", content)
                for name, version in matches:
                    deps[name] = version
                if deps:
                    self._check_with_ai("Go/go.mod", deps)
        except:
            pass

    def _scan_java(self, path: str):
        """Parses pom.xml files for dependencies (Maven)."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                deps = {}
                # Extract <artifactId> and <version> inside <dependency> blocks
                # Using regex for simplicity without full XML parser dependency
                blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
                for block in blocks:
                    artifact = re.search(r"<artifactId>(.*?)</artifactId>", block)
                    version = re.search(r"<version>(.*?)</version>", block)
                    if artifact:
                        deps[artifact.group(1)] = version.group(1) if version else "latest"
                if deps:
                    self._check_with_ai("Java/Maven", deps)
        except:
            pass

    def _scan_rust(self, path: str):
        """Parses Cargo.toml files for dependencies."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
                # Basic TOML parsing for dependencies
                # Match: name = "version" or name = { version = "..." }
                deps = {}
                in_deps = False
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("[dependencies]"):
                        in_deps = True
                        continue
                    if line.startswith("[") and in_deps:
                        in_deps = False
                        continue
                    if in_deps and "=" in line:
                        parts = line.split("=")
                        name = parts[0].strip()
                        version = parts[1].strip().strip('"').strip("'")
                        deps[name] = version
                if deps:
                    self._check_with_ai("Rust/Cargo", deps)
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
