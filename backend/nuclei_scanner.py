import subprocess
import json
import tempfile
import os
import shutil
import platform
import urllib.request
import zipfile
from typing import List, Dict, Any


class NucleiScanner:
    """Wrapper to execute ProjectDiscovery's Nuclei for 'Beast Mode' vulnerability scanning."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.bin_dir = os.path.join(os.path.dirname(__file__), ".bin")
        self.nuclei_path = os.path.join(self.bin_dir, "nuclei.exe" if platform.system() == "Windows" else "nuclei")

    def _auto_install(self):
        """Automatically downloads the pre-compiled Nuclei binary to avoid manual setup."""
        if not os.path.exists(self.bin_dir):
            os.makedirs(self.bin_dir)
            
        sys_os = platform.system().lower()
        if sys_os == "windows":
            download_url = "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_windows_amd64.zip"
        elif sys_os == "darwin": # macOS
             download_url = "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_macOS_amd64.zip"
        else: # linux
            download_url = "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip"

        print(f"[*] BEAST MODE: Nuclei binary not found. Auto-downloading from {download_url}...")
        try:
            zip_path = os.path.join(self.bin_dir, "nuclei.zip")
            urllib.request.urlretrieve(download_url, zip_path)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.bin_dir)
            
            os.remove(zip_path)
            if sys_os != "windows":
                os.chmod(self.nuclei_path, 0o755)
                
            print("[*] BEAST MODE: Nuclei auto-installation complete.")
            return True
        except Exception as e:
            print(f"[!] BEAST MODE: Auto-installation failed: {str(e)}")
            return False

    def is_installed(self) -> bool:
        if os.path.exists(self.nuclei_path):
            return True
        elif shutil.which("nuclei"):
            self.nuclei_path = shutil.which("nuclei")
            return True
        else:
            return self._auto_install()

    def attack(self) -> List[Dict[str, Any]]:
        """Runs nuclei silently via subprocess, exporting results to temporary JSON."""
        if not self.is_installed():
            return [{
                "anomaly": "[ERROR] Nuclei is not installed on the system.", 
                "url": self.target_url, 
                "verified": False
            }]

        results = []
        # Create a temp file to hold JSON results since parsing stdout can be messy with nuclei's colors/banners
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp_file:
            tmp_path = tmp_file.name

        try:
            # -silent prevents terminal clutter, -json-export dumps structured logs
            cmd = [
                self.nuclei_path,
                "-u", self.target_url,
                "-silent",
                "-json-export", tmp_path
            ]
            
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)

            if os.path.exists(tmp_path):
                with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            finding = json.loads(line)
                            info = finding.get("info", {})
                            template_id = finding.get("template-id", "unknown")
                            name = info.get("name", "Nuclei Finding")
                            severity = info.get("severity", "info")
                            description = info.get("description", "No description provided.")
                            
                            results.append({
                                "url": finding.get("matched-at", self.target_url),
                                "payload": f"Nuclei Template: {template_id}",
                                "anomaly": f"[Nuclei - {severity.upper()}] {name}",
                                "response_snippet": str(finding.get("extracted-results", description)),
                                "verified": True,
                                "validation_proof": finding.get("curl-command", ""),
                                "evidence": {
                                    "source": "nuclei",
                                    "baseline_status": "Template Match",
                                    "delta_reason": "Matched predefined signature."
                                }
                            })
                        except json.JSONDecodeError:
                            continue

        except subprocess.TimeoutExpired:
             results.append({"anomaly": "[WARNING] Nuclei scan timed out after 5 minutes.", "url": self.target_url})
        except Exception as e:
             results.append({"anomaly": f"[ERROR] Nuclei execution failed: {str(e)}", "url": self.target_url})
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

        return results
