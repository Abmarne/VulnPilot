import os
import shutil
import tempfile
import subprocess
from pathlib import Path

class SastEngine:
    def __init__(self, codebase_path: str):
        self.raw_path = codebase_path
        self.is_github = codebase_path.startswith("http://github.com") or codebase_path.startswith("https://github.com")
        self.temp_dir = None
        self.target_dir = os.path.abspath(codebase_path)
        
    def prepare_codebase(self) -> str:
        """Clones if github, extracts if zip, otherwise validates local path."""
        if self.is_github:
            self.temp_dir = tempfile.mkdtemp(prefix="vulnpilot_sast_")
            print(f"[*] Cloning {self.raw_path} to {self.temp_dir}...")
            try:
                subprocess.run(["git", "clone", "--depth", "1", self.raw_path, self.temp_dir], check=True, capture_output=True)
                self.target_dir = os.path.abspath(self.temp_dir)
            except Exception as e:
                print(f"[!] Error cloning repository: {e}")
                return ""
        
        # Zip handling
        if self.raw_path.endswith(".zip") and os.path.exists(self.raw_path):
             import zipfile
             self.temp_dir = tempfile.mkdtemp(prefix="vulnpilot_zip_")
             print(f"[*] Extracting ZIP {self.raw_path} to {self.temp_dir}...")
             with zipfile.ZipFile(self.raw_path, 'r') as zip_ref:
                 zip_ref.extractall(self.temp_dir)
             self.target_dir = os.path.abspath(self.temp_dir)

        if not os.path.exists(self.target_dir):
            print(f"[!] Codebase path does not exist: {self.target_dir}")
            return ""
            
        print(f"[*] Codebase initialized at {self.target_dir}")
        return self.target_dir

    def _resolve_path(self, rel_path: str) -> str:
        if not self.target_dir or not rel_path:
            return ""

        root = Path(self.target_dir).resolve()
        candidate = (root / rel_path).resolve()

        try:
            candidate.relative_to(root)
            return str(candidate)
        except ValueError:
            return ""

    def extract_critical_files(self) -> str:
        """
        Extracts ALL React/Next.js source files into a concatenated string for LLM analysis.
        """
        code_context = ""
        if not self.target_dir:
            return code_context
            
        extensions_to_scan = ['.tsx', '.ts', '.js', '.jsx', '.env', '.py', '.yml', '.yaml', '.pem', '.key', '.json', '.xml']
        # Always include package.json but never lock files (huge, no vulns)
        include_filenames = {'package.json', 'requirements.txt', 'docker-compose.yml', 'Dockerfile', '.env.example', 'secrets.yaml', 'config.json'}
        exclude_filenames = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', '.gitignore'}
        max_files = 30 # Increased for better coverage
        files_scanned = 0
        
        print("[*] Extracting source files for SAST analysis...")
        
        found_files = []
        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in {
                'node_modules', '.git', '.next', '__pycache__', 'dist', 'build', '.turbo', 'venv', '.venv'
            }]
            for file in files:
                found_files.append(os.path.join(root, file))

        # Prioritize "Sensitive" files
        def score_file(path: str) -> int:
            name = os.path.basename(path).lower()
            if name.startswith(".env") or "secret" in name or "config" in name: return 0
            if name.endswith(".pem") or name.endswith(".key"): return 1
            if name in include_filenames: return 2
            return 10

        found_files.sort(key=score_file)

        for file_path in found_files:
            file = os.path.basename(file_path)
            is_included = file in include_filenames
            is_excluded = file in exclude_filenames
            has_ext = any(file.endswith(ext) for ext in extensions_to_scan)
            
            if is_excluded or (not is_included and not has_ext):
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                if not content.strip():
                    continue
                    
                rel_path = os.path.relpath(file_path, self.target_dir)
                code_context += f"\n\n--- FILE PATH: {rel_path} ---\n```\n{content[:2000]}\n```\n"
                files_scanned += 1
                # print(f"  [+] Queued: {rel_path}")
                    
            except Exception as e:
                print(f"  [!] Could not read {file_path}: {e}")
                    
            if files_scanned >= max_files:
                break
                
        print(f"[*] Extraction complete: {files_scanned} files queued for Gemini SAST analysis.")
        return code_context

    def get_file_content(self, rel_path: str) -> str:
        """Retrieves the full content of a specific file by its relative path."""
        if not self.target_dir:
            return ""
        
        file_path = self._resolve_path(rel_path)
        if not file_path or not os.path.exists(file_path):
            # Attempt to find it if AI didn't provide exact path
            for root, _, files in os.walk(self.target_dir):
                for f in files:
                    if f == os.path.basename(rel_path):
                        file_path = os.path.join(root, f)
                        break
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except:
            return ""

    def write_file_content(self, rel_path: str, new_content: str) -> bool:
        """Safely overwrites a file with new content (for auto-remediation)."""
        if not self.target_dir or not new_content:
            return False
            
        file_path = self._resolve_path(rel_path)
        if not file_path:
            print(f"[!] Refusing to write outside codebase root: {rel_path}")
            return False
        # Final directory path check
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"[*] Success: Applied security fix to {rel_path}")
            return True
        except Exception as e:
            print(f"[!] Write failed for {rel_path}: {e}")
            return False
        
    def cleanup(self):
        if self.is_github and self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
