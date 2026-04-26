import os
import shutil
import tempfile
import subprocess
from pathlib import Path

class SastEngine:
    def __init__(self, codebase_path: str, status_callback=None):
        self.raw_path = codebase_path
        self.is_github = codebase_path.startswith("http://github.com") or codebase_path.startswith("https://github.com")
        self.temp_dir = None
        self.target_dir = os.path.abspath(codebase_path)
        self._cached_context = None
        self.status_callback = status_callback
        
    def prepare_codebase(self) -> str:
        """Clones if github, extracts if zip, otherwise validates local path."""
        if self.is_github:
            self.temp_dir = tempfile.mkdtemp(prefix="vulnpilot_sast_")
            msg = f"[*] Cloning {self.raw_path} to {self.temp_dir}..."
            print(msg)
            if self.status_callback: self.status_callback(msg)
            try:
                subprocess.run(["git", "clone", "--depth", "1", self.raw_path, self.temp_dir], check=True, capture_output=True)
                self.target_dir = os.path.abspath(self.temp_dir)
            except Exception as e:
                err = f"[!] Error cloning repository: {e}"
                print(err)
                if self.status_callback: self.status_callback(err)
                return ""
        
        # Zip handling
        if self.raw_path.endswith(".zip") and os.path.exists(self.raw_path):
             import zipfile
             self.temp_dir = tempfile.mkdtemp(prefix="vulnpilot_zip_")
             msg = f"[*] Extracting ZIP {self.raw_path} to {self.temp_dir}..."
             print(msg)
             if self.status_callback: self.status_callback(msg)
             with zipfile.ZipFile(self.raw_path, 'r') as zip_ref:
                 zip_ref.extractall(self.temp_dir)
             self.target_dir = os.path.abspath(self.temp_dir)

        if not os.path.exists(self.target_dir):
            err = f"[!] Codebase path does not exist: {self.target_dir}"
            print(err)
            if self.status_callback: self.status_callback(err)
            return ""
            
        msg = f"[*] Codebase initialized at {self.target_dir}"
        print(msg)
        if self.status_callback: self.status_callback(msg)
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
        """Walks target_dir and collects content of relevant files."""
        if self._cached_context:
            print("[*] Extraction complete: (cached) files queued for SAST analysis.")
            return self._cached_context

        code_context = ""
        if not self.target_dir:
            return code_context
            
        extensions_to_scan = ['.tsx', '.ts', '.js', '.jsx', '.env', '.py', '.yml', '.yaml', '.pem', '.key', '.json', '.xml', '.sh', '.bash', '.config']
        include_filenames = {'package.json', 'requirements.txt', 'docker-compose.yml', 'Dockerfile', '.env.example', 'secrets.yaml', 'config.json', 'settings.py', 'main.py'}
        exclude_filenames = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', '.gitignore'}
        max_files = 10000 # Virtually unlimited for full repo coverage
        files_scanned = 0
        
        msg = "[*] Extracting source files for SAST analysis..."
        print(msg)
        if self.status_callback: self.status_callback(msg)

        for root, dirs, files in os.walk(self.target_dir):
            # Skip hidden dirs like .git
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if files_scanned >= max_files:
                    break
                    
                ext = os.path.splitext(file)[1].lower()
                if ext not in extensions_to_scan and file not in include_filenames:
                    continue
                if file in exclude_filenames:
                    continue
                    
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    rel_path = os.path.relpath(file_path, self.target_dir)
                    
                    # Update status for each file scanned
                    if self.status_callback:
                        self.status_callback(f"[*] Scanning: {rel_path}")
                    
                    # Cap total context at 100k chars to fit in standard LLM windows (Groq/Llama)
                    if len(code_context) + len(content) > 100000:
                         print(f"[*] Context limit reached (100k). Stopping extraction to preserve AI focus.")
                         break
                         
                    code_context += f"\n\n--- FILE PATH: {rel_path} ---\n```\n{content[:10000]}\n```\n"
                    files_scanned += 1
                        
                except Exception as e:
                    print(f"  [!] Could not read {file_path}: {e}")

        self._cached_context = code_context
        msg = f"[*] Extraction complete: {files_scanned} files queued for SAST analysis."
        print(msg)
        if self.status_callback: self.status_callback(msg)
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
