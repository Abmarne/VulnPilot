import os
import shutil
import tempfile
import subprocess

class SastEngine:
    def __init__(self, codebase_path: str):
        self.raw_path = codebase_path
        self.is_github = codebase_path.startswith("http://github.com") or codebase_path.startswith("https://github.com")
        self.temp_dir = None
        self.target_dir = codebase_path
        
    def prepare_codebase(self) -> str:
        """Clones if github, otherwise validates local path."""
        if self.is_github:
            self.temp_dir = tempfile.mkdtemp(prefix="vulnpilot_sast_")
            print(f"[*] Cloning {self.raw_path} to {self.temp_dir}...")
            try:
                subprocess.run(["git", "clone", "--depth", "1", self.raw_path, self.temp_dir], check=True, capture_output=True)
                self.target_dir = self.temp_dir
            except Exception as e:
                print(f"[!] Error cloning repository: {e}")
                return ""
        
        if not os.path.exists(self.target_dir):
            print(f"[!] Codebase path does not exist: {self.target_dir}")
            return ""
            
        print(f"[*] Codebase initialized at {self.target_dir}")
        return self.target_dir

    def extract_critical_files(self) -> str:
        """
        Extracts key React/Next.js files into a concatenated string constraint.
        """
        code_context = ""
        if not self.target_dir:
            return code_context
            
        extensions_to_scan = ['.tsx', '.ts', '.js', '.jsx', '.json']
        max_files = 30 # Limit for context window safely
        files_scanned = 0
        
        print("[*] Performing static extraction of critical framework files...")
        
        for root, dirs, files in os.walk(self.target_dir):
            # Exclude node_modules and hidden git files
            dirs[:] = [d for d in dirs if not d.startswith('.') and 'node_modules' not in d]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions_to_scan):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            # Key indicators of potential risk in React stacks
                            keywords = ['use server', 'getServerSideProps', 'dangerouslySetInnerHTML', 'apiKey', 'password', 'query(', 'execute(']
                            if any(kw in content for kw in keywords) or file == "package.json":
                                rel_path = os.path.relpath(file_path, self.target_dir)
                                code_context += f"\n\n--- FILE PATH: {rel_path} ---\n```\n{content[:2500]}\n```\n"
                                files_scanned += 1
                                
                    except Exception:
                        pass
                        
                if files_scanned >= max_files:
                    break
            if files_scanned >= max_files:
                break
                
        print(f"[*] Extracted {files_scanned} critical files for SAST LLM context.")
        return code_context
        
    def cleanup(self):
        if self.is_github and self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
