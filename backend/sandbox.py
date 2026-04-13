import os
import sys
import json
import uuid
import tempfile
import subprocess
from typing import Any, Dict, Optional, Tuple

class SandboxManager:
    """
    Manages restricted execution of code snippets and payloads across multiple languages.
    Supported: Python, Node.js (JavaScript/TypeScript).
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.flag = f"VULNPILOT_{uuid.uuid4().hex[:8].upper()}_FLAG"

    def verify_exploit(self, code: str, payload: str, vuln_type: str) -> Tuple[bool, str]:
        """
        Detects language, prepares wrapper, and executes in the appropriate sandbox.
        """
        vuln_type = vuln_type.lower()
        
        # 1. Detect Language
        lang = self._detect_language(code)
        
        # 2. Prepare Wrapper & Filename
        if lang == "python":
            wrapper_code = self._prepare_python_wrapper(code, payload, vuln_type)
            suffix = ".py"
            cmd_prefix = [sys.executable]
        elif lang in ["javascript", "typescript"]:
            wrapper_code = self._prepare_node_wrapper(code, payload, vuln_type)
            suffix = ".ts" if lang == "typescript" or ".tsx" in code else ".js"
            # Use 'npx tsx' to handle JS/TS/TSX seamlessly
            cmd_prefix = ["npx", "tsx"]
        else:
            return False, f"Unsupported language for live verification: {lang}"

        # 3. Run in a temporary file
        with tempfile.NamedTemporaryFile(suffix=suffix, mode='w', delete=False, encoding='utf-8') as tmp:
            tmp.write(wrapper_code)
            tmp_path = tmp.name

        try:
            # 4. Execute with restricted environment
            env = os.environ.copy()
            env["VULNPILOT_SECRET_FLAG"] = self.flag
            # Minimal security: prevent network if possible (hard on Windows without complex tools)
            
            result = subprocess.run(
                cmd_prefix + [tmp_path],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
                shell=True
            )
            
            output = (result.stdout + result.stderr).strip()
            
            # 5. Check results
            is_success = self._detect_exploit(output, vuln_type)
            msg = f"[{lang.upper()} Sandbox] Output:\n{output[:500]}"
            return is_success, msg

        except subprocess.TimeoutExpired:
            return False, "Execution timed out (Possible exploit or infinite loop)."
        except Exception as e:
            return False, f"Sandbox error ({lang}): {str(e)}"
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except:
                    pass

    def _detect_language(self, code: str) -> str:
        """Heuristic to detect coding language from snippet."""
        code_clean = code.strip()
        
        # TypeScript / JavaScript indicators
        js_indicators = ["import ", "const ", "let ", "var ", "require(", "function ", "=>", "module.exports", "export "]
        ts_indicators = [": string", ": number", "interface ", "type ", "enum ", "<T>"]
        
        # Python indicators
        py_indicators = ["def ", "class ", "import os", "import sys", "print(", "elif ", "if __name__"]
        
        # Check for TS first (JSX/TSX often have these)
        if any(ind in code_clean for ind in ts_indicators):
            return "typescript"
            
        # Check for JS
        js_score = sum(1 for ind in js_indicators if ind in code_clean)
        py_score = sum(1 for ind in py_indicators if ind in code_clean)
        
        if js_score > py_score:
            return "javascript"
        return "python"

    def _prepare_python_wrapper(self, code: str, payload: str, vuln_type: str) -> str:
        """Original Python instrumentation."""
        instr_top = f"""
import os
import sys
import json
import builtins

# Setup detection markers
SECRET_FLAG = os.environ.get("VULNPILOT_SECRET_FLAG", "MISSING_FLAG")

# Provide CLI arguments
sys.argv = ["script.py", {json.dumps(payload)}]

# Set common injection variables
user_input = {json.dumps(payload)}

def exploit_success(reason):
    print(f"---VULNPILOT_SUCCESS--- {{reason}}")
    sys.exit(0)

# Mocking dangerous functions
orig_eval = builtins.eval
def mocked_eval(x):
    if str(SECRET_FLAG) in str(x): exploit_success("Evaluated secret flag")
    return orig_eval(x)
builtins.eval = mocked_eval

# SQLi Detection
try:
    import sqlite3
    orig_connect = sqlite3.connect
    class MockedCursor:
        def __init__(self, real_cursor): self.real_cursor = real_cursor
        def execute(self, query, *args):
            q_upper = str(query).upper()
            if any(p in q_upper for p in ["--", "1=1", "UNION SELECT", "OR 1=1"]):
                print(f"---VULNPILOT_SQLI_DETECTED--- {{query}}")
            return self.real_cursor.execute(query, *args)
        def __getattr__(self, name): return getattr(self.real_cursor, name)
    class MockedConn:
        def __init__(self, real_conn): self.real_conn = real_conn
        def cursor(self, *args, **kwargs): return MockedCursor(self.real_conn.cursor(*args, **kwargs))
        def execute(self, query, *args):
            q_upper = str(query).upper()
            if any(p in q_upper for p in ["--", "1=1", "UNION SELECT", "OR 1=1"]):
                print(f"---VULNPILOT_SQLI_DETECTED--- {{query}}")
            return self.real_conn.execute(query, *args)
        def __getattr__(self, name): return getattr(self.real_conn, name)
    def mocked_connect(*args, **kwargs): return MockedConn(orig_connect(*args, **kwargs))
    sqlite3.connect = mocked_connect
except ImportError:
    pass

# --- User Code ---
"""
        return instr_top + code

    def _prepare_node_wrapper(self, code: str, payload: str, vuln_type: str) -> str:
        """Node.js/TypeScript instrumentation."""
        instr_top = f"""
const os = require('os');
const fs = require('fs');

const SECRET_FLAG = process.env.VULNPILOT_SECRET_FLAG || "MISSING_FLAG";

// Inject CLI arguments
process.argv = ["node", "script.js", {json.dumps(payload)}];
const user_input = {json.dumps(payload)};

function exploit_success(reason) {{
    console.log(`---VULNPILOT_SUCCESS--- ${{reason}}`);
    process.exit(0);
}}

// Mocking eval
const orig_eval = global.eval;
global.eval = function(x) {{
    if (String(x).includes(SECRET_FLAG)) exploit_success("Evaluated secret flag");
    return orig_eval(x);
}};
"""
        return instr_top + code

    def _detect_exploit(self, output: str, vuln_type: str) -> bool:
        """Determines if the output indicates a successful exploit."""
        if "---VULNPILOT_SUCCESS---" in output:
            return True
        if "---VULNPILOT_SQLI_DETECTED---" in output:
            return True
        if self.flag in output:
            return True
        
        # Heuristic detection
        if ("command_injection" in vuln_type or "rce" in vuln_type):
            lower_out = output.lower()
            if any(x in lower_out for x in ["uid=", "root:", "nt authority\\system", "/etc/passwd"]):
                return True
        
        return False
