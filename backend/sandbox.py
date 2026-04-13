import os
import sys
import json
import uuid
import tempfile
import subprocess
from typing import Any, Dict, Optional, Tuple

class SandboxManager:
    """
    Manages restricted execution of code snippets and payloads to verify vulnerabilities.
    Currently supports Python only.
    """

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self.flag = f"VULNPILOT_{uuid.uuid4().hex[:8].upper()}_FLAG"

    def verify_exploit(self, code: str, payload: str, vuln_type: str) -> Tuple[bool, str]:
        """
        Actually runs the code and payload to see if the vulnerability is triggered.
        Returns (success, message).
        """
        vuln_type = vuln_type.lower()
        
        # 1. Prepare the wrapper script
        wrapper_code = self._prepare_wrapper(code, payload, vuln_type)
        
        # 2. Run in a temporary file
        with tempfile.NamedTemporaryFile(suffix=".py", mode='w', delete=False) as tmp:
            tmp.write(wrapper_code)
            tmp_path = tmp.name

        try:
            # 3. Execute with restricted environment
            env = os.environ.copy()
            env["VULNPILOT_SECRET_FLAG"] = self.flag
            
            result = subprocess.run(
                [sys.executable, tmp_path],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env
            )
            
            output = (result.stdout + result.stderr).strip()
            
            # 4. Check results based on type
            is_success = self._detect_exploit(output, vuln_type)
            msg = f"Exploit Output:\n{output[:500]}"
            return is_success, msg

        except subprocess.TimeoutExpired:
            return False, "Execution timed out (Possible successful exploit via DoS or infinite loop, but not confirmed)."
        except Exception as e:
            return False, f"Sandbox error: {str(e)}"
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except:
                    pass

    def _prepare_wrapper(self, code: str, payload: str, vuln_type: str) -> str:
        """
        Injects the payload into the code and adds instrumentation.
        """
        # Common instrumentation and argument setup AT THE TOP
        instr_top = f"""
import os
import sys
import json
import builtins

# Setup detection markers
SECRET_FLAG = os.environ.get("VULNPILOT_SECRET_FLAG", "MISSING_FLAG")

# Provide CLI arguments in case the script expects them
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

# SQLi Detection (More robust)
try:
    import sqlite3
    orig_connect = sqlite3.connect
    
    class MockedCursor:
        def __init__(self, real_cursor):
            self.real_cursor = real_cursor
        def execute(self, query, *args):
            q_upper = str(query).upper()
            if any(p in q_upper for p in ["--", "1=1", "UNION SELECT", "SLEEP(", "OR 1=1"]):
                print(f"---VULNPILOT_SQLI_DETECTED--- {{query}}")
            return self.real_cursor.execute(query, *args)
        def __getattr__(self, name):
            return getattr(self.real_cursor, name)

    class MockedConn:
        def __init__(self, real_conn):
            self.real_conn = real_conn
        def cursor(self, *args, **kwargs):
            return MockedCursor(self.real_conn.cursor(*args, **kwargs))
        def execute(self, query, *args):
            q_upper = str(query).upper()
            if any(p in q_upper for p in ["--", "1=1", "UNION SELECT", "SLEEP(", "OR 1=1"]):
                print(f"---VULNPILOT_SQLI_DETECTED--- {{query}}")
            return self.real_conn.execute(query, *args)
        def __getattr__(self, name):
            return getattr(self.real_conn, name)

    def mocked_connect(*args, **kwargs):
        conn = orig_connect(*args, **kwargs)
        return MockedConn(conn)
    
    sqlite3.connect = mocked_connect
except ImportError:
    pass

# --- User Code ---
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
        
        # Heuristic detection for common fails
        if "command_injection" in vuln_type and ("uid=" in output or "root:" in output):
            return True
        
        return False
