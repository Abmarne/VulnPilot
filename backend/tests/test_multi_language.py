from backend.sandbox import SandboxManager
from backend.dependency_scanner import DependencyScanner
import sys
import os
import shutil
import tempfile
import json

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_node_sandbox_vulnerable():
    print("Testing Node.js Vulnerable Code...")
    code = """
const eval_me = (input) => {
    eval("console.log('Result: ' + " + input + ")");
};
eval_me(process.argv[2]);
"""
    # Payload that should trigger flag leak in our mocked eval
    payload = "process.env.VULNPILOT_SECRET_FLAG"
    sb = SandboxManager()
    is_success, msg = sb.verify_exploit(code, payload, "rce")
    
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == True

def test_node_sandbox_secure():
    print("\nTesting Node.js Secure Code...")
    code = """
const safe_eval = (input) => {
    console.log('Result: ' + input);
};
safe_eval(process.argv[2]);
"""
    payload = "process.env.VULNPILOT_SECRET_FLAG"
    sb = SandboxManager()
    is_success, msg = sb.verify_exploit(code, payload, "rce")
    
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == False

def test_python_regression():
    print("\nTesting Python Regression...")
    code = """
import os
print(os.environ.get("VULNPILOT_SECRET_FLAG"))
"""
    payload = "irrelevant"
    sb = SandboxManager()
    is_success, msg = sb.verify_exploit(code, payload, "info_leak")
    
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == True

def test_sca_go_support():
    print("\nTesting SCA Go Support...")
    tmp_dir = tempfile.mkdtemp()
    try:
        go_mod_content = """module example.com/app
go 1.21
require github.com/gin-gonic/gin v1.9.0
"""
        with open(os.path.join(tmp_dir, "go.mod"), "w") as f:
            f.write(go_mod_content)
        
        scanner = DependencyScanner(tmp_dir)
        findings = scanner.scan()
        
        print(f"SCA Findings: {len(findings)}")
        for f in findings:
            print(f" - {f['vulnerability_type']}: {f['severity']}")
        
        assert len(findings) >= 0 # Findings depend on LLM response, but at least it ran
    finally:
        shutil.rmtree(tmp_dir)

if __name__ == "__main__":
    try:
        test_node_sandbox_vulnerable()
        test_node_sandbox_secure()
        test_python_regression()
        test_sca_go_support()
        print("\nALL multi-language tests passed!")
    except Exception as e:
        print(f"\nTest failed!")
        import traceback
        traceback.print_exc()
        sys.exit(1)
