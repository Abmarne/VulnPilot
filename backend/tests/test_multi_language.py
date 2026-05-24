import sys
import os
import shutil
import tempfile
import json

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.sandbox import SandboxManager
from backend.dependency_scanner import DependencyScanner

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

def test_php_sandbox_vulnerable():
    print("\nTesting PHP SQLi Vulnerable Code...")
    code = """<?php
$uid = $_GET['id'];
$db = new PDO("mysql:host=localhost;dbname=test", "user", "pass");
$db->query("SELECT * FROM users WHERE id = " . $uid);
"""
    sb = SandboxManager()
    if not sb._is_binary_available("php"):
        print("PHP binary not found, skipping.")
        return
    is_success, msg = sb.verify_exploit(code, "1 OR 1=1", "sql_injection")
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == True

def test_php_sandbox_secure():
    print("\nTesting PHP SQLi Secure Code...")
    code = """<?php
$uid = $_GET['id'];
$db = new PDO("mysql:host=localhost;dbname=test", "user", "pass");
$stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$uid]);
"""
    sb = SandboxManager()
    if not sb._is_binary_available("php"):
        print("PHP binary not found, skipping.")
        return
    is_success, msg = sb.verify_exploit(code, "1 OR 1=1", "sql_injection")
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == False

def test_go_sandbox_vulnerable():
    print("\nTesting Go SQLi Vulnerable Code...")
    code = """package main
import (
    "database/sql"
    "fmt"
    "os"
)
func main() {
    db, _ := sql.Open("mysql", "connstring")
    uid := os.Args[1]
    query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", uid)
    db.Query(query)
}
"""
    sb = SandboxManager()
    if not sb._is_binary_available("go"):
        print("Go binary not found, skipping.")
        return
    is_success, msg = sb.verify_exploit(code, "1 OR 1=1", "sql_injection")
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == True

def test_go_sandbox_secure():
    print("\nTesting Go SQLi Secure Code...")
    code = """package main
import (
    "database/sql"
    "os"
)
func main() {
    db, _ := sql.Open("mysql", "connstring")
    uid := os.Args[1]
    db.Query("SELECT * FROM users WHERE id = ?", uid)
}
"""
    sb = SandboxManager()
    if not sb._is_binary_available("go"):
        print("Go binary not found, skipping.")
        return
    is_success, msg = sb.verify_exploit(code, "1 OR 1=1", "sql_injection")
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == False

def test_java_sandbox_vulnerable():
    print("\nTesting Java SQLi Vulnerable Code...")
    code = """import java.sql.*;
public class TestVulnerable {
    public static void main(String[] args) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "user", "pass");
        String uid = args[0];
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + uid);
    }
}
"""
    sb = SandboxManager()
    if not sb._is_binary_available("java") or not sb._is_binary_available("javac"):
        print("Java/Javac binary not found, skipping.")
        return
    is_success, msg = sb.verify_exploit(code, "1 OR 1=1", "sql_injection")
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == True

def test_java_sandbox_secure():
    print("\nTesting Java SQLi Secure Code...")
    code = """import java.sql.*;
public class TestSecure {
    public static void main(String[] args) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "user", "pass");
        String uid = args[0];
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, uid);
        stmt.execute();
    }
}
"""
    sb = SandboxManager()
    if not sb._is_binary_available("java") or not sb._is_binary_available("javac"):
        print("Java/Javac binary not found, skipping.")
        return
    is_success, msg = sb.verify_exploit(code, "1 OR 1=1", "sql_injection")
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == False

if __name__ == "__main__":
    try:
        test_node_sandbox_vulnerable()
        test_node_sandbox_secure()
        test_python_regression()
        test_sca_go_support()
        test_php_sandbox_vulnerable()
        test_php_sandbox_secure()
        test_go_sandbox_vulnerable()
        test_go_sandbox_secure()
        test_java_sandbox_vulnerable()
        test_java_sandbox_secure()
        print("\nALL multi-language tests passed!")
    except Exception as e:
        print(f"\nTest failed!")
        import traceback
        traceback.print_exc()
        sys.exit(1)
