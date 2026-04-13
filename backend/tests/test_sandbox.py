from backend.sandbox import SandboxManager
import sys
import os

# Add parent dir to path so we can import backend.sandbox
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_sqli_vulnerable():
    print("Testing SQLi Vulnerable Code...")
    code = """
import sqlite3
import sys

def get_user(uid):
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'Admin')")
    
    # Vulnerable injection
    query = f"SELECT * FROM users WHERE id = {uid}"
    results = conn.execute(query).fetchall()
    print(f"Results: {results}")

if __name__ == "__main__":
    get_user(sys.argv[1])
"""
    # Payload that should trigger detection in our mocked sqlite3
    payload = "1 OR 1=1"
    sb = SandboxManager()
    is_success, msg = sb.verify_exploit(code, payload, "sql_injection")
    
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == True

def test_secure_code():
    print("\nTesting Secure Code...")
    code = """
import sqlite3
import sys

def get_user(uid):
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'Admin')")
    
    # SECURE: parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    results = conn.execute(query, (uid,)).fetchall()
    print(f"Results: {results}")

if __name__ == "__main__":
    get_user(sys.argv[1])
"""
    payload = "1 OR 1=1"
    sb = SandboxManager()
    is_success, msg = sb.verify_exploit(code, payload, "sql_injection")
    
    print(f"Exploit Success: {is_success}")
    print(f"Message: {msg}")
    assert is_success == False

if __name__ == "__main__":
    try:
        test_sqli_vulnerable()
        test_secure_code()
        print("\nALL sandbox tests passed!")
    except Exception as e:
        print(f"\nTest failed!")
        import traceback
        traceback.print_exc()
        sys.exit(1)
