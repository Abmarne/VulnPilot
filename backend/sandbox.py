import os
import sys
import json
import uuid
import tempfile
import subprocess
import re
from typing import Any, Dict, Optional, Tuple

class SandboxManager:
    """
    Manages restricted execution of code snippets and payloads across multiple languages.
    Supported: Python, Node.js, Go, PHP, Java.
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.flag = f"VULNPILOT_{uuid.uuid4().hex[:8].upper()}_FLAG"

    def _is_binary_available(self, cmd: str) -> bool:
        """Checks if a binary command is available in the system PATH."""
        import shutil
        return shutil.which(cmd) is not None

    def verify_exploit(self, code: str, payload: str, vuln_type: str) -> Tuple[bool, str]:
        """
        Detects language, prepares wrapper, and executes in the appropriate sandbox.
        """
        vuln_type = vuln_type.lower()
        
        # 1. Detect Language
        lang = self._detect_language(code)
        
        # 2. Prepare Wrapper & Run Command
        tmpdir = None
        tmp_path = None
        cleanup_paths = []
        cwd = None
        
        try:
            if lang == "python":
                wrapper_code = self._prepare_python_wrapper(code, payload, vuln_type)
                suffix = ".py"
                with tempfile.NamedTemporaryFile(suffix=suffix, mode='w', delete=False, encoding='utf-8') as tmp:
                    tmp.write(wrapper_code)
                    tmp_path = tmp.name
                cmd = [sys.executable, tmp_path]
                cleanup_paths.append(tmp_path)
                
            elif lang in ["javascript", "typescript"]:
                wrapper_code = self._prepare_node_wrapper(code, payload, vuln_type)
                suffix = ".ts" if lang == "typescript" or ".tsx" in code else ".js"
                with tempfile.NamedTemporaryFile(suffix=suffix, mode='w', delete=False, encoding='utf-8') as tmp:
                    tmp.write(wrapper_code)
                    tmp_path = tmp.name
                cmd = ["npx", "tsx", tmp_path]
                cleanup_paths.append(tmp_path)
                
            elif lang == "php":
                if not self._is_binary_available("php"):
                    return False, "PHP CLI ('php') is not installed or not in PATH."
                wrapper_code = self._prepare_php_wrapper(code, payload, vuln_type)
                with tempfile.NamedTemporaryFile(suffix=".php", mode='w', delete=False, encoding='utf-8') as tmp:
                    tmp.write(wrapper_code)
                    tmp_path = tmp.name
                cmd = ["php", tmp_path]
                cleanup_paths.append(tmp_path)
                
            elif lang == "go":
                if not self._is_binary_available("go"):
                    return False, "Go CLI ('go') is not installed or not in PATH."
                tmpdir = tempfile.mkdtemp()
                main_path = os.path.join(tmpdir, "main.go")
                helper_path = os.path.join(tmpdir, "helper.go")
                
                main_code, helper_code = self._prepare_go_wrapper(code, payload, vuln_type)
                with open(main_path, "w", encoding="utf-8") as f:
                    f.write(main_code)
                with open(helper_path, "w", encoding="utf-8") as f:
                    f.write(helper_code)
                    
                cmd = ["go", "run", "main.go", "helper.go"]
                cwd = tmpdir
                
            elif lang == "java":
                if not self._is_binary_available("java") or not self._is_binary_available("javac"):
                    return False, "Java JDK ('java' and 'javac') is not installed or not in PATH."
                
                # Dynamic Class & Package resolution
                public_class_match = re.search(r'public\s+class\s+(\w+)', code)
                if public_class_match:
                    class_name = public_class_match.group(1)
                else:
                    class_match = re.search(r'class\s+(\w+)', code)
                    if class_match:
                        class_name = class_match.group(1)
                    else:
                        class_name = "Main"
                        code = f"public class Main {{\npublic static void main(String[] args) {{\n{code}\n}}\n}}"
                
                package_match = re.search(r'package\s+([a-zA-Z0-9_\.]+);', code)
                package_prefix = package_match.group(1) if package_match else None
                
                tmpdir = tempfile.mkdtemp()
                
                if package_prefix:
                    pkg_dir = os.path.join(tmpdir, *package_prefix.split('.'))
                    os.makedirs(pkg_dir, exist_ok=True)
                else:
                    pkg_dir = tmpdir
                    
                main_path = os.path.join(pkg_dir, f"{class_name}.java")
                driver_path = os.path.join(pkg_dir, "MockDriver.java")
                
                main_code, driver_code = self._prepare_java_wrapper(code, payload, vuln_type, package_prefix, class_name)
                
                with open(main_path, "w", encoding="utf-8") as f:
                    f.write(main_code)
                with open(driver_path, "w", encoding="utf-8") as f:
                    f.write(driver_code)
                
                rel_main = os.path.relpath(main_path, tmpdir)
                rel_driver = os.path.relpath(driver_path, tmpdir)
                
                compile_res = subprocess.run(
                    ["javac", rel_main, rel_driver],
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                    cwd=tmpdir,
                    shell=True
                )
                if compile_res.returncode != 0:
                    return False, f"Java compilation error:\n{compile_res.stderr}"
                    
                full_class_name = f"{package_prefix}.{class_name}" if package_prefix else class_name
                cmd = ["java", "-cp", ".", full_class_name, payload]
                cwd = tmpdir
                
            else:
                return False, f"Unsupported language for live verification: {lang}"
                
            # 3. Execute with restricted environment
            env = os.environ.copy()
            env["VULNPILOT_SECRET_FLAG"] = self.flag
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
                cwd=cwd,
                shell=True
            )
            
            output = (result.stdout + result.stderr).strip()
            is_success = self._detect_exploit(output, vuln_type)
            msg = f"[{lang.upper()} Sandbox] Output:\n{output[:500]}"
            return is_success, msg

        except subprocess.TimeoutExpired:
            return False, "Execution timed out (Possible exploit or infinite loop)."
        except Exception as e:
            return False, f"Sandbox error ({lang}): {str(e)}"
        finally:
            for path in cleanup_paths:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except:
                        pass
            if tmpdir and os.path.exists(tmpdir):
                import shutil
                try:
                    shutil.rmtree(tmpdir)
                except:
                    pass

    def _detect_language(self, code: str) -> str:
        """Heuristic to detect coding language from snippet."""
        code_clean = code.strip()
        
        # Explicit/Strong indicators
        if "<?php" in code_clean or "<?=" in code_clean:
            return "php"
        if "package main" in code_clean or "func main(" in code_clean:
            return "go"
        if "public static void main" in code_clean or "System.out.println" in code_clean:
            return "java"
            
        # TypeScript / JavaScript indicators
        js_indicators = ["import ", "const ", "let ", "var ", "require(", "function ", "=>", "module.exports", "export "]
        ts_indicators = [": string", ": number", "interface ", "type ", "enum ", "<T>"]
        
        # Python indicators
        py_indicators = ["def ", "class ", "import os", "import sys", "print(", "elif ", "if __name__"]
        
        # Go indicators
        go_indicators = ["package ", "func ", "import (", "go.mod"]
        
        # PHP indicators
        php_indicators = ["$this->", "$argv", "$_GET", "$_POST", "$_REQUEST"]
        
        # Java indicators
        java_indicators = ["public class ", "class ", "import java."]

        # Check for TS first (JSX/TSX often have these)
        if any(ind in code_clean for ind in ts_indicators):
            return "typescript"
            
        # Fallback to scores
        scores = {
            "javascript": sum(1 for ind in js_indicators if ind in code_clean),
            "python": sum(1 for ind in py_indicators if ind in code_clean),
            "go": sum(1 for ind in go_indicators if ind in code_clean),
            "php": sum(1 for ind in php_indicators if ind in code_clean),
            "java": sum(1 for ind in java_indicators if ind in code_clean)
        }
        
        detected = max(scores, key=scores.get)
        if scores[detected] > 0:
            return detected
            
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

    def _prepare_php_wrapper(self, code: str, payload: str, vuln_type: str) -> str:
        """PHP PDO/mysqli mocking and environment setup."""
        instr = f"""
// Setup detection markers
$SECRET_FLAG = getenv("VULNPILOT_SECRET_FLAG") ?: "MISSING_FLAG";

// Inject inputs into common sources
$user_input = {json.dumps(payload)};
$_GET['input'] = $user_input;
$_POST['input'] = $user_input;
$_REQUEST['input'] = $user_input;
$_GET['id'] = $user_input;
$_POST['id'] = $user_input;
$_REQUEST['id'] = $user_input;

// Override argv for CLI scripts
$argv = ['script.php', $user_input];
$argc = 2;

function exploit_success($reason) {{
    echo "---VULNPILOT_SUCCESS--- " . $reason . "\\n";
    exit(0);
}}

// Mocked PDO
class MockedPDOStatement {{
    private $query;
    public function __construct($query) {{
        $this->query = $query;
    }}
    public function execute($params = null) {{
        $q = strtoupper($this->query);
        if (preg_match('/--|1=1|UNION SELECT|OR 1=1/i', $q)) {{
            echo "---VULNPILOT_SQLI_DETECTED--- " . $this->query . "\\n";
        }}
        return true;
    }}
    public function fetch($fetch_style = null, $cursor_orientation = null, $cursor_offset = null) {{
        return [];
    }}
    public function fetchAll($mode = null, ...$args) {{
        return [];
    }}
}}

class MockedPDO {{
    public function __construct($dsn, $username = null, $password = null, $options = null) {{}}
    public function query($query, $fetchMode = null, ...$fetchModeArgs) {{
        $q = strtoupper($query);
        if (preg_match('/--|1=1|UNION SELECT|OR 1=1/i', $q)) {{
            echo "---VULNPILOT_SQLI_DETECTED--- " . $query . "\\n";
        }}
        return new MockedPDOStatement($query);
    }}
    public function prepare($query, $options = []) {{
        return new MockedPDOStatement($query);
    }}
    public function exec($statement) {{
        $q = strtoupper($statement);
        if (preg_match('/--|1=1|UNION SELECT|OR 1=1/i', $q)) {{
            echo "---VULNPILOT_SQLI_DETECTED--- " . $statement . "\\n";
        }}
        return 1;
    }}
}}

// Mocked mysqli
class MockedMysqliStmt {{
    private $query;
    public function __construct($query) {{
        $this->query = $query;
    }}
    public function bind_param($types, &...$vars) {{ return true; }}
    public function execute() {{
        $q = strtoupper($this->query);
        if (preg_match('/--|1=1|UNION SELECT|OR 1=1/i', $q)) {{
            echo "---VULNPILOT_SQLI_DETECTED--- " . $this->query . "\\n";
        }}
        return true;
    }}
    public function get_result() {{ return new MockedMysqliResult(); }}
}}

class MockedMysqliResult {{
    public function fetch_assoc() {{ return null; }}
    public function fetch_all($mode = null) {{ return []; }}
}}

class MockedMysqli {{
    public $connect_error = null;
    public $connect_errno = 0;
    public function __construct($host = null, $username = null, $passwd = null, $dbname = null, $port = null, $socket = null) {{}}
    public function query($query, $resultmode = null) {{
        $q = strtoupper($query);
        if (preg_match('/--|1=1|UNION SELECT|OR 1=1/i', $q)) {{
            echo "---VULNPILOT_SQLI_DETECTED--- " . $query . "\\n";
        }}
        return true;
    }}
    public function prepare($query) {{
        return new MockedMysqliStmt($query);
    }}
}}

if (!function_exists('mysqli_connect')) {{
    function mysqli_connect($host = null, $username = null, $passwd = null, $dbname = null, $port = null, $socket = null) {{
        return new MockedMysqli();
    }}
}}

if (!function_exists('mysqli_query')) {{
    function mysqli_query($link, $query, $resultmode = null) {{
        return $link->query($query, $resultmode);
    }}
}}
"""
        code_rewritten = code
        # Class and method invocation rewrites for mocking
        code_rewritten = re.sub(r'new\s+\\?PDO\s*\(', 'new MockedPDO(', code_rewritten)
        code_rewritten = re.sub(r'\\?PDO::', 'MockedPDO::', code_rewritten)
        code_rewritten = re.sub(r'new\s+\\?mysqli\s*\(', 'new MockedMysqli(', code_rewritten)
        code_rewritten = re.sub(r'mysqli_connect\s*\(', 'mysqli_connect(', code_rewritten)
        code_rewritten = re.sub(r'mysqli_query\s*\(', 'mysqli_query(', code_rewritten)

        # Insert instrumentation after the first <?php tag
        if re.search(r'<\?php', code_rewritten, re.IGNORECASE):
            code_rewritten = re.sub(r'<\?php', '<?php\n' + instr, code_rewritten, count=1, flags=re.IGNORECASE)
        else:
            code_rewritten = "<?php\n" + instr + "\n" + code_rewritten

        return code_rewritten

    def _prepare_go_wrapper(self, code: str, payload: str, vuln_type: str) -> Tuple[str, str]:
        """Prepares Go files for compilation and execution."""
        code_rewritten = code
        # Rewrite database connections to mock
        code_rewritten = re.sub(r'sql\.Open\s*\(\s*["\'](mysql|postgres|sqlite3|sqlite|mssql|oracle)["\']', 'sql.Open("mock_sql"', code_rewritten)
        
        # Replace common driver imports
        code_rewritten = re.sub(r'["\']github\.com/go-sql-driver/mysql["\']', '"database/sql/driver"', code_rewritten)
        code_rewritten = re.sub(r'["\']github\.com/lib/pq["\']', '"database/sql/driver"', code_rewritten)
        code_rewritten = re.sub(r'["\']github\.com/mattn/go-sqlite3["\']', '"database/sql/driver"', code_rewritten)
        
        # Ensure package main is set
        if "package " in code_rewritten:
            code_rewritten = re.sub(r'package\s+\w+', 'package main', code_rewritten, count=1)
        else:
            code_rewritten = "package main\n" + code_rewritten

        helper_code = f"""package main

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"os"
)

type MockDriver struct{{}}

func (d MockDriver) Open(name string) (driver.Conn, error) {{
	return MockConn{{}}, nil
}}

type MockConn struct{{}}

func (c MockConn) Prepare(query string) (driver.Stmt, error) {{
	return MockStmt{{query: query}}, nil
}}

func (c MockConn) Close() error {{
	return nil
}}

func (c MockConn) Begin() (driver.Tx, error) {{
	return MockTx{{}}, nil
}}

type MockStmt struct {{
	query string
}}

func (s MockStmt) Close() error {{
	return nil
}}

func (s MockStmt) NumInput() int {{
	return -1
}}

func (s MockStmt) Exec(args []driver.Value) (driver.Result, error) {{
	detectSQLi(s.query)
	return MockResult{{}}, nil
}}

func (s MockStmt) Query(args []driver.Value) (driver.Rows, error) {{
	detectSQLi(s.query)
	return MockRows{{}}, nil
}}

type MockResult struct{{}}

func (r MockResult) LastInsertId() (int64, error) {{ return 0, nil }}
func (r MockResult) RowsAffected() (int64, error) {{ return 0, nil }}

type MockRows struct{{}}

func (r MockRows) Columns() []string              {{ return []string{{}} }}
func (r MockRows) Close() error                   {{ return nil }}
func (r MockRows) Next(dest []driver.Value) error {{ return fmt.Errorf("EOF") }}

type MockTx struct{{}}

func (t MockTx) Commit() error   {{ return nil }}
func (t MockTx) Rollback() error {{ return nil }}

func detectSQLi(query string) {{
	qUpper := strings.ToUpper(query)
	if strings.Contains(qUpper, "--") || strings.Contains(qUpper, "1=1") || strings.Contains(qUpper, "UNION SELECT") || strings.Contains(qUpper, "OR 1=1") {{
		fmt.Println("---VULNPILOT_SQLI_DETECTED---", query)
	}}
}}

func init() {{
	// Override os.Args to inject payload
	os.Args = []string{{"main.go", {json.dumps(payload)}}}
	
	// Register driver
	sql.Register("mock_sql", MockDriver{{}})
}}
"""
        return code_rewritten, helper_code

    def _prepare_java_wrapper(self, code: str, payload: str, vuln_type: str, package_prefix: Optional[str], class_name: str) -> Tuple[str, str]:
        """Prepares Java files for compilation and execution."""
        code_rewritten = code
        # Replace JDBC connection URLs
        code_rewritten = re.sub(r'jdbc:[a-zA-Z0-9_:\.-]+', 'jdbc:mock:', code_rewritten)
        # Remove common database driver registration class.forName calls
        code_rewritten = re.sub(r'Class\.forName\s*\(\s*["\'](com\.mysql\.cj\.jdbc\.Driver|org\.postgresql\.Driver|org\.sqlite\.JDBC|com\.mysql\.jdbc\.Driver)["\']\s*\)', 'Class.forName("MockDriver")', code_rewritten)
        
        # Package statement header
        package_stmt = f"package {package_prefix};\n" if package_prefix else ""
        
        driver_code = f"""{package_stmt}
import java.sql.*;
import java.util.Properties;
import java.util.logging.Logger;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

class MockDriver implements Driver {{
    static {{
        try {{
            DriverManager.registerDriver(new MockDriver());
        }} catch (SQLException e) {{
            e.printStackTrace();
        }}
    }}

    public Connection connect(String url, Properties info) throws SQLException {{
        if (!acceptsURL(url)) return null;
        return createProxy(Connection.class, new ConnectionHandler());
    }}

    public boolean acceptsURL(String url) throws SQLException {{
        return url != null && url.startsWith("jdbc:mock");
    }}

    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {{
        return new DriverPropertyInfo[0];
    }}

    public int getMajorVersion() {{ return 1; }}
    public int getMinorVersion() {{ return 0; }}
    public boolean jdbcCompliant() {{ return true; }}
    public Logger getParentLogger() throws SQLFeatureNotSupportedException {{
        throw new SQLFeatureNotSupportedException();
    }}

    @SuppressWarnings("unchecked")
    private static <T> T createProxy(Class<T> interfaceClass, InvocationHandler handler) {{
        return (T) Proxy.newProxyInstance(
            interfaceClass.getClassLoader(),
            new Class<?>[]{{interfaceClass}},
            handler
        );
    }}

    static class ConnectionHandler implements InvocationHandler {{
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {{
            String methodName = method.getName();
            if (methodName.equals("prepareStatement") || methodName.equals("prepareCall")) {{
                String sql = (String) args[0];
                return createProxy(PreparedStatement.class, new StatementHandler(sql));
            } else if (methodName.equals("createStatement")) {{
                return createProxy(Statement.class, new StatementHandler(null));
            } else if (methodName.equals("close") || methodName.equals("isClosed")) {{
                return false;
            }}
            return null;
        }}
    }}

    static class StatementHandler implements InvocationHandler {{
        private String sql;
        public StatementHandler(String sql) {{
            this.sql = sql;
        }}

        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {{
            String methodName = method.getName();
            String currentSql = this.sql;
            if (methodName.startsWith("execute")) {{
                if (args != null && args.length > 0 && args[0] instanceof String) {{
                    currentSql = (String) args[0];
                }}
                if (currentSql != null) {{
                    String qUpper = currentSql.toUpperCase();
                    if (qUpper.contains("--") || qUpper.contains("1=1") || qUpper.contains("UNION SELECT") || qUpper.contains("OR 1=1")) {{
                        System.out.println("---VULNPILOT_SQLI_DETECTED--- " + currentSql);
                    }}
                }}
                if (methodName.equals("executeQuery")) {{
                    return createProxy(ResultSet.class, new ResultSetHandler());
                }}
                return true;
            } else if (methodName.equals("close") || methodName.equals("isClosed")) {{
                return false;
            }}
            return null;
        }}
    }}

    static class ResultSetHandler implements InvocationHandler {{
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {{
            if (method.getName().equals("next")) return false;
            return null;
        }}
    }}
}}
"""
        return code_rewritten, driver_code

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
