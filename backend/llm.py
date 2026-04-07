from google import genai
from groq import Groq
import os
import json
import time
from typing import List, Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ── Provider Selection ──────────────────────────────────────────────────────
GROQ_API_KEY    = os.environ.get("GROQ_API_KEY", "")
GEMINI_API_KEY  = os.environ.get("GOOGLE_API_KEY", "")

# Initialize Gemini Client (New SDK)
gemini_client = None
if GEMINI_API_KEY:
    gemini_client = genai.Client(api_key=GEMINI_API_KEY)

# Initialize Groq if available
groq_client = None
if GROQ_API_KEY and GROQ_API_KEY != "PASTE_YOUR_GROQ_KEY_HERE":
    groq_client = Groq(api_key=GROQ_API_KEY)

def _call_llm(prompt: str) -> str:
    """Try Gemini first; if it fails, fallback to Groq."""
    
    # 1. Try Gemini
    if gemini_client:
        try:
            print("[LLM] Attempting Gemini (gemini-2.0-flash)...")
            response = gemini_client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt
            )
            return response.text
        except Exception as e:
            print(f"[!] Gemini failed: {e}")
    else:
        print("[!] Gemini client not initialized.")
    
    # 2. Fallback to Groq
    if groq_client:
        print("[LLM] Falling back to Groq (llama-3.3-70b)...")
        try:
            response = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=4096,
            )
            return response.choices[0].message.content
        except Exception as ge:
            print(f"[!!] Groq fallback also failed: {ge}")
    else:
        print("[!] Groq not configured for fallback.")
    
    raise Exception("All LLM providers failed.")

# Alias for backward compat
_call_gemini = _call_llm



def _parse_gemini_json(text: str) -> list:
    """Cleans and parses Gemini JSON output reliably, handling escaping issues."""
    import re
    text = text.strip()
    # Remove markdown code blocks
    text = re.sub(r'^```(?:json)?', '', text)
    text = re.sub(r'```$', '', text)
    text = text.strip()
    
    try:
        # Try strict first
        parsed = json.loads(text)
    except json.JSONDecodeError:
        try:
            # Try lenient mode (handles some unescaped control characters)
            parsed = json.loads(text, strict=False)
        except json.JSONDecodeError:
            # Emergency fix: Escape backslashes that aren't already escaped or part of a valid escape
            # This is common in Windows paths like C:\Users
            repaired_text = re.sub(r'(?<!\\)\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', r'\\\\', text)
            try:
                parsed = json.loads(repaired_text, strict=False)
            except json.JSONDecodeError:
                # Last resort: extract JSON array
                start = text.find("[")
                end = text.rfind("]") + 1
                if start != -1 and end > start:
                    try:
                        parsed = json.loads(text[start:end], strict=False)
                    except:
                        return []
                else:
                    # Maybe it's a single object?
                    start = text.find("{")
                    end = text.rfind("}") + 1
                    if start != -1 and end > start:
                        try:
                            parsed = json.loads(text[start:end], strict=False)
                        except:
                            return []
                    else:
                        return []

    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return parsed
    return []


def generate_fuzzing_payloads(target_urls: List[str]) -> List[str]:
    """Uses LLM to dynamically generate benign testing payloads."""
    prompt = f"""
    You are an expert security engineer building a DAST tool.
    Generate 10 highly effective, BENIGN testing payloads for these endpoints:
    {target_urls}

    Payloads should safely trigger database errors, 500 errors, or reflections.
    Do NOT generate shell exploits or data-destroying payloads.

    Respond ONLY as a valid JSON array of strings. No markdown, no text outside the array.
    Example: ["' OR 1=1 --", "<script>alert(1)</script>", "../../../../etc/passwd"]
    """
    try:
        print("[*] Asking LLM to craft custom fuzzing payloads...")
        text = _call_llm(prompt)
        # Use our safe parser which handles markdown and cleaning
        raw_payloads = _parse_gemini_json(text)
        
        # Ensure we only return a list of strings to avoid type-mismatch crashes in the fuzzer
        clean_payloads = []
        for p in raw_payloads:
            if isinstance(p, str):
                clean_payloads.append(p)
            elif isinstance(p, dict):
                # If LLM returned a list of dicts, try to extract the likely payload field
                val = next(iter(p.values()), str(p))
                clean_payloads.append(str(val))
            else:
                clean_payloads.append(str(p))
        
        if clean_payloads:
            return clean_payloads
            
    except Exception as e:
        print(f"[!] LLM Payload Generation failed: {e}. Using defaults.")

    return [
        "' OR 1=1 --",
        "\" OR 1=1 --",
        "<script>alert('VulnPilot')</script>",
        "../../../../../../../../etc/passwd",
        "`; sleep 3; `",
        "A" * 500
    ]


def identify_sinks(code_context: str) -> List[Dict[str, Any]]:
    """Analyzes source code to find 'Sinks' (vulnerable functions) and their parameters."""
    if not code_context:
        return []

    prompt = f"""
    You are an expert security code auditor. Analyze this source code to find dangerous 'Sinks' 
    (parts of the code that handle user input unsafely).
    
    Find occurrences of:
    - Raw SQL queries (SQLi)
    - System command execution (RCE)
    - User input reflected in HTML (XSS)
    - File system access (LFI/Path Traversal)
    - Unauthenticated API routes
    
    SOURCE CODE:
    {code_context}
    
    Respond ONLY as a valid JSON array of objects (no markdown, no extra text):
    [
      {{
        "url_pattern": "e.g. /api/search",
        "param": "e.g. q",
        "vulnerability_type": "sql_injection | command_injection | xss | path_traversal",
        "sink_line": "The exact code line where the sink is",
        "required_context": ["list", "of", "relative", "paths", "to", "imported", "files", "e.g.", "utils/db.js"]
      }}
    ]
    """
    try:
        print("[*] Identifying potential sinks in source code with LLM...")
        text = _call_llm(prompt)
        sinks = _parse_gemini_json(text)
        return sinks if isinstance(sinks, list) else []
    except Exception as e:
        print(f"[!] Sink identification failed: {e}")
        return []


def reconstruct_api_schema(js_content: str) -> List[Dict[str, Any]]:
    """Analyzes client-side JS to find hidden API endpoints and their parameters."""
    if not js_content or len(js_content) < 50:
        return []

    prompt = f"""
    You are an expert security engineer reverse-engineering a web application.
    Analyze the following JavaScript code to find ALL internal API endpoints it communicates with.
    
    Look for:
    - fetch(), axios(), $.ajax(), XMLHttpRequest calls
    - URL strings that look like API routes (e.g., /api/v1/user)
    - Query parameters, POST body fields, or JSON keys used in these requests
    - Custom headers (e.g., X-Auth-Token)
    
    JAVASCRIPT CODE:
    {js_content[:15000]} # Limit context to avoid token bloat
    
    Respond ONLY as a valid JSON array of objects (no markdown, no extra text):
    [
      {{
        "url": "the full or relative path discovered",
        "method": "GET | POST | PUT | DELETE",
        "params": ["list", "of", "query", "params"],
        "form_fields": ["list", "of", "POST", "body", "fields", "or", "JSON", "keys"]
      }}
    ]
    """
    try:
        print("[*] Reconstructing API surface from JavaScript with LLM...")
        text = _call_llm(prompt)
        endpoints = _parse_gemini_json(text)
        return endpoints if isinstance(endpoints, list) else []
    except Exception as e:
        print(f"[!] API reconstruction failed: {e}")
        return []


def deep_taint_audit(vulnerability_chain: Dict[str, Any], extra_context: str) -> Dict[str, Any]:
    """Performs a high-confidence audit across multiple files to verify a taint path."""
    if not extra_context:
        return vulnerability_chain

    prompt = f"""
    You are an elite security researcher performs a multi-file 'Taint Analysis'.
    
    INITIAL FINDING:
    - Type: {vulnerability_chain.get('vulnerability_type')}
    - Sink: {vulnerability_chain.get('sink_line')}
    - Context: {vulnerability_chain.get('explanation', 'N/A')}
    
    DEEP CONTEXT (Found in imported/dependent files):
    {extra_context[:20000]}
    
    TASK:
    1. Determine if the 'Taint' (user input) is properly sanitized in the DEEP CONTEXT files.
    2. If a sanitizer like 'mysql.escape()' or 'DOMPurify.sanitize()' is used effectively, 
       this is a FALSE POSITIVE.
    3. If no sanitization exists or it is bypassed, this is a VERIFIED CRITICAL BUG.
    
    Respond as a single JSON object:
    {{
      "is_verified": "boolean: true if bug is proven through cross-file check",
      "verdict": "Verified | False Positive | Suspicious",
      "explanation": "Detailed explanation of the multi-file flow.",
      "remediation_code": "Corrected versions of ALL involved files."
    }}
    """
    try:
        print(f"[*] Auditing Taint Chain for {vulnerability_chain.get('url_pattern')}...")
        text = _call_llm(prompt)
        verdict_list = _parse_gemini_json(text)
        if verdict_list and isinstance(verdict_list[0], dict):
            return verdict_list[0]
    except Exception as e:
        print(f"[!] Taint audit failed: {e}")
    
    return {}


def get_refactored_file(original_code: str, vulnerability_details: Dict[str, Any]) -> str:
    """Uses LLM to refactor an entire source file to fix a specific security bug."""
    if not original_code:
        return ""

    prompt = f"""
    You are an expert security engineer performing a 'Secure Code Refactor'.
    
    VULNERABILITY TO FIX:
    - Type: {vulnerability_details.get('vulnerability_type')}
    - Risk: {vulnerability_details.get('explanation')}
    - Suggested Fix: {vulnerability_details.get('remediation_code')}
    
    ORIGINAL SOURCE CODE:
    ```
    {original_code}
    ```
    
    TASK:
    1. Rewrite the entire file above to eliminate the security vulnerability.
    2. DO NOT change any unrelated logic, function names, or application behavior.
    3. PRESERVE all comments, variable names, and stylistic formatting where possible.
    4. Ensure the output is syntactically valid and ready to be saved to disk.
    
    Respond ONLY with the complete, refactored source code. No markdown, no introductory text, no explanations. Just the code.
    """
    try:
        print(f"[*] AI is refactoring file to fix {vulnerability_details.get('vulnerability_type')}...")
        text = _call_llm(prompt)
        # Cleanup any accidental markdown markers
        import re
        text = re.sub(r'^```[a-zA-Z]*\n', '', text)
        text = re.sub(r'\n```$', '', text)
        return text.strip()
    except Exception as e:
        print(f"[!] AI refactoring failed: {e}")
        return ""


def analyze_anomalies(anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyzes fuzzer DAST anomalies with LLM."""
    analyzed_results = []
    if not anomalies:
        return analyzed_results

    for anomaly in anomalies:
        prompt = f"""
        You are an expert Penetration Tester. Analyze this DAST anomaly.

        Target URL: {anomaly['url']}
        Payload Used: {anomaly['payload']}
        Fuzzer Finding: {anomaly['anomaly']}
        Is Verified (Double-Blind Test Passed): {anomaly.get('verified', False)}
        Validation Proof Detail: {anomaly.get('validation_proof', 'N/A')}
        Server Response Snippet:
        {anomaly['response_snippet']}

        Respond as a single JSON object (no markdown, no extra text):
        {{
          "vulnerability_type": "e.g. SQL Injection",
          "severity": "Low|Medium|High|Critical",
          "explanation": "2-sentence explanation of the risk.",
          "manual_poc": "Step-by-step manual verification and validation.",
          "poc_script": "A copy-pasteable Python or Curl script to reproduce the vulnerability (safely).",
          "remediation_code": "The SECURE version of the code that fixes this bug (e.g. using parameterized queries).",
          "remediation_steps": "Step-by-step resolution plan for developers (and 3rd party tools).",
          "is_verified": "boolean: true if the fuzzer logically proved this bug"
        }}
        """
        try:
            print(f"[*] Analyzing DAST anomaly on {anomaly['url']} with LLM...")
            text = _call_llm(prompt)
            analysis_list = _parse_gemini_json(text)
            if analysis_list and isinstance(analysis_list[0], dict):
                analysis = analysis_list[0]
                analyzed_results.append({**anomaly, **analysis})
            else:
                raise ValueError("LLM did not return a valid analysis object.")
        except Exception as e:
            print(f"[!] LLM API error: {e}")
            analyzed_results.append({
                **anomaly,
                "vulnerability_type": "Analysis Error",
                "severity": "Unknown",
                "explanation": str(e)[:200],
                "manual_poc": "Check backend logs for raw server response."
            })

    return analyzed_results


def _analyze_file_batch(file_blocks: List[str], anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sends a batch of up to 5 files to Gemini in a single API call."""
    dast_context = json.dumps(anomalies[:3], indent=2) if anomalies else "None"
    combined = "\n\n".join(file_blocks)

    prompt = f"""
    You are an aggressive penetration tester performing a thorough security audit.
    Analyze ALL source code files below. Find EVERY security issue — even Info-level ones.

    DO NOT respond with an empty array unless ALL files are blank or trivial (pure CSS/empty JSON).
    Always flag at least something if real source code is present.

    Report ALL of the following (even minor/informational):
    - Hardcoded secrets, tokens, passwords, API keys (even test/dev ones)
    - Missing authentication on server-side functions ('use server', API routes)
    - Dangerous functions: dangerouslySetInnerHTML, eval(), innerHTML, document.write
    - SQL/NoSQL injection risk: query(), execute(), find(), raw()
    - Sensitive data exposed in getServerSideProps, API routes, or server components
    - Outdated/vulnerable packages in package.json
    - Missing security headers (CORS, CSP, rate limiting)
    - Open redirects, missing input validation, insecure direct object references
    - Client-side exposure of secrets via process.env or window object

    SOURCE FILES:
    {combined}

    DAST ANOMALIES (cross-reference with code):
    {dast_context}

    Respond ONLY as a valid JSON array — no markdown, no text outside the array:
    [
      {{
        "vulnerability_type": "e.g. Hardcoded API Key",
        "severity": "Info|Low|Medium|High|Critical",
        "url": "exact relative filename from the FILE PATH header above each code block",
        "explanation": "2-sentence explanation of the risk.",
        "manual_poc": "Step-by-step manual verification and validation.",
        "poc_script": "A copy-pasteable Python or Curl script to reproduce the vulnerability (safely).",
        "remediation_code": "The SECURE version of the code that fixes this bug (e.g. using process.env or parameterized queries).",
        "remediation_steps": "Step-by-step resolution plan for developers (and 3rd party tools)."
      }}
    ]
    """
    try:
        text = _call_gemini(prompt)
        return _parse_gemini_json(text)
    except Exception as e:
        err = str(e)
        print(f"  [!] Batch failed: {err[:150]}")
        if "RESOURCE_EXHAUSTED" in err or "429" in err or "quota" in err.lower():
            print("  [!] Rate limit hit — waiting 65s before retry...")
            time.sleep(65)
            try:
                text = _call_gemini(prompt)
                return _parse_gemini_json(text)
            except Exception as e2:
                print(f"  [!] Retry failed: {e2}")
        return []


def analyze_hybrid(anomalies: List[Dict[str, Any]], code_context: str) -> List[Dict[str, Any]]:
    """
    Batched hybrid analysis: groups files 5-at-a-time to stay within
    Gemini free-tier rate limits (~15 RPM), then merges with DAST results.
    """
    if not code_context:
        print("[*] No codebase provided — running pure DAST analysis.")
        return analyze_anomalies(anomalies)

    file_blocks = [b.strip() for b in code_context.split("--- FILE PATH:") if b.strip()]
    total = len(file_blocks)
    batch_size = 10  # 10 files per API call = fewer quota hits
    total_batches = (total + batch_size - 1) // batch_size
    print(f"[*] Batched SAST: {total} files across {total_batches} Gemini API call(s)...")

    all_findings: List[Dict[str, Any]] = []

    for i in range(0, total, batch_size):
        batch = file_blocks[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        labels = [b.splitlines()[0][:60] for b in batch]
        print(f"  [Batch {batch_num}/{total_batches}] {labels}")

        findings = _analyze_file_batch(batch, anomalies)
        if findings:
            print(f"    → {len(findings)} finding(s) in this batch")
            all_findings.extend(findings)
        else:
            print(f"    → 0 findings in this batch")

        # Respect free-tier rate limit: 1 call per ~5s
        if i + batch_size < total:
            time.sleep(5)

    if anomalies:
        print(f"[*] Running DAST-only analysis on {len(anomalies)} fuzzer anomalies...")
        all_findings.extend(analyze_anomalies(anomalies))

    if not all_findings:
        all_findings.append({
            "vulnerability_type": "No Vulnerabilities Detected",
            "severity": "Info",
            "url": "All Scanned Files",
            "explanation": "Gemini found no security issues in the codebase or DAST surface.",
            "manual_poc": "The scanned code appears clean. Try a different codebase with known vulnerabilities like OWASP Juice Shop.",
            "poc_script": "# No vulnerability found to reproduce."
        })

    return all_findings
