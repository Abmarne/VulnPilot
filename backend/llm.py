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
        Server Response Snippet:
        {anomaly['response_snippet']}

        Respond as a single JSON object (no markdown, no extra text):
        {{
          "vulnerability_type": "e.g. SQL Injection",
          "severity": "Low|Medium|High|Critical",
          "explanation": "2-sentence explanation of the risk.",
          "manual_poc": "Step-by-step manual verification steps.",
          "poc_script": "A copy-pasteable Python or Curl script to reproduce the vulnerability (safely)."
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
        "manual_poc": "Step-by-step manual verification and exact remediation snippet.",
        "poc_script": "A copy-pasteable Python or Curl script to reproduce the vulnerability (safely)."
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
