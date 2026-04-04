from google import genai as google_genai
from groq import Groq
import os
import json
import time
from typing import List, Dict, Any

# ── Provider Selection ──────────────────────────────────────────────────────
# Set GROQ_API_KEY env var (or paste below) to use Groq (recommended: 14k req/day free)
# Set GOOGLE_API_KEY env var to fall back to Gemini
GROQ_API_KEY    = os.environ.get("GROQ_API_KEY", "")
GEMINI_API_KEY  = os.environ.get("GOOGLE_API_KEY", "")

USE_GROQ = GROQ_API_KEY and GROQ_API_KEY != "PASTE_YOUR_GROQ_KEY_HERE"

if USE_GROQ:
    groq_client = Groq(api_key=GROQ_API_KEY)
    MODEL = "llama-3.3-70b-versatile"
    print(f"[LLM] Provider: Groq ({MODEL})")
else:
    google_genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = google_genai.GenerativeModel("gemini-1.5-flash-8b")
    MODEL = "gemini-1.5-flash-8b"
    print(f"[LLM] Provider: Gemini ({MODEL})")


def _call_llm(prompt: str) -> str:
    """Unified LLM call — uses Groq if configured, else falls back to Gemini."""
    if USE_GROQ:
        response = groq_client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=4096,
        )
        return response.choices[0].message.content
    else:
        import google.generativeai as genai_legacy
        genai_legacy.configure(api_key=GEMINI_API_KEY)
        m = genai_legacy.GenerativeModel("gemini-1.5-flash-8b")
        return m.generate_content(prompt).text


# Alias for backward compat inside this file
_call_gemini = _call_llm



def _parse_gemini_json(text: str) -> list:
    """Cleans and parses Gemini JSON output reliably."""
    text = text.strip()
    for wrapper in ["```json", "```"]:
        text = text.replace(wrapper, "")
    text = text.strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        # Try to extract JSON array from within the text
        start = text.find("[")
        end = text.rfind("]") + 1
        if start != -1 and end > start:
            parsed = json.loads(text[start:end])
        else:
            return []
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return parsed
    return []


def generate_fuzzing_payloads(target_urls: List[str]) -> List[str]:
    """Uses Gemini to dynamically generate benign testing payloads."""
    prompt = f"""
    You are an expert security engineer building a DAST tool.
    Generate 10 highly effective, BENIGN testing payloads for these endpoints:
    {target_urls}

    Payloads should safely trigger database errors, 500 errors, or reflections.
    Do NOT generate shell exploits or data-destroying payloads.

    Respond ONLY as a valid JSON array of strings. No markdown.
    Example: ["' OR 1=1 --", "<script>alert(1)</script>", "../../../../etc/passwd"]
    """
    try:
        print("[*] Asking Gemini to craft custom fuzzing payloads...")
        text = _call_gemini(prompt)
        text = text.replace("```json", "").replace("```", "").strip()
        payloads = json.loads(text)
        if isinstance(payloads, list):
            return payloads
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
    """Analyzes fuzzer DAST anomalies with Gemini."""
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

        Respond as a single JSON object (no markdown):
        {{
          "vulnerability_type": "e.g. SQL Injection",
          "severity": "Low|Medium|High|Critical",
          "explanation": "2-sentence explanation.",
          "manual_poc": "Step-by-step benign verification steps."
        }}
        """
        try:
            print(f"[*] Analyzing DAST anomaly on {anomaly['url']}...")
            text = _call_gemini(prompt)
            text = text.replace("```json", "").replace("```", "").strip()
            analysis = json.loads(text)
            analyzed_results.append({**anomaly, **analysis})
        except Exception as e:
            print(f"[!] Gemini API error: {e}")
            analyzed_results.append({
                **anomaly,
                "vulnerability_type": "Analysis Error",
                "severity": "Unknown",
                "explanation": str(e)[:200],
                "manual_poc": "Check backend logs."
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
        "manual_poc": "Step-by-step safe verification and exact remediation snippet."
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
            "manual_poc": "The scanned code appears clean. Try a different codebase with known vulnerabilities like OWASP Juice Shop."
        })

    return all_findings
