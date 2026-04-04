from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uvicorn
from crawler import ReconCrawler
from fuzzer import Fuzzer
import llm
from sast_engine import SastEngine

app = FastAPI(title="VulnPilot Backend", description="Hybrid DAST+SAST Orchestrator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Local development so allow all
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    session_cookie: Optional[str] = None
    crawl_depth: Optional[int] = 2

class ScanResponse(BaseModel):
    status: str
    message: str
    job_id: str
    findings: List[Dict[str, Any]]

@app.post("/api/scan/start", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    input_targets = [t.strip() for t in request.target.split(",") if t.strip()]
    target_url = None
    codebase_path = None
    
    for t in input_targets:
        is_github = "github.com" in t.lower()
        is_http = t.lower().startswith(("http://", "https://"))
        
        if is_github:
            if not is_http:
                t = "https://" + t
            codebase_path = t
            print(f"[*] Detected GitHub repository as target: {codebase_path}")
        elif is_http:
            target_url = t
            print(f"[*] Detected Web Application as target: {target_url}")
        elif "." in t and "/" not in t and "\\" not in t:
            # Probable domain name like "example.com"
            target_url = "http://" + t
            print(f"[*] Detected Domain as target: {target_url}")
        else:
            # Assume local path
            codebase_path = t
            print(f"[*] Detected Local Codebase as target: {codebase_path}")

    print(f"\n--- [ SCAN INITIATED ] ---")
    
    # 1 & 2. Recon and Fuzzing (DAST)
    raw_anomalies = []
    endpoints_count = 0
    if target_url:
        print(f"[*] Starting Black/Grey Box Discovery on {target_url}...")
        crawler = ReconCrawler(target_url, request.session_cookie)
        endpoints = crawler.map_surface()
        endpoints_count = len(endpoints)
        
        if endpoints:
            fuzzer = Fuzzer(endpoints, request.session_cookie)
            raw_anomalies = fuzzer.run_fuzzer(target_url)
        else:
            print("[!] Crawler could not find any valid endpoints for DAST.")
            
    # 3. Codebase Extraction (SAST)
    code_context = ""
    if codebase_path:
        print(f"\n--- [ EXTRACTING SOURCE CODE ] ---")
        sast = SastEngine(codebase_path)
        sast.prepare_codebase()
        code_context = sast.extract_critical_files()
        sast.cleanup()
    
    if not target_url and not code_context:
        return {"status": "error", "message": "No valid targets found (web URL or valid codebase).", "job_id": "job_0", "findings": []}

    # 4. LLM Analysis (Hybrid, DAST-only, or SAST-only)
    analyzed_findings = llm.analyze_hybrid(raw_anomalies, code_context)

    print(f"--- [ SCAN COMPLETE ] ---")
    print(f"Total Findings: {len(analyzed_findings)}\n")

    return {
        "status": "success",
        "message": f"Scan completed. Analyzed {endpoints_count} endpoints and codebase context. Found {len(analyzed_findings)} potential issues.",
        "job_id": "job_12345",
        "findings": analyzed_findings
    }

@app.get("/api/debug/sast")
async def debug_sast(codebase_path: str):
    """Debug endpoint: shows what files SAST engine extracts without calling Gemini."""
    sast = SastEngine(codebase_path)
    sast.prepare_codebase()
    ctx = sast.extract_critical_files()
    files = [line.replace("--- FILE PATH: ", "").split(" ---")[0].strip()
             for line in ctx.splitlines() if "--- FILE PATH:" in line]
    sast.cleanup()
    return {"files_found": len(files), "files": files, "total_chars": len(ctx)}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
