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
    target_url: str
    codebase_path: Optional[str] = None
    session_cookie: Optional[str] = None
    crawl_depth: Optional[int] = 2

class ScanResponse(BaseModel):
    status: str
    message: str
    job_id: str
    findings: List[Dict[str, Any]]

@app.post("/api/scan/start", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    if not request.target_url.startswith("http"):
        raise HTTPException(status_code=400, detail="Target URL must start with http:// or https://")
    
    print(f"\n--- [ SCAN INITIATED ] ---")
    print(f"Target: {request.target_url}")
    
    # 1. Recon (Crawling)
    crawler = ReconCrawler(request.target_url, request.session_cookie)
    endpoints = crawler.map_surface()
    
    if not endpoints:
        return {"status": "error", "message": "Crawler could not find any valid endpoints.", "job_id": "job_0", "findings": []}
        
    # 2. Fuzzing
    fuzzer = Fuzzer(endpoints, request.session_cookie)
    raw_anomalies = fuzzer.run_fuzzer()
    
    # 3. Codebase Extraction (SAST)
    code_context = ""
    if request.codebase_path:
        print(f"\n--- [ EXTRACTING SOURCE CODE ] ---")
        sast = SastEngine(request.codebase_path)
        sast.prepare_codebase()
        code_context = sast.extract_critical_files()
        sast.cleanup()
    
    # 4. LLM Analysis (Hybrid or Pure DAST)
    analyzed_findings = llm.analyze_hybrid(raw_anomalies, code_context)

    print(f"--- [ SCAN COMPLETE ] ---")
    print(f"Total Confirmed Findings: {len(analyzed_findings)}\n")

    return {
        "status": "success",
        "message": f"Scan completed across {len(endpoints)} endpoints. Found {len(analyzed_findings)} potential issues.",
        "job_id": "job_12345",
        "findings": analyzed_findings
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
