from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import json
import asyncio
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uvicorn
from crawler import ReconCrawler
from fuzzer import Fuzzer
import llm
from sast_engine import SastEngine
from header_analyzer import analyze_headers

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

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        await websocket.send_json(message)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

async def emit_log(websocket: WebSocket, text: str, stage: str = "general"):
    """Sends a log message to the client over WebSocket."""
    await manager.send_personal_message({
        "type": "log",
        "message": text,
        "stage": stage
    }, websocket)

async def emit_progress(websocket: WebSocket, stage: str, percent: int):
    """Sends progress update to the client over WebSocket."""
    await manager.send_personal_message({
        "type": "progress",
        "stage": stage,
        "percent": percent
    }, websocket)

async def emit_finding(websocket: WebSocket, finding: Dict[str, Any]):
    """Sends a new vulnerability finding to the client over WebSocket."""
    await manager.send_personal_message({
        "type": "finding",
        "data": finding
    }, websocket)

@app.websocket("/api/scan/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            request_data = json.loads(data)
            
            if request_data.get("type") == "START_SCAN":
                target = request_data.get("target", "")
                session_cookie = request_data.get("session_cookie", None)
                
                await emit_log(websocket, "--- [ SCAN INITIATED VIA WS ] ---", "init")
                await emit_progress(websocket, "init", 5)
                
                input_targets = [t.strip() for t in target.split(",") if t.strip()]
                target_url = None
                codebase_path = None
                
                for t in input_targets:
                    is_github = "github.com" in t.lower()
                    is_http = t.lower().startswith(("http://", "https://"))
                    
                    if is_github:
                        if not is_http: t = "https://" + t
                        codebase_path = t
                        await emit_log(websocket, f"[*] Detected GitHub: {codebase_path}", "init")
                    elif is_http:
                        target_url = t
                        await emit_log(websocket, f"[*] Detected Web App: {target_url}", "init")
                    elif "." in t and "/" not in t and "\\" not in t:
                        target_url = "http://" + t
                        await emit_log(websocket, f"[*] Detected Domain: {target_url}", "init")
                    else:
                        codebase_path = t
                        await emit_log(websocket, f"[*] Detected Local Code: {codebase_path}", "init")

                await emit_progress(websocket, "recon", 10)
                
                # 1. Recon (DAST Surface Discovery)
                endpoints = []
                if target_url:
                    await emit_log(websocket, f"[*] Recon: Crawling {target_url}...", "recon")
                    crawler = ReconCrawler(target_url, session_cookie)
                    discovery_data = crawler.map_surface()
                    endpoints = discovery_data.get("endpoints", [])
                    js_urls = discovery_data.get("js_urls", [])
                    
                    await emit_log(websocket, f"[*] Recon: Found {len(endpoints)} surface endpoints and {len(js_urls)} scripts.", "recon")
                    
                    # 1b. Semantic API Reconstruction (Ghost Endpoints)
                    if js_urls:
                        await emit_log(websocket, "[*] Recon: Analyzing JavaScript for hidden API routes...", "recon")
                        ghost_count = 0
                        for js_url in js_urls[:5]: # Analyze top 5 scripts to balance depth vs speed
                            await emit_log(websocket, f"  [>] Analyzing {js_url.split('/')[-1]}...", "recon")
                            js_content = crawler.fetch_js_content(js_url)
                            if js_content:
                                discovered_api = llm.reconstruct_api_schema(js_content)
                                for ep in discovered_api:
                                    # Normalize URL
                                    if ep["url"].startswith("/"):
                                        ep["url"] = target_url + ep["url"]
                                    
                                    # Avoid duplicates
                                    if not any(e["url"] == ep["url"] for e in endpoints):
                                        endpoints.append(ep)
                                        ghost_count += 1
                                        await emit_log(websocket, f"  [+] GHOST ENDPOINT: {ep['method']} {ep['url']}", "recon")
                        
                        if ghost_count > 0:
                            await emit_log(websocket, f"[*] Recon: Added {ghost_count} hidden 'Ghost Endpoints' to attack surface.", "recon")
                
                
                await emit_progress(websocket, "sast", 30)
                        
                # 2. Codebase Extraction & Sink Discovery (SAST)
                code_context = ""
                guided_insights = []
                if codebase_path:
                    await emit_log(websocket, "[*] SAST: Extracting source code...", "sast")
                    sast = SastEngine(codebase_path)
                    sast.prepare_codebase()
                    code_context = sast.extract_critical_files()
                    await emit_log(websocket, "[*] SAST: Running AI Sink Analysis...", "sast")
                    guided_insights = llm.identify_sinks(code_context)
                    await emit_log(websocket, f"[*] SAST: Found {len(guided_insights)} potential code sinks.", "sast")
                    sast.cleanup()
                
                await emit_progress(websocket, "fuzzing", 50)
                
                # 3. Hybrid Fuzzing (Guided DAST)
                raw_anomalies = []
                if endpoints:
                    await emit_log(websocket, f"[*] Fuzzing: Launching guided assault on {len(endpoints)} targets...", "fuzzing")
                    fuzzer = Fuzzer(endpoints, session_cookie, guided_insights=guided_insights)
                    raw_anomalies = fuzzer.run_fuzzer(target_url)
                    await emit_log(websocket, f"[*] Fuzzing: Detected {len(raw_anomalies)} raw anomalies.", "fuzzing")
                
                await emit_progress(websocket, "analysis", 80)
                
                # 4. Built-in Security Analysis (Headers)
                header_findings = []
                if target_url:
                    await emit_log(websocket, "[*] Analyzing security headers...", "analysis")
                    header_findings = analyze_headers(target_url)
                    for hf in header_findings:
                        await emit_finding(websocket, hf)
                
                # 5. LLM Analysis
                await emit_log(websocket, "[*] Finalizing Hybrid Analysis with Gemini...", "analysis")
                all_findings = llm.analyze_hybrid(raw_anomalies, code_context)
                
                for f in all_findings:
                    await emit_finding(websocket, f)
                
                await emit_progress(websocket, "complete", 100)
                await emit_log(websocket, "--- [ SCAN COMPLETE ] ---", "complete")
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        await emit_log(websocket, f"Error: {e}", "error")
        manager.disconnect(websocket)

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
