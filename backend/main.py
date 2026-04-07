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
from engine import ScannerEngine

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
                
                # Create the engine with WebSocket emitters as callbacks
                engine = ScannerEngine(
                    target=target,
                    session_cookie=session_cookie,
                    on_log=lambda text, stage: emit_log(websocket, text, stage),
                    on_progress=lambda stage, percent: emit_progress(websocket, stage, percent),
                    on_finding=lambda finding: emit_finding(websocket, finding)
                )
                
                # Execute the scan (Headless or UI-driven, logic is the same)
                await engine.run()
                
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
