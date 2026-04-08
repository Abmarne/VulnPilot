from typing import Any, Dict, List, Optional
import json

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from engine import ScannerEngine
from profile_parser import parse_curl_command, parse_har_content
from profile_store import get_profile, list_profiles, save_profile
from sast_engine import SastEngine


app = FastAPI(title="VulnPilot Backend", description="Hybrid DAST+SAST Orchestrator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
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


class CurlImportRequest(BaseModel):
    name: Optional[str] = None
    target: str
    curl: str


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


manager = ConnectionManager()


async def emit_log(websocket: WebSocket, text: str, stage: str = "general"):
    await manager.send_personal_message(
        {
            "type": "log",
            "message": text,
            "stage": stage,
        },
        websocket,
    )


async def emit_progress(websocket: WebSocket, stage: str, percent: int):
    await manager.send_personal_message(
        {
            "type": "progress",
            "stage": stage,
            "percent": percent,
        },
        websocket,
    )


async def emit_finding(websocket: WebSocket, finding: Dict[str, Any]):
    await manager.send_personal_message(
        {
            "type": "finding",
            "data": finding,
        },
        websocket,
    )


@app.post("/api/profiles/import-har")
async def import_har_profile(
    target: str = Form(...),
    name: Optional[str] = Form(None),
    file: UploadFile = File(...),
):
    content = await file.read()
    try:
        parsed = parse_har_content(content, target=target, filename=name or file.filename or "Imported HAR")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid HAR file.") from exc

    profile = save_profile(
        name=name or parsed["name"],
        target=target,
        source_type=parsed["source_type"],
        requests=parsed["requests"],
    )
    return {
        "profile": {
            "id": profile["id"],
            "name": profile["name"],
            "target": profile["target"],
            "target_host": profile["target_host"],
            "source_type": profile["source_type"],
            "created_at": profile["created_at"],
            "request_count": len(profile.get("requests", [])),
        }
    }


@app.post("/api/profiles/import-curl")
async def import_curl_profile(payload: CurlImportRequest):
    try:
        parsed = parse_curl_command(payload.curl, target=payload.target, name=payload.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    profile = save_profile(
        name=payload.name or parsed["name"],
        target=payload.target,
        source_type=parsed["source_type"],
        requests=parsed["requests"],
    )
    return {
        "profile": {
            "id": profile["id"],
            "name": profile["name"],
            "target": profile["target"],
            "target_host": profile["target_host"],
            "source_type": profile["source_type"],
            "created_at": profile["created_at"],
            "request_count": len(profile.get("requests", [])),
        }
    }


@app.get("/api/profiles")
async def get_profiles(target: Optional[str] = None):
    return {"profiles": list_profiles(target)}


@app.get("/api/profiles/{profile_id}")
async def get_profile_detail(profile_id: int):
    profile = get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found.")
    return {"profile": profile}


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
                profile_id = request_data.get("profile_id")
                use_profile_requests = bool(request_data.get("use_profile_requests", False))

                engine = ScannerEngine(
                    target=target,
                    session_cookie=session_cookie,
                    profile_id=profile_id,
                    use_profile_requests=use_profile_requests,
                    on_log=lambda text, stage: emit_log(websocket, text, stage),
                    on_progress=lambda stage, percent: emit_progress(websocket, stage, percent),
                    on_finding=lambda finding: emit_finding(websocket, finding),
                )
                await engine.run()

            elif request_data.get("type") == "APPLY_FIX":
                finding = request_data.get("finding")
                target = request_data.get("target")
                if finding and target:
                    engine = ScannerEngine(
                        target=target,
                        on_log=lambda text, stage: emit_log(websocket, text, stage),
                    )
                    success = await engine.apply_remediation(finding)
                    await manager.send_personal_message(
                        {
                            "type": "fix_status",
                            "success": success,
                            "url": finding.get("url") or finding.get("url_pattern"),
                        },
                        websocket,
                    )

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as exc:
        await emit_log(websocket, f"Error: {exc}", "error")
        manager.disconnect(websocket)


@app.get("/api/debug/sast")
async def debug_sast(codebase_path: str):
    sast = SastEngine(codebase_path)
    sast.prepare_codebase()
    ctx = sast.extract_critical_files()
    files = [
        line.replace("--- FILE PATH: ", "").split(" ---")[0].strip()
        for line in ctx.splitlines()
        if "--- FILE PATH:" in line
    ]
    sast.cleanup()
    return {"files_found": len(files), "files": files, "total_chars": len(ctx)}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
