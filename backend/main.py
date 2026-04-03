from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn

app = FastAPI(title="VulnPilot Backend", description="Black-Box DAST Orchestrator")

class ScanRequest(BaseModel):
    target_url: str
    session_cookie: Optional[str] = None
    crawl_depth: Optional[int] = 2

class ScanResponse(BaseModel):
    status: str
    message: str
    job_id: str

@app.post("/api/scan/start", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    if not request.target_url.startswith("http"):
        raise HTTPException(status_code=400, detail="Target URL must start with http:// or https://")
    
    # TODO: Hand off to the async crawler/fuzzer queue
    print(f"Starting scan for {request.target_url} with cookie: {request.session_cookie}")

    return {
        "status": "success",
        "message": f"Scan initiated for {request.target_url}",
        "job_id": "job_12345"
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
