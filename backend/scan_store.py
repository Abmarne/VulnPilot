import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

STORE_DIR = Path(__file__).resolve().parent / ".data" / "scans"

def _ensure_store() -> None:
    STORE_DIR.mkdir(parents=True, exist_ok=True)

def save_scan(target: str, findings: List[Dict[str, Any]], logs: List[Dict[str, Any]], profile_id: Optional[int] = None) -> str:
    _ensure_store()
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    # Sanitize target for filename
    safe_target = "".join([c if c.isalnum() else "_" for c in target])[:30]
    scan_id = f"scan_{timestamp}_{safe_target}"
    file_path = STORE_DIR / f"{scan_id}.json"
    
    data = {
        "id": scan_id,
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "profile_id": profile_id,
        "findings": findings,
        "logs": logs,
        "finding_count": len(findings)
    }
    
    file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return scan_id

def list_scans() -> List[Dict[str, Any]]:
    _ensure_store()
    scans = []
    for file_path in STORE_DIR.glob("*.json"):
        try:
            content = json.loads(file_path.read_text(encoding="utf-8"))
            scans.append({
                "id": content["id"],
                "target": content["target"],
                "timestamp": content["timestamp"],
                "finding_count": content["finding_count"]
            })
        except (json.JSONDecodeError, KeyError):
            continue
    
    # Sort by timestamp descending
    return sorted(scans, key=lambda x: x["timestamp"], reverse=True)

def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    _ensure_store()
    file_path = STORE_DIR / f"{scan_id}.json"
    if not file_path.exists():
        return None
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
