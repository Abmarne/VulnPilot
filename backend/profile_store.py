import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


STORE_DIR = Path(__file__).resolve().parent / ".data"
STORE_PATH = STORE_DIR / "attack_profiles.json"


def _ensure_store() -> None:
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    if not STORE_PATH.exists():
        STORE_PATH.write_text(json.dumps({"next_profile_id": 1, "profiles": []}, indent=2), encoding="utf-8")


def _load_store() -> Dict[str, Any]:
    _ensure_store()
    try:
        return json.loads(STORE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"next_profile_id": 1, "profiles": []}


def _save_store(data: Dict[str, Any]) -> None:
    _ensure_store()
    STORE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def normalize_target_host(target: str) -> str:
    normalized = target.strip()
    if not normalized:
        return ""
    if "://" not in normalized:
        normalized = f"http://{normalized}"
    return (urlparse(normalized).hostname or "").lower()


def _profile_summary(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": profile["id"],
        "name": profile["name"],
        "target": profile["target"],
        "target_host": profile["target_host"],
        "source_type": profile["source_type"],
        "created_at": profile["created_at"],
        "request_count": len(profile.get("requests", [])),
    }


def list_profiles(target: Optional[str] = None) -> List[Dict[str, Any]]:
    host_filter = normalize_target_host(target or "")
    store = _load_store()
    profiles = store.get("profiles", [])
    if host_filter:
        profiles = [profile for profile in profiles if profile.get("target_host") == host_filter]
    return [_profile_summary(profile) for profile in sorted(profiles, key=lambda item: item.get("created_at", ""), reverse=True)]


def get_profile(profile_id: int) -> Optional[Dict[str, Any]]:
    store = _load_store()
    for profile in store.get("profiles", []):
        if profile.get("id") == profile_id:
            return deepcopy(profile)
    return None


def save_profile(name: str, target: str, source_type: str, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    store = _load_store()
    profile_id = store.get("next_profile_id", 1)
    created_at = datetime.utcnow().isoformat() + "Z"
    profile = {
        "id": profile_id,
        "name": name,
        "target": target,
        "target_host": normalize_target_host(target),
        "source_type": source_type,
        "created_at": created_at,
        "requests": [],
    }

    for idx, request in enumerate(requests, start=1):
        stored_request = dict(request)
        stored_request["id"] = idx
        stored_request["profile_id"] = profile_id
        profile["requests"].append(stored_request)

    store.setdefault("profiles", []).append(profile)
    store["next_profile_id"] = profile_id + 1
    _save_store(store)
    return deepcopy(profile)
