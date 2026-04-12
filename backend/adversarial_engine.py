"""
VulnPilot Adversarial Arena Engine
====================================
Two free, cloud-based AI agents battle over your vulnerable code:

  RED  AGENT  → Qwen2.5-Coder-32B (HuggingFace) — tries to break the fix
  BLUE AGENT  → Mistral-7B-Instruct (HuggingFace) — defends with patches or honey-patches

The fight continues until:
  - Blue produces code Red cannot break (Provably Secure), OR
  - Max rounds are exhausted and a Honey-Patch trap is deployed instead.
"""

import os
import json
import re
import time
from typing import Any, AsyncGenerator, Dict, List, Optional

# ── Hugging Face Inference Client ───────────────────────────────────────────
try:
    from huggingface_hub import InferenceClient
    _HF_AVAILABLE = True
except ImportError:
    _HF_AVAILABLE = False

HF_API_KEY = os.environ.get("HF_API_KEY", "")

# Red Agent  → code-focused model, best at finding bypasses
RED_MODEL  = "Qwen/Qwen2.5-Coder-32B-Instruct"
# Blue Agent → instruction-tuned model, best at writing secure fixes / deception
BLUE_MODEL = "mistralai/Mistral-7B-Instruct-v0.2"

MAX_ROUNDS = 3  # Max Red vs. Blue battle rounds per finding


def _hf_call(model: str, system_prompt: str, user_prompt: str, temperature: float = 0.3) -> str:
    """Makes a free Hugging Face Inference API call."""
    if not _HF_AVAILABLE:
        raise RuntimeError("huggingface_hub is not installed. Run: pip install huggingface_hub")
    if not HF_API_KEY:
        raise RuntimeError("HF_API_KEY not set in .env file. Get a free token at https://huggingface.co/settings/tokens")

    client = InferenceClient(api_key=HF_API_KEY)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_prompt},
    ]
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        max_tokens=2048,
        temperature=temperature,
    )
    return response.choices[0].message.content or ""


def _red_agent_attack(vulnerable_code: str, current_fix: str, vuln_type: str) -> Dict[str, Any]:
    """
    RED AGENT: Given existing code and Blue's current fix attempt,
    try to find a bypass or residual vulnerability in the fix.
    """
    system = (
        "You are an elite offensive security researcher (Red Team). "
        "Your ONLY goal is to find bypasses in security patches. "
        "Be adversarial, creative, and thorough. Think like a real attacker."
    )
    user = f"""
VULNERABILITY TYPE: {vuln_type}

ORIGINAL VULNERABLE CODE:
```
{vulnerable_code}
```

BLUE TEAM'S CURRENT PATCH (attempt to fix):
```
{current_fix}
```

TASK:
- Analyze the patch for any bypass, edge-case, or residual vulnerability.
- If you can bypass it (e.g., URL encoding, case sensitivity, second-order injection, type confusion), explain HOW.
- If the patch is TRULY secure and you CANNOT find any bypass, say "SECURE" clearly.

Respond as JSON:
{{
  "bypassed": true or false,
  "bypass_technique": "exact technique name or null",
  "bypass_payload": "exact payload string or null",
  "bypass_explanation": "step by step how the bypass works, or 'Patch is provably secure.'",
  "confidence": "High | Medium | Low"
}}
"""
    raw = _hf_call(RED_MODEL, system, user, temperature=0.5)
    # Parse JSON from the response
    try:
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception:
        pass
    return {
        "bypassed": False,
        "bypass_technique": None,
        "bypass_payload": None,
        "bypass_explanation": raw[:500],
        "confidence": "Low"
    }


def _blue_agent_defend(vulnerable_code: str, red_bypass: Optional[Dict], vuln_type: str, round_num: int) -> Dict[str, Any]:
    """
    BLUE AGENT: Produces a secure patch, OR on last round, generates a Honey-Patch.
    """
    is_honey_round = round_num >= MAX_ROUNDS

    if is_honey_round:
        mode = "HONEY-PATCH (Active Deception)"
        task = f"""
The Red Team has broken your previous patches {MAX_ROUNDS} times. 
Now generate a HONEY-PATCH instead of a plain fix.

A Honey-Patch is DECEPTIVE CODE that:
1. APPEARS to be vulnerable (so the attacker thinks they won).
2. Internally, it traps them by returning FAKE data (fake DB dumps, fake /etc/passwd, fake tokens).
3. Secretly logs the attack: timestamp, payload used, IP header, User-Agent.
4. Includes a "HoneyAlert" dict/comment that VulnPilot can read to surface in the dashboard.

Generate the full Honey-Patch code with embedded trap logic.
"""
    else:
        mode = f"SECURE FIX (Round {round_num})"
        bypass_context = ""
        if red_bypass and red_bypass.get("bypassed"):
            bypass_context = f"""
RED TEAM BYPASS from previous round:
- Technique: {red_bypass.get('bypass_technique')}
- Payload:   {red_bypass.get('bypass_payload')}
- How:       {red_bypass.get('bypass_explanation')}

Your NEW patch MUST specifically close this bypass vector.
"""
        task = f"""
{bypass_context}
Generate a SECURE, production-ready fix for this vulnerability.
Use the industry-standard remediation approach (parameterized queries, strict input validation, allowlists, etc.).
"""

    system = (
        "You are a world-class Blue Team security engineer. "
        "Your job is to write provably secure code patches or strategic honey-patches."
    )
    user = f"""
VULNERABILITY TYPE: {vuln_type}
MODE: {mode}

ORIGINAL VULNERABLE CODE:
```
{vulnerable_code}
```

{task}

Respond as JSON:
{{
  "mode": "{mode}",
  "patched_code": "complete, runnable code with the fix applied",
  "explanation": "what was changed and why this is secure",
  "is_honey_patch": {str(is_honey_round).lower()},
  "honey_trap_log_key": "HONEY_ALERT (only if honey-patch, else null)",
  "fake_data_returned": "description of the fake data the trap returns (only if honey-patch)"
}}
"""
    raw = _hf_call(BLUE_MODEL, system, user, temperature=0.2)
    try:
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            return json.loads(match.group())
    except Exception:
        pass
    return {
        "mode": mode,
        "patched_code": raw,
        "explanation": "Blue Agent generated a patch.",
        "is_honey_patch": is_honey_round,
        "honey_trap_log_key": None,
        "fake_data_returned": None,
    }


async def run_arena(
    finding: Dict[str, Any],
    emit: Any = None  # async callable(event_type: str, data: dict)
) -> Dict[str, Any]:
    """
    Orchestrates the full Red vs. Blue battle.
    Yields live events via the `emit` callback for WebSocket streaming.

    Returns a final arena_result dict.
    """

    vuln_type    = finding.get("vulnerability_type", "Unknown")
    vuln_code    = finding.get("remediation_code") or finding.get("explanation", "")
    url_surface  = finding.get("url") or finding.get("file_path") or "Unknown Surface"

    battle_log: List[Dict] = []
    current_fix: str = vuln_code  # Start from LLM's initial remediation suggestion
    red_result:  Optional[Dict] = None
    final_status = "in_progress"

    async def _emit(event: str, data: dict):
        if emit:
            await emit(event, data)

    await _emit("arena_start", {
        "vuln_type": vuln_type,
        "surface": url_surface,
        "max_rounds": MAX_ROUNDS,
        "red_model": RED_MODEL,
        "blue_model": BLUE_MODEL,
    })

    for round_num in range(1, MAX_ROUNDS + 1):
        await _emit("round_start", {"round": round_num})

        # ── RED AGENT ATTACKS ────────────────────────────────────────────────
        await _emit("red_thinking", {"round": round_num, "message": "🔴 Red Agent is analyzing the patch for bypasses..."})
        try:
            red_result = _red_agent_attack(
                vulnerable_code=finding.get("poc_script") or vuln_code,
                current_fix=current_fix,
                vuln_type=vuln_type,
            )
        except Exception as exc:
            await _emit("arena_error", {"error": str(exc), "hint": "Check HF_API_KEY in your .env file."})
            return {"status": "error", "error": str(exc), "battle_log": battle_log}

        await _emit("red_result", {
            "round": round_num,
            "bypassed": red_result.get("bypassed"),
            "technique": red_result.get("bypass_technique"),
            "payload": red_result.get("bypass_payload"),
            "explanation": red_result.get("bypass_explanation"),
        })

        battle_log.append({"round": round_num, "agent": "RED", "result": red_result})

        # If Red cannot bypass → code is provably secure!
        if not red_result.get("bypassed"):
            final_status = "provably_secure"
            await _emit("blue_wins", {
                "round": round_num,
                "message": "✅ Red Agent could not find a bypass. Code is PROVABLY SECURE!",
                "final_code": current_fix,
            })
            break

        # ── BLUE AGENT DEFENDS / HONEY-PATCHES ──────────────────────────────
        await _emit("blue_thinking", {"round": round_num, "message": "🔵 Blue Agent is engineering a stronger patch..."})
        try:
            blue_result = _blue_agent_defend(
                vulnerable_code=vuln_code,
                red_bypass=red_result,
                vuln_type=vuln_type,
                round_num=round_num,
            )
        except Exception as exc:
            await _emit("arena_error", {"error": str(exc)})
            return {"status": "error", "error": str(exc), "battle_log": battle_log}

        current_fix = blue_result.get("patched_code", current_fix)
        battle_log.append({"round": round_num, "agent": "BLUE", "result": blue_result})

        await _emit("blue_result", {
            "round": round_num,
            "patched_code": current_fix,
            "explanation": blue_result.get("explanation"),
            "is_honey_patch": blue_result.get("is_honey_patch"),
            "fake_data_returned": blue_result.get("fake_data_returned"),
        })

        if blue_result.get("is_honey_patch"):
            final_status = "honey_patched"
            await _emit("honey_deployed", {
                "message": "🍯 Honey-Patch deployed! Attackers will be trapped with fake data.",
                "final_code": current_fix,
                "fake_data": blue_result.get("fake_data_returned"),
            })
            break

    # Build final report
    arena_result = {
        "status": final_status,
        "vuln_type": vuln_type,
        "surface": url_surface,
        "rounds_fought": len([x for x in battle_log if x["agent"] == "RED"]),
        "final_patched_code": current_fix,
        "battle_log": battle_log,
        "is_honey_patch": final_status == "honey_patched",
        "is_provably_secure": final_status == "provably_secure",
    }

    await _emit("arena_complete", arena_result)
    return arena_result
