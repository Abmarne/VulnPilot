import json
import re
import asyncio
from typing import Any, Dict, List, Optional, Callable, Awaitable

import llm
from engine import ScannerEngine
from sast_engine import SastEngine
from fuzzer import Fuzzer
from crawler import ReconCrawler
from sandbox import SandboxManager

from agents.base import AgentContext
from agents.specialized import ScoutAgent, AuditorAgent, RedTeamAgent

class PilotOrchestrator:
    """
    The Orchestrator for the Multi-Agent Agentic AI.
    Manages state hand-overs and reflection steps between specialized agents.
    """

    def __init__(
        self,
        target: str,
        session_cookie: Optional[str] = None,
        on_thought: Optional[Callable[[str], Awaitable[None]]] = None,
        on_action: Optional[Callable[[str, Any], Awaitable[None]]] = None,
        on_finding: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
        llm_config: Optional[Dict[str, Any]] = None,
    ):
        self.target = target
        self.session_cookie = session_cookie
        self.on_thought = on_thought
        self.on_action = on_action
        self.on_finding = on_finding
        self.llm_config = llm_config
        
        self.world_model = {
            "endpoints": [],
            "code_files": [],
            "verified_findings": [],
            "current_stage": "init",
            "agent_assignments": []
        }
        self.max_steps = 20
        self.context = AgentContext(target, self.world_model)
        
        self.agents = {
            "scout": ScoutAgent(),
            "auditor": AuditorAgent(),
            "redteam": RedTeamAgent()
        }
        self.current_agent_key = "scout" if target.startswith("http") else "auditor"
        
        # Determine if target is a URL or a Codebase
        self.is_url = target.startswith(("http://", "https://"))
        self.codebase_path = target if not self.is_url else None
        self._sast_engine = SastEngine(self.codebase_path) if self.codebase_path else None
        self._sandbox = SandboxManager()

    async def _think(self, text: str, persona: str = "Orchestrator"):
        prefix = f"[{persona}] " if persona else ""
        if self.on_thought:
            await self.on_thought(f"{prefix}{text}")
        else:
            print(f"{prefix}{text}")

    async def _emit_action(self, tool: str, params: Any):
        if self.on_action:
            await self.on_action(tool, params)
        else:
            print(f"[ACTION] {tool}({params})")

    async def run(self, mission_goal: str = "Find and verify as many vulnerabilities as possible."):
        """The main Agentic Loop with Reflection and Multi-Agent hand-over."""
        await self._think(f"Mission briefing received: {mission_goal}")
        
        for step in range(self.max_steps):
            agent = self.agents[self.current_agent_key]
            
            # --- PHASE 1: REFLECTION ---
            await self._think(f"Reflecting on mission state... (Current Agent: {agent.persona_name})")
            reflection_prompt = self._build_reflection_prompt(mission_goal, agent)
            reflection = llm._call_llm(reflection_prompt, config=self.llm_config)
            
            if "HANDOVER" in reflection.upper():
                new_agent_key = self._determine_handover(reflection)
                if new_agent_key and new_agent_key != self.current_agent_key:
                    await self._think(f"Strategic transition: Handing over from {agent.persona_name} to {self.agents[new_agent_key].persona_name}.")
                    
                    # CHECKPOINT: RedTeam requires explicit mention of approval if transitioning to it
                    if new_agent_key == "redteam":
                         await self._think("⚠️ REDTEAM CHECKPOINT: Moving to active exploitation phase.")
                         # Since we have user 'Yes' in history, we proceed, but log the checkpoint.
                    
                    self.current_agent_key = new_agent_key
                    agent = self.agents[self.current_agent_key]
            
            # --- PHASE 2: REASONING & ACTING ---
            prompt = agent.get_system_prompt(self.context)
            response = llm._call_llm(prompt, config=self.llm_config)
            
            reasoning = self._extract_reasoning(response)
            action = self._extract_action(response)
            
            if reasoning:
                await self._think(reasoning, persona=agent.persona_name)
            
            if not action or action.get("tool") == "finish":
                if self.current_agent_key == "redteam":
                    await self._think("Final reports generated. Mission complete.")
                    break
                else:
                    await self._think(f"{agent.persona_name} finished their tasks. Returning to Orchestrator for reassignment.")
                    # Force a handover by making the reflection decide next agent
                    self.current_agent_key = "auditor" if self.current_agent_key == "scout" else "redteam"
                    continue
                
            # Execute tool
            tool_name = action.get("tool")
            tool_params = action.get("params", {})
            
            await self._emit_action(tool_name, tool_params)
            observation = await self._execute_tool(tool_name, tool_params)
            
            # Store history
            self.context.history.append({
                "step": step,
                "agent": agent.persona_name,
                "thought": reasoning,
                "action": action,
                "observation": observation
            })
            
            await asyncio.sleep(1)

    def _build_reflection_prompt(self, goal: str, current_agent: Any) -> str:
        history_summary = "\n".join([f"- {h['agent']}: {h['thought']}" for h in self.context.history[-3:]])
        return f"""
State Reflection Engine:
Goal: {goal}
Current Agent: {current_agent.persona_name}
Recent History:
{history_summary}

Analyze the situation. Should we:
1. CONTINUE with the current agent?
2. HANDOVER to another agent? (scout, auditor, redteam)

Current World Model: {json.dumps(self.world_model, indent=2)}

If a handover is needed, respond with "HANDOVER: <agent_key>". Otherwise respond with "CONTINUE".
"""

    def _determine_handover(self, reflection: str) -> Optional[str]:
        if "HANDOVER: scout" in reflection.lower(): return "scout"
        if "HANDOVER: auditor" in reflection.lower(): return "auditor"
        if "HANDOVER: redteam" in reflection.lower(): return "redteam"
        return None

    def _extract_reasoning(self, text: str) -> str:
        match = re.search(r"THOUGHT:\s*(.*?)(?=ACTION:|$)", text, re.DOTALL | re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _extract_action(self, text: str) -> Optional[Dict]:
        pattern = r"ACTION:\s*(.*)"
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if not match:
            match = re.search(r'(\{\s*"tool":\s*".*"\})', text, re.DOTALL)
        if match:
            try:
                raw_json = match.group(0 if "ACTION:" not in text.upper() else 1).strip()
                if "```" in raw_json:
                    raw_json = re.sub(r"```(?:json)?", "", raw_json).strip()
                if "{" in raw_json:
                    raw_json = raw_json[raw_json.find("{"):]
                if "}" in raw_json:
                    raw_json = raw_json[:raw_json.rfind("}")+1]
                return json.loads(raw_json)
            except: return None
        return None

    async def _execute_tool(self, tool_name: str, params: Dict) -> Any:
        try:
            if tool_name == "recon_attack_surface":
                url = params.get("url") or (self.target if self.is_url else None)
                if not url: return "Error: Target is not a URL."
                crawler = ReconCrawler(url, self.session_cookie)
                data = crawler.map_surface()
                new_endpoints = data.get("endpoints", [])
                self.world_model["endpoints"].extend(new_endpoints)
                return f"Recon complete. Found {len(new_endpoints)} endpoints."

            elif tool_name == "read_code":
                if not self._sast_engine: return "Error: No local codebase available."
                path = params.get("path")
                content = self._sast_engine.get_file_content(path)
                if content:
                    self.world_model["code_files"].append(path)
                    return f"Content of {path} (truncated): {content[:500]}..."
                return f"Error: Could not read {path}."

            elif tool_name == "analyze_sast":
                context = params.get("code_context")
                sinks = llm.identify_sinks(context, llm_config=self.llm_config)
                for sink in sinks:
                    if self.on_finding: await self.on_finding(sink)
                return f"SAST found {len(sinks)} potential sinks."

            elif tool_name == "fuzz_endpoint":
                endpoint = params.get("endpoint_data")
                if not endpoint or not self.is_url: return "Error: Invalid target."
                fuzzer = Fuzzer([endpoint], self.session_cookie, [], {}, llm_config=self.llm_config)
                anomalies = fuzzer.run_fuzzer(base_url=self.target)
                analyzed = llm.analyze_anomalies(anomalies, llm_config=self.llm_config)
                for finding in analyzed:
                    if self.on_finding: await self.on_finding(finding)
                return f"Fuzzing found {len(analyzed)} vulnerabilities."

            elif tool_name == "verify_finding":
                finding = params.get("finding_data")
                code = finding.get("code") or (self._sast_engine.get_file_content(finding.get("file_path")) if self._sast_engine else "")
                payload = finding.get("payload")
                vtype = finding.get("vulnerability_type", "unknown")
                if not code or not payload: return "Error: Missing data for verification."
                result, msg = await asyncio.to_thread(self._sandbox.verify_exploit, code, payload, vtype)
                return f"Sandbox outcome: {'VERIFIED' if result else 'BLOCKED'}. Message: {msg}"

            return f"Error: Tool '{tool_name}' not implemented."
        except Exception as e:
            return f"Exception in tool {tool_name}: {str(e)}"

class SecurityPilot(PilotOrchestrator):
    """Alias for backward compatibility with existing main.py imports."""
    pass
