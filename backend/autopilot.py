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

class SecurityPilot:
    """
    The brain of the Agentic VulnPilot.
    Uses a ReAct (Reasoning + Acting) loop to autonomously find and verify vulnerabilities.
    """

    def __init__(
        self,
        target: str,
        session_cookie: Optional[str] = None,
        on_thought: Optional[Callable[[str], Awaitable[None]]] = None,
        on_action: Optional[Callable[[str, Any], Awaitable[None]]] = None,
        on_finding: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
    ):
        self.target = target
        self.session_cookie = session_cookie
        self.on_thought = on_thought
        self.on_action = on_action
        self.on_finding = on_finding
        
        self.world_model = {
            "endpoints": [],
            "code_files": [],
            "verified_findings": [],
            "current_stage": "init"
        }
        self.max_steps = 15
        self.history = []
        
        # Determine if target is a URL or a Codebase
        self.is_url = target.startswith(("http://", "https://"))
        self.codebase_path = target if not self.is_url else None
        self._sast_engine = SastEngine(self.codebase_path) if self.codebase_path else None
        self._sandbox = SandboxManager()

    async def _think(self, text: str):
        if self.on_thought:
            await self.on_thought(text)
        else:
            print(f"[THOUGHT] {text}")

    async def _emit_action(self, tool: str, params: Any):
        if self.on_action:
            await self.on_action(tool, params)
        else:
            print(f"[ACTION] {tool}({params})")

    async def run(self, mission_goal: str = "Find and verify as many high-severity vulnerabilities as possible."):
        """Main autonomic loop."""
        await self._think(f"Mission briefing received: {mission_goal}")
        
        for step in range(self.max_steps):
            prompt = self._build_prompt(mission_goal)
            response = llm._call_llm(prompt)
            
            # Parse reasoning and action
            reasoning = self._extract_reasoning(response)
            action = self._extract_action(response)
            
            if reasoning:
                await self._think(reasoning)
            
            if not action or action.get("tool") == "finish":
                await self._think("Mission objective achieved or no further actions possible.")
                break
                
            # Execute tool
            tool_name = action.get("tool")
            tool_params = action.get("params", {})
            
            await self._emit_action(tool_name, tool_params)
            observation = await self._execute_tool(tool_name, tool_params)
            
            # Store history
            self.history.append({
                "step": step,
                "thought": reasoning,
                "action": action,
                "observation": observation
            })
            
            # await self._think(f"Observation from {tool_name}: {str(observation)[:500]}")

    def _build_prompt(self, goal: str) -> str:
        state_summary = json.dumps(self.world_model, indent=2)
        history_summary = ""
        for h in self.history[-5:]: # More history for better context
            history_summary += f"Step {h['step']} Thought: {h['thought']}\nStep {h['step']} Action: {h['action']['tool']}\nStep {h['step']} Observation: {str(h['observation'])[:300]}\n\n"

        return f"""
You are the VulnPilot Security Autopilot, an elite autonomous security researcher.
Your goal: {goal}
Target: {self.target}

Available Tools:
1. `recon_attack_surface(url)`: Crawls the target URL and finds endpoints.
2. `read_code(path)`: Reads the content of a local file (only if target is a codebase).
3. `analyze_sast(code_context)`: Identifies potential security sinks in code and returns potential vulnerabilities.
4. `fuzz_endpoint(endpoint_data)`: Runs a fuzzer against a specific endpoint (needs a URL target).
5. `verify_finding(finding_data)`: Uses an isolated sandbox to verify if a finding is truly exploitable. Requires `code` and `payload`.
6. `finish()`: Use this when you have completed your mission.

Current World Model:
{state_summary}

Recent History:
{history_summary}

Rules:
- You must always provide your "THOUGHT" followed by your "ACTION".
- Output format:
THOUGHT: <your reasoning about the next step>
ACTION: {{"tool": "<tool_name>", "params": {{...}}}}

Think step-by-step. Focus on critical vulnerabilities (SQLi, RCE, IDOR, XSS).
"""

    def _extract_reasoning(self, text: str) -> str:
        match = re.search(r"THOUGHT:\s*(.*?)(?=ACTION:|$)", text, re.DOTALL | re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _extract_action(self, text: str) -> Optional[Dict]:
        match = re.search(r"ACTION:\s*(\{.*\})", text, re.DOTALL | re.IGNORECASE)
        if match:
            try:
                # Clean up json if markdown formatted
                json_str = match.group(1).strip()
                if json_str.startswith("```"):
                   json_str =  re.sub(r'^```(?:json)?', '', json_str).strip()
                   json_str = re.sub(r'```$', '', json_str).strip()
                return json.loads(json_str)
            except:
                return None
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
                return f"Recon complete. Found {len(new_endpoints)} endpoints. Endpoints: {json.dumps(new_endpoints[:5])}"

            elif tool_name == "read_code":
                if not self._sast_engine: return "Error: No local codebase available."
                path = params.get("path")
                content = self._sast_engine.get_file_content(path)
                if content:
                    self.world_model["code_files"].append(path)
                    return f"Content of {path} (truncated): {content[:1000]}..."
                return f"Error: Could not read {path}."

            elif tool_name == "analyze_sast":
                context = params.get("code_context")
                sinks = llm.identify_sinks(context)
                for sink in sinks:
                    if self.on_finding:
                        await self.on_finding(sink)
                return f"SAST Analysis found {len(sinks)} potential sinks. Findings: {json.dumps(sinks)}"

            elif tool_name == "fuzz_endpoint":
                # In a real scenario, we'd run the actual fuzzer. 
                # For this implementation, we interface with the existing Fuzzer class.
                endpoint = params.get("endpoint_data")
                if not endpoint or not self.is_url: return "Error: Invalid target or endpoint."
                
                fuzzer = Fuzzer([endpoint], self.session_cookie, [], {})
                anomalies = fuzzer.run_fuzzer(base_url=self.target)
                
                analyzed = llm.analyze_anomalies(anomalies)
                for finding in analyzed:
                    if self.on_finding:
                        await self.on_finding(finding)
                return f"Fuzzing complete. Found {len(analyzed)} potential vulnerabilities."

            elif tool_name == "verify_finding":
                finding = params.get("finding_data")
                code = finding.get("code") or (self._sast_engine.get_file_content(finding.get("file_path")) if self._sast_engine else "")
                payload = finding.get("payload")
                vtype = finding.get("vulnerability_type", "unknown")
                
                if not code or not payload: return "Error: Code or payload missing for verification."
                
                result, msg = await asyncio.to_thread(self._sandbox.verify_exploit, code, payload, vtype)
                return f"Sandbox outcome: {'VERIFIED' if result else 'BLOCKED'}. Message: {msg}"

            return f"Error: Tool '{tool_name}' not implemented."
        except Exception as e:
            return f"Exception in tool {tool_name}: {str(e)}"
