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
            response = llm._call_llm(prompt, config=self.llm_config)
            
            # 1. Handle LLM Provider Errors (e.g. Rate Limits)
            if response.startswith("Error:") or "rate limit" in response.lower() or "429" in response:
                wait_time = 10 if ("429" in response or "rate limit" in response.lower()) else 3
                await self._think(f"⚠️ Provider Alert: {response[:100]}... Pausing for {wait_time}s to recover.")
                await asyncio.sleep(wait_time)
                continue # Retry same step

            # 2. Parse reasoning and action
            reasoning = self._extract_reasoning(response)
            action = self._extract_action(response)
            
            if reasoning:
                await self._think(reasoning)
            
            if not action or action.get("tool") == "finish":
                # If we have no action but also no error, the LLM might be confused.
                if not reasoning and not action:
                    await self._think("I'm having trouble formulating the next step. Re-evaluating...")
                    await asyncio.sleep(2)
                    continue
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
            
            # 3. Defensive Throttle (Stay within free-tier burst limits)
            await asyncio.sleep(1)

    def _get_summarized_state(self) -> str:
        """Compresses the world model into a readable summary for the AI."""
        endpoints = self.world_model.get("endpoints", [])
        code_files = self.world_model.get("code_files", [])
        summary = {
            "current_stage": self.world_model.get("current_stage"),
            "verified_findings_count": len(self.world_model.get("verified_findings", [])),
            "discovery_summary": ""
        }

        # Summarize Endpoints
        if len(endpoints) > 15:
            # Group by first path segment
            groups = {}
            for e in endpoints:
                url = e.get("url", "") if isinstance(e, dict) else str(e)
                parts = url.strip("/").split("/")
                prefix = f"/{parts[0]}" if parts[0] else "/"
                groups[prefix] = groups.get(prefix, 0) + 1
            
            summary["discovery_summary"] = f"Found {len(endpoints)} total endpoints. Groups: " + \
                ", ".join([f"{k} ({v} pages)" for k, v in sorted(groups.items(), key=lambda x: x[1], reverse=True)[:5]])
            if len(groups) > 5: summary["discovery_summary"] += " ..."
        else:
            summary["endpoints"] = endpoints[:15]

        # Summarize Code
        if len(code_files) > 10:
            summary["code_summary"] = f"Audited {len(code_files)} files so far."
        else:
            summary["code_files"] = code_files

        return json.dumps(summary, indent=2)

    def _build_prompt(self, goal: str) -> str:
        state_summary = self._get_summarized_state()
        history_summary = ""
        for h in self.history[-5:]: # More history for better context
            history_summary += f"Step {h['step']} Thought: {h['thought']}\nStep {h['step']} Action: {h['action']['tool']}\nStep {h['step']} Observation: {str(h['observation'])[:300]}\n\n"

        return f"""
You are the VulnPilot Security Consultant, a friendly and expert virtual security advisor.
Your Goal: {goal}
Target: {self.target}

Mission instructions:
- Speak in plain, non-technical English in your THOUGHT section.
- Instead of "SCA", say "checking for outdated parts".
- Instead of "SAST", say "auditing the code for mistakes".
- Instead of "DAST" or "Fuzzing", say "testing how the app handles unexpected input".
- Be professional, transparent, and reassuring.

Available Actions:
1. `recon_attack_surface(url)`: Map out the website's structure and public pages.
2. `read_code(path)`: Review a specific file in the project.
3. `analyze_sast(code_context)`: Perform a detailed code audit for security flaws.
4. `fuzz_endpoint(endpoint_data)`: Run tests to see how the app reacts to unusual behavior.
5. `verify_finding(finding_data)`: Double-check a potential issue to see if it is a real threat.
6. `finish()`: End the audit and summarize the results.

Current Progress:
{state_summary}

Recent Activity:
{history_summary}

Rules:
- Always provide a "THOUGHT" in plain English.
- Always provide an "ACTION" in valid JSON format.
- Format:
THOUGHT: <Clear, easy-to-understand explanation of what you are doing next>
ACTION: {{"tool": "<action_name>", "params": {{...}}}}
"""

    def _extract_reasoning(self, text: str) -> str:
        match = re.search(r"THOUGHT:\s*(.*?)(?=ACTION:|$)", text, re.DOTALL | re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _extract_action(self, text: str) -> Optional[Dict]:
        """Robustly extracts JSON action even with conversational noise."""
        if text.startswith("Error:") or "429" in text:
            return None # Don't try to parse error strings as actions

        # Look for the last JSON-like block in the text
        pattern = r"ACTION:\s*(.*)"
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if not match:
            # Fallback: find any JSON block that looks like a tool call
            match = re.search(r'(\{\s*"tool":\s*".*"\})', text, re.DOTALL)
            
        if match:
            try:
                raw_json = match.group(0 if "ACTION:" not in text.upper() else 1).strip()
                # Clean markdown blocks
                if "```" in raw_json:
                    raw_json = re.sub(r"```(?:json)?", "", raw_json).strip()
                    raw_json = re.sub(r"```", "", raw_json).strip()
                
                # Ensure we start at the first {
                if "{" in raw_json:
                    raw_json = raw_json[raw_json.find("{"):]
                # Ensure we end at the last }
                if "}" in raw_json:
                    raw_json = raw_json[:raw_json.rfind("}")+1]
                
                parsed = json.loads(raw_json)
                # Validation: must have 'tool'
                if isinstance(parsed, dict) and "tool" in parsed:
                    return parsed
                return None
            except Exception as e:
                print(f"[!] JSON Parse Error: {e} | Raw: {text[:100]}...")
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
                sinks = llm.identify_sinks(context, llm_config=self.llm_config)
                for sink in sinks:
                    if self.on_finding:
                        await self.on_finding(sink)
                return f"SAST Analysis found {len(sinks)} potential sinks. Findings: {json.dumps(sinks)}"

            elif tool_name == "fuzz_endpoint":
                # In a real scenario, we'd run the actual fuzzer. 
                # For this implementation, we interface with the existing Fuzzer class.
                endpoint = params.get("endpoint_data")
                if not endpoint or not self.is_url: return "Error: Invalid target or endpoint."
                
                fuzzer = Fuzzer([endpoint], self.session_cookie, [], {}, llm_config=self.llm_config)
                anomalies = fuzzer.run_fuzzer(base_url=self.target)
                
                analyzed = llm.analyze_anomalies(anomalies, llm_config=self.llm_config)
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
