import json
from typing import Any, Dict, List, Optional, Callable, Awaitable
from abc import ABC, abstractmethod

class AgentContext:
    """Shared state between agents."""
    def __init__(self, target: str, world_model: Dict[str, Any]):
        self.target = target
        self.world_model = world_model
        self.history: List[Dict[str, Any]] = []

class BaseAgent(ABC):
    """Abstract base class for all specialized agents."""
    
    def __init__(self, persona_name: str, description: str):
        self.persona_name = persona_name
        self.description = description

    @abstractmethod
    def get_system_prompt(self, context: AgentContext) -> str:
        """Generate the system prompt for this agent."""
        pass

    def _get_format_instructions(self) -> str:
        return """
FORMAT INSTRUCTIONS (MANDATORY):
You MUST respond with EXACTLY this structure. No exceptions.

THOUGHT: <one sentence explaining what you will do next and why>
ACTION: {"tool": "<tool_name>", "params": {"<arg>": "<value>"}}

CRITICAL RULES:
- The ACTION line must contain ONLY the raw JSON object. No markdown, no backticks.
- Choose a DIFFERENT tool or file than what you used in your recent history.
- If audit is complete, use: ACTION: {"tool": "finish", "params": {}}
"""

    def _format_history(self, context: AgentContext) -> str:
        """Show the last 8 actions so the agent doesn't repeat itself."""
        if not context.history:
            return ""
        recent = context.history[-8:]
        lines = ["--- YOUR RECENT ACTIONS (DO NOT REPEAT THESE) ---"]
        for h in recent:
            tool = h.get("action", {}).get("tool", "unknown")
            params = h.get("action", {}).get("params", {})
            obs_preview = str(h.get("observation", ""))[:120].replace("\n", " ")
            lines.append(f"  ✓ {tool}({json.dumps(params)}) → {obs_preview}...")
        lines.append("--------------------------------------------------")
        return "\n".join(lines) + "\n"

    def get_correction_prompt(self, context: AgentContext, action: Dict, observation: Any) -> str:
        """Generate a prompt to ask the agent to self-correct based on a tool failure or suboptimal result."""
        return f"""
VULNPILOT SELF-CORRECTION PROTOCOL
Agent: {self.persona_name}
Action Taken: {json.dumps(action)}
Observation: {str(observation)[:1000]}

Goal: {context.target}

CRITICAL: The previous action did not yield the expected results or was blocked. 
Analyze the failure and provide a REFINED ACTION.

If you believe you cannot proceed further, respond with ACTION: {{"tool": "finish", "params": {{}}}}.
Otherwise, respond with your reasoning and a new action.

THOUGHT: <your analysis of why the previous action failed>
ACTION: {{"tool": "<new_tool>", "params": {{"<arg>": "<value>"}}}}
"""

    async def process_observation(self, action: Dict, observation: Any, context: AgentContext) -> str:
        """Analyze the result of a tool execution for logging and history."""
        return f"{self.persona_name} processed {action.get('tool')}."

    def _format_world_model(self, world_model: Dict[str, Any]) -> str:
        # Avoid dumping entire code content - just show keys + file list
        summary = {
            "current_stage": world_model.get("current_stage"),
            "endpoints_count": len(world_model.get("endpoints", [])),
            "code_files": world_model.get("code_files", [])[:20],
            "verified_findings_count": len(world_model.get("verified_findings", [])),
            "strategic_notes": world_model.get("strategic_notes", []),
        }
        return json.dumps(summary, indent=2)

    def _format_blackboard(self, context: AgentContext) -> str:
        notes = context.world_model.get("strategic_notes", [])
        if not notes:
            return "Strategic Blackboard: No insights posted yet.\n"
        
        formatted_notes = "\n".join([f"- {note}" for note in notes])
        return f"--- STRATEGIC BLACKBOARD (Shared Insights) ---\n{formatted_notes}\n"
