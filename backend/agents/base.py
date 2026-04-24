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

If you believe you cannot proceed further, respond with ACTION: finish().
Otherwise, respond with your reasoning and a new action.

Format:
THOUGHT: <your analysis of why the previous action failed>
ACTION: <your new tool call>
"""

    async def process_observation(self, action: Dict, observation: Any, context: AgentContext) -> str:
        """Analyze the result of a tool execution for logging and history."""
        return f"{self.persona_name} processed {action.get('tool')}."

    def _format_world_model(self, world_model: Dict[str, Any]) -> str:
        return json.dumps(world_model, indent=2)

    def _format_blackboard(self, context: AgentContext) -> str:
        notes = context.world_model.get("strategic_notes", [])
        if not notes:
            return "Strategic Blackboard: No insights posted yet."
        
        formatted_notes = "\n".join([f"- {note}" for note in notes])
        return f"--- STRATEGIC BLACKBOARD (Shared Insights) ---\n{formatted_notes}\n"
