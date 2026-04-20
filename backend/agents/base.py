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

    @abstractmethod
    async def process_observation(self, action: Dict, observation: Any, context: AgentContext) -> str:
        """Analyze the result of a tool execution."""
        pass

    def _format_world_model(self, world_model: Dict[str, Any]) -> str:
        return json.dumps(world_model, indent=2)
