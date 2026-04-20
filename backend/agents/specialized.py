from .base import BaseAgent, AgentContext
from typing import Any, Dict, List

class ScoutAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            "Scout", 
            "Focused on reconnaissance and attack surface mapping. Your goal is to find all possible entry points."
        )

    def get_system_prompt(self, context: AgentContext) -> str:
        knowledge_str = self._format_knowledge(context.world_model.get("recalled_knowledge", []))
        return f"""
You are the VulnPilot 'Scout' Agent.
Your Goal: Map out the target attack surface ({context.target}).
Specialty: Reconnaissance, crawling, and hidden endpoint discovery.

{knowledge_str}

Available Actions:
- `recon_attack_surface(url)`: Map website structure.
- `finish()`: Hand over to the Orchestrator when surface is mapped.

Current World Model:
{self._format_world_model(context.world_model)}
"""

    def _format_knowledge(self, knowledge: List[Dict]) -> str:
        if not knowledge: return ""
        lines = ["--- RECALLED KNOWLEDGE (FROM PAST MISSIONS) ---"]
        for k in knowledge:
            lines.append(f"- Pattern: {k['document']}")
            lines.append(f"  Note: Past success rate: {k['metadata'].get('success_rate', 1.0):.2f}")
        return "\n".join(lines) + "\n"

    async def process_observation(self, action: Dict, observation: Any, context: AgentContext) -> str:
        return f"Scout analyzed {action.get('tool')}: {str(observation)[:500]}"


class AuditorAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            "Auditor", 
            "Focused on code review and finding static vulnerabilities (SAST)."
        )

    def get_system_prompt(self, context: AgentContext) -> str:
        knowledge_str = self._format_knowledge(context.world_model.get("recalled_knowledge", []))
        return f"""
You are the VulnPilot 'Auditor' Agent.
Your Goal: Identify vulnerabilities in the source code or configurations.
Specialty: SAST analysis, reading code, and identifying security sinks.

{knowledge_str}

Available Actions:
- `read_code(path)`: Review a file.
- `analyze_sast(code_context)`: Perform deep audit for security flaws.
- `finish()`: Hand over to the Orchestrator when the code audit is complete.

Current World Model:
{self._format_world_model(context.world_model)}
"""

    def _format_knowledge(self, knowledge: List[Dict]) -> str:
        if not knowledge: return ""
        lines = ["--- RECALLED KNOWLEDGE (FROM PAST MISSIONS) ---"]
        for k in knowledge:
            lines.append(f"- Vulnerability: {k['metadata'].get('vulnerability_type')}")
            lines.append(f"  Context: {k['document']}")
        return "\n".join(lines) + "\n"

    async def process_observation(self, action: Dict, observation: Any, context: AgentContext) -> str:
        return f"Auditor analyzed {action.get('tool')}: {str(observation)[:500]}"


class RedTeamAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            "RedTeam", 
            "Focused on active exploitation, fuzzing, and verification (DAST)."
        )

    def get_system_prompt(self, context: AgentContext) -> str:
        knowledge_str = self._format_knowledge(context.world_model.get("recalled_knowledge", []))
        return f"""
You are the VulnPilot 'RedTeam' Agent.
Your Goal: Verify findings and exploit endpoints to prove high-severity risks.
Specialty: Fuzzing, exploit verification, and dynamic testing.

{knowledge_str}

Available Actions:
- `fuzz_endpoint(endpoint_data)`: Active dynamic testing.
- `verify_finding(finding_data)`: Sandbox exploit verification.
- `finish()`: End the mission and summarize findings.

Current World Model:
{self._format_world_model(context.world_model)}
"""

    def _format_knowledge(self, knowledge: List[Dict]) -> str:
        if not knowledge: return ""
        lines = ["--- RECALLED PAYLOADS (FROM PAST SUCCESSES) ---"]
        for k in knowledge:
            lines.append(f"- Exploit: {k['metadata'].get('vulnerability_type')}")
            lines.append(f"  Payload: {k['metadata'].get('payload')}")
            lines.append(f"  Proved Efficacy: {k['metadata'].get('success_rate', 1.0):.2f}")
        return "\n".join(lines) + "\n"

    async def process_observation(self, action: Dict, observation: Any, context: AgentContext) -> str:
        return f"RedTeam analyzed {action.get('tool')}: {str(observation)[:500]}"
