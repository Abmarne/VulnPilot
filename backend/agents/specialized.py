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
        blackboard_str = self._format_blackboard(context)
        history_str = self._format_history(context)
        return f"""
You are the VulnPilot 'Scout' Agent.
Your Goal: Map out the target attack surface ({context.target}).
Specialty: Reconnaissance, crawling, and hidden endpoint discovery.

{knowledge_str}
{blackboard_str}
{history_str}

Available Tools:
- recon_attack_surface: Map website structure. params: {{"url": "<target_url>"}}
- post_strategic_note: Share an insight on the Blackboard. params: {{"note": "<insight>"}}
- request_human_intercept: Ask a human for help. params: {{"question": "<question>"}}
- finish: Hand over when surface is fully mapped. params: {{}}

Current World Model:
{self._format_world_model(context.world_model)}

{self._get_format_instructions()}
"""

    def _format_knowledge(self, knowledge: List[Dict]) -> str:
        if not knowledge: return ""
        lines = ["--- RECALLED KNOWLEDGE (FROM PAST MISSIONS) ---"]
        for k in knowledge:
            lines.append(f"- Pattern: {k['document']}")
            lines.append(f"  Note: Past success rate: {k['metadata'].get('success_rate', 1.0):.2f}")
        return "\n".join(lines) + "\n"

    async def process_observation(self, action: Dict, observation: Any, context: AgentContext) -> str:
        return f"Scout successfully mapped {len(context.world_model.get('endpoints', []))} endpoints."

    def get_correction_prompt(self, context: AgentContext, action: Dict, observation: Any) -> str:
        prompt = super().get_correction_prompt(context, action, observation)
        return prompt + "\nHint: If the crawl found nothing, try checking for common sensitive paths or different entry points."


class AuditorAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            "Auditor", 
            "Focused on code review and finding static vulnerabilities (SAST)."
        )

    def get_system_prompt(self, context: AgentContext) -> str:
        knowledge_str = self._format_knowledge(context.world_model.get("recalled_knowledge", []))
        blackboard_str = self._format_blackboard(context)
        history_str = self._format_history(context)
        
        # Build list of unread files
        all_files = context.world_model.get("code_files", [])
        read_files = [
            h.get("action", {}).get("params", {}).get("path", "")
            for h in context.history
            if h.get("action", {}).get("tool") == "read_code"
        ]
        unread_files = [f for f in all_files if f not in read_files][:15]
        
        files_section = ""
        if unread_files:
            files_section = "FILES AVAILABLE TO READ (prioritize these):\n" + "\n".join(f"  - {f}" for f in unread_files)
        elif all_files:
            files_section = "All priority files have been read. Run analyze_sast or finish."
        
        return f"""
You are the VulnPilot 'Auditor' Agent.
Your Goal: Identify vulnerabilities in the source code or configurations.
Specialty: SAST analysis, reading code, and identifying security sinks.

{knowledge_str}
{blackboard_str}
{history_str}

{files_section}

Available Tools:
- read_code: Review a specific file. params: {{"path": "<relative_file_path>"}}
- analyze_sast: Perform deep audit using collected code context. params: {{"code_context": "<pasted_code_snippet>"}}
- post_strategic_note: Share insight on the Blackboard. params: {{"note": "<insight>"}}
- request_human_intercept: Ask human for help ONLY if truly blocked. params: {{"question": "<question>"}}
- finish: Call this when audit is complete. params: {{}}

Current World Model:
{self._format_world_model(context.world_model)}

{self._get_format_instructions()}
"""

    def _format_knowledge(self, knowledge: List[Dict]) -> str:
        if not knowledge: return ""
        lines = ["--- RECALLED KNOWLEDGE (FROM PAST MISSIONS) ---"]
        for k in knowledge:
            lines.append(f"- Vulnerability: {k['metadata'].get('vulnerability_type')}")
            lines.append(f"  Context: {k['document']}")
        return "\n".join(lines) + "\n"

    async def process_observation(self, action: Dict, observation: Any, context: AgentContext) -> str:
        return f"Auditor is analyzing findings. {len(context.world_model.get('code_files', []))} files read so far."

    def get_correction_prompt(self, context: AgentContext, action: Dict, observation: Any) -> str:
        prompt = super().get_correction_prompt(context, action, observation)
        return prompt + "\nHint: If code reading failed, check if the file path is correct or if you need to read a parent directory."


class RedTeamAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            "RedTeam", 
            "Focused on active exploitation, fuzzing, and verification (DAST)."
        )

    def get_system_prompt(self, context: AgentContext) -> str:
        knowledge_str = self._format_knowledge(context.world_model.get("recalled_knowledge", []))
        blackboard_str = self._format_blackboard(context)
        history_str = self._format_history(context)
        return f"""
You are the VulnPilot 'RedTeam' Agent.
Your Goal: Verify findings and exploit endpoints to prove high-severity risks.
Specialty: Fuzzing, exploit verification, and dynamic testing.

{knowledge_str}
{blackboard_str}
{history_str}

Available Tools:
- fuzz_endpoint: Active dynamic testing. params: {{"endpoint_data": "<endpoint_url>"}}
- verify_finding: Sandbox exploit verification. params: {{"finding_data": {{"vulnerability_type": "...", "file_path": "...", "payload": "..."}}}}
- post_strategic_note: Share insight on the Blackboard. params: {{"note": "<insight>"}}
- request_human_intercept: Ask human for bypass tokens/MFA. params: {{"question": "<question>"}}
- finish: End mission when exploitation is complete. params: {{}}

Current World Model:
{self._format_world_model(context.world_model)}

{self._get_format_instructions()}
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
        return f"RedTeam has verified {len(context.world_model.get('verified_findings', []))} vulnerabilities."

    def get_correction_prompt(self, context: AgentContext, action: Dict, observation: Any) -> str:
        prompt = super().get_correction_prompt(context, action, observation)
        return prompt + "\nHint: If the payload was blocked, consider WAF evasion (encoding, case-switching) or logical bypasses."
