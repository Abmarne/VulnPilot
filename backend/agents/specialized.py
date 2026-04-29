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
- recon_attack_surface: Map website structure. Use this if the target is a live website URL. params: {{"url": "<target_url>"}}
- post_strategic_note: Share an insight on the Blackboard for other agents. params: {{"note": "<insight>"}}
- request_human_intercept: Ask a human for help if you encounter MFA, CAPTCHA, or need credentials. params: {{"question": "<question>"}}
- finish: Call this only when you have a comprehensive map of endpoints. params: {{}}

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
    Your Goal: Identify EVERY possible vulnerability in the source code or configurations, explicitly mapping them to the OWASP Top 10.
    Specialty: Deep-dive SAST analysis, logic flow tracking, and OWASP Top 10 edge-case hunting.
    
    CRITICAL: Do not stop at the first 2-3 findings. A professional audit should find at least 5-10 issues including OWASP Top 10 flaws like Injection, Broken Access Control, SSRF, and even low-severity ones like missing security headers or insecure dependencies.

    IMPORTANT: The repository has ALREADY been cloned and mapped to a temporary directory for you. Do NOT try to use 'git_clone' or any external tools.
    Use 'get_full_context' as your FIRST action. If the code is truncated, use 'read_code' to follow the logic into specific files.

{knowledge_str}
{blackboard_str}
{history_str}

{files_section}

Available Tools:
- get_full_context: Get an overview of all critical files at once (EXTREMELY efficient). params: {{}}
- read_code: Review a specific file for deeper analysis. params: {{"path": "<relative_file_path>"}}
- analyze_sast: Perform a deep audit on the code. Pass 'file_path' to analyze a specific file, or leave parameters empty to audit all extracted critical files automatically. params: {{"file_path": "<optional_path>"}}
- post_strategic_note: Share insight on the Blackboard for the RedTeam to verify. params: {{"note": "<insight>"}}
- request_human_intercept: Ask human for help ONLY if truly blocked. params: {{"question": "<question>"}}
- finish: Call this when you have found all possible vulnerabilities in the code. params: {{}}

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
        return prompt + "\nHint: If 'get_full_context' was successful, do NOT call it again. Start analyzing the files listed in the context using 'analyze_sast' or 'read_code'."


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
Your Goal: Verify findings and actively exploit endpoints to prove high-severity OWASP Top 10 risks.
Specialty: Fuzzing, exploit verification, DAST, and proving OWASP Top 10 vulnerabilities (Injection, XSS, Broken Access Control, SSRF, etc.).

{knowledge_str}
{blackboard_str}
{history_str}

Available Tools:
- fuzz_endpoint: Perform active dynamic testing (fuzzing) on a URL. params: {{"endpoint_data": "<endpoint_url>"}}
- verify_finding: Use the secure sandbox to verify if a finding is exploitable. params: {{"finding_data": {{"vulnerability_type": "...", "file_path": "...", "payload": "..."}}}}
- post_strategic_note: Share insight or a confirmed exploit on the Blackboard. params: {{"note": "<insight>"}}
- request_human_intercept: Ask human for bypass tokens, MFA, or credentials. params: {{"question": "<question>"}}
- finish: Call this only when all findings are verified and the final report is ready. params: {{}}

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
