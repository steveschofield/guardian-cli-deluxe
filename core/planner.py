"""
Strategic Planner Agent
Decides next steps in the penetration testing workflow
"""

import re
from typing import Dict, Any
from core.agent import BaseAgent
from ai.prompt_templates import (
    PLANNER_SYSTEM_PROMPT,
    PLANNER_DECISION_PROMPT,
    PLANNER_ANALYSIS_PROMPT
)


class PlannerAgent(BaseAgent):
    """Strategic planner that decides next pentest steps"""
    
    def __init__(self, config, llm_client, memory):
        super().__init__("Planner", config, llm_client, memory)
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Decide the next action in the penetration test"""
        return await self.decide_next_action()
    
    async def decide_next_action(self) -> Dict[str, Any]:
        """
        Analyze current state and decide next action
        
        Returns:
            Dict with next_action, parameters, reasoning
        """
        # Build context
        context = self.memory.get_context_for_ai()
        findings_summary = self._format_findings()
        available_actions = self._get_available_actions()
        
        prompt = PLANNER_DECISION_PROMPT.format(
            phase=self.memory.current_phase,
            target=self.memory.target,
            completed_actions="\n".join(f"- {a}" for a in self.memory.completed_actions) or "None",
            findings=findings_summary,
            available_actions=available_actions
        )
        
        # Get AI decision
        result = await self.think(prompt, PLANNER_SYSTEM_PROMPT)
        
        # Parse the response
        decision = self._parse_decision(result["response"])
        decision["reasoning"] = result["reasoning"]
        
        self.log_action("Decision", decision.get("next_action", "Unknown"))
        
        return decision
    
    async def analyze_results(self) -> Dict[str, str]:
        """Provide strategic analysis of pentest results"""
        findings_summary = self._format_findings()
        tools_executed = "\n".join(
            f"- {t.tool} on {t.target}" for t in self.memory.tool_executions
        )
        
        prompt = PLANNER_ANALYSIS_PROMPT.format(
            target=self.memory.target,
            phase=self.memory.current_phase,
            findings_summary=findings_summary,
            tools_executed=tools_executed or "None"
        )
        
        result = await self.think(prompt, PLANNER_SYSTEM_PROMPT)
        
        return result
    
    def _format_findings(self) -> str:
        """Format findings for AI consumption"""
        if not self.memory.findings:
            return "No findings yet"
        
        findings_by_severity = {}
        for finding in self.memory.findings:
            if not finding.false_positive:
                severity = finding.severity.lower()
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding.title)
        
        formatted = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in findings_by_severity:
                formatted.append(f"\n{severity.upper()}:")
                for title in findings_by_severity[severity]:
                    formatted.append(f"  - {title}")
        
        return "\n".join(formatted)
    
    def _get_available_actions(self) -> str:
        """Get list of available actions based on current phase"""
        all_actions = {
            "reconnaissance": [
                "subdomain_enumeration - Discover subdomains (domains only)",
                "dns_enumeration - Gather DNS records (domains only)",
                "technology_detection - Identify web technologies",
                "port_scanning - Scan for open ports"
            ],
            "scanning": [
                "service_detection - Identify services on open ports",
                "vulnerability_scanning - Run vulnerability scanners",
                "web_probing - Probe web services",
                "ssl_analysis - Analyze SSL/TLS configuration"
            ],
            "analysis": [
                "correlate_findings - Combine data from multiple tools",
                "risk_assessment - Analyze security posture",
                "false_positive_filter - Filter out false positives",
                "prioritize_vulns - Rank vulnerabilities by risk"
            ],
            "reporting": [
                "generate_report - Create final report",
                "executive_summary - Write executive summary",
                "remediation_plan - Create fix recommendations"
            ]
        }
        
        phase = self.memory.current_phase
        actions = all_actions.get(phase, all_actions["reconnaissance"])
        
        return "\n".join(f"- {action}" for action in actions)
    
    def _parse_decision(self, response: str) -> Dict[str, Any]:
        """Parse AI response into structured decision"""
        decision = {
            "next_action": "unknown",
            "parameters": {},
            "expected_outcome": ""
        }
        
        # Simple parsing of the AI response
        if "NEXT_ACTION:" in response:
            start = response.find("NEXT_ACTION:") + len("NEXT_ACTION:")
            end = response.find("PARAMETERS:", start) if "PARAMETERS:" in response else len(response)
            decision["next_action"] = response[start:end].strip()
        
        if "PARAMETERS:" in response:
            start = response.find("PARAMETERS:") + len("PARAMETERS:")
            end = response.find("EXPECTED_OUTCOME:", start) if "EXPECTED_OUTCOME:" in response else len(response)
            decision["parameters"] = response[start:end].strip()
        
        if "EXPECTED_OUTCOME:" in response:
            start = response.find("EXPECTED_OUTCOME:") + len("EXPECTED_OUTCOME:")
            decision["expected_outcome"] = response[start:].strip()
        
        # Normalize common variants and extract known action tokens
        aliases = {
            "automated_web_scanning": "web_probing",
            "exploitation": "vulnerability_scanning",
            "web_scanning": "web_probing",
            "report": "generate_report",
            "port_scan": "port_scanning",
            "port_scans": "port_scanning",
            "portscanner": "port_scanning",
            "dns_scan": "dns_enumeration",
            "subdomain_scan": "subdomain_enumeration",
            "vuln_scan": "vulnerability_scanning",
            "vuln_scanning": "vulnerability_scanning",
            "web_scan": "web_probing",
            "tech_detection": "technology_detection",
        }

        valid_actions = {
            "subdomain_enumeration",
            "dns_enumeration",
            "technology_detection",
            "port_scanning",
            "service_detection",
            "vulnerability_scanning",
            "web_probing",
            "ssl_analysis",
            "correlate_findings",
            "risk_assessment",
            "false_positive_filter",
            "prioritize_vulns",
            "generate_report",
            "executive_summary",
            "remediation_plan",
            "fuzzing",
            "analysis",
        }

        action_clean = decision["next_action"].strip().lower()
        # Strip common markdown formatting without breaking underscore-delimited action names.
        action_clean = re.sub(r"[*`]+", "", action_clean).strip().strip("_").strip()
        # Normalize common natural-language variants like "Web Probing" -> "web_probing".
        action_clean = re.sub(r"[\s\-]+", "_", action_clean)
        action_clean = re.sub(r"[^a-z0-9_]+", "", action_clean)
        action_clean = re.sub(r"_+", "_", action_clean).strip("_")

        # Extract known action if embedded in numbering/formatting
        if action_clean and action_clean not in valid_actions:
            pattern = "|".join(sorted(valid_actions, key=len, reverse=True))
            match = re.search(pattern, action_clean)
            if match:
                action_clean = match.group(0)

        # Apply aliases on cleaned action
        if action_clean in aliases:
            action_clean = aliases[action_clean]
        else:
            for key, value in aliases.items():
                if key in action_clean:
                    action_clean = value
                    break

        decision["next_action"] = action_clean

        # Validate next_action against known actions; if invalid, mark unknown
        if decision["next_action"] not in valid_actions:
            decision["next_action"] = "unknown"
            decision["expected_outcome"] = ""
            decision["parameters"] = {}

        return decision
