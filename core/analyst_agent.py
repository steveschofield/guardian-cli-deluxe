"""
Analyst Agent
Interprets scan results and identifies security vulnerabilities
"""

from typing import Dict, Any, List
from datetime import datetime
from core.agent import BaseAgent
from core.memory import Finding
from ai.prompt_templates import (
    ANALYST_SYSTEM_PROMPT,
    ANALYST_INTERPRET_PROMPT,
    ANALYST_CORRELATION_PROMPT,
    ANALYST_FALSE_POSITIVE_PROMPT
)
from utils.helpers import parse_severity


class AnalystAgent(BaseAgent):
    """Agent that analyzes scan results and extracts security findings"""
    
    def __init__(self, config, llm_client, memory):
        super().__init__("Analyst", config, llm_client, memory)
    
    async def execute(self, tool_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze tool output and extract findings
        
        Args:
            tool_result: Results from a tool execution
        
        Returns:
            Dict with extracted findings and analysis
        """
        return await self.interpret_output(
            tool=tool_result["tool"],
            target=tool_result.get("target", "unknown"),
            command=tool_result.get("command", ""),
            output=tool_result.get("raw_output", "")
        )
    
    async def interpret_output(
        self,
        tool: str,
        target: str,
        command: str,
        output: str
    ) -> Dict[str, Any]:
        """
        Interpret tool output and extract security findings
        
        Returns:
            Dict with findings, summary, and analysis
        """
        # Short-circuit on empty/error-only output
        if not output.strip() or "Output file format specified without a name" in output:
            msg = "No actionable output from tool; skipping findings."
            self.log_action("AnalysisComplete", msg)
            return {
                "findings": [],
                "summary": msg,
                "reasoning": msg,
                "tool": tool
            }

        # Truncate very long outputs
        if len(output) > 5000:
            output = output[:5000] + "\n... (truncated)"
        
        prompt = ANALYST_INTERPRET_PROMPT.format(
            tool=tool,
            target=target,
            command=command,
            output=output
        )
        
        result = await self.think(prompt, ANALYST_SYSTEM_PROMPT)
        
        # Parse findings from AI response
        findings = self._parse_findings(result["response"], tool, target)

        # Drop findings whose evidence isn't in the raw output (reduces hallucinations)
        filtered = []
        output_lower = output.lower()
        low_signal_tools = {"nmap", "whatweb", "httpx"}
        for f in findings:
            if f.evidence and f.evidence.lower() in output_lower:
                if f.tool in low_signal_tools and f.severity in {"critical", "high", "medium"}:
                    ev = f.evidence.lower()
                    if not any(token in ev for token in ["cve", "vulnerab", "exploit", "xss", "sqli", "sql injection", "rce", "csrf"]):
                        continue
                filtered.append(f)
        findings = filtered

        # If still nothing with evidence, return empty
        if not findings:
            msg = "No evidence-backed findings; output deemed informational."
            self.log_action("AnalysisComplete", msg)
            return {
                "findings": [],
                "summary": msg,
                "reasoning": msg,
                "tool": tool
            }
        
        # Add findings to memory
        for finding in findings:
            self.memory.add_finding(finding)
        
        self.log_action("AnalysisComplete", f"Found {len(findings)} issues from {tool}")
        
        return {
            "findings": findings,
            "summary": result["response"],
            "reasoning": result["reasoning"],
            "tool": tool
        }
    
    async def correlate_findings(self) -> Dict[str, Any]:
        """
        Correlate findings from multiple tools to build attack chains
        
        Returns:
            Strategic analysis of all findings
        """
        if not self.memory.findings:
            return {
                "correlations": [],
                "attack_chains": [],
                "priority_findings": []
            }
        
        # Format findings for AI
        tool_results = self._format_findings_for_correlation()
        
        prompt = ANALYST_CORRELATION_PROMPT.format(
            target=self.memory.target,
            tool_results=tool_results
        )
        
        result = await self.think(prompt, ANALYST_SYSTEM_PROMPT)
        
        return {
            "analysis": result["response"],
            "reasoning": result["reasoning"],
            "findings_count": len(self.memory.findings)
        }
    
    async def check_false_positive(self, finding: Finding) -> Dict[str, Any]:
        """
        Evaluate if a finding is likely a false positive
        
        Returns:
            Dict with confidence score and recommendation
        """
        # Get context
        context = self.memory.get_context_for_ai()
        
        prompt = ANALYST_FALSE_POSITIVE_PROMPT.format(
            tool=finding.tool,
            severity=finding.severity,
            description=finding.description,
            evidence=finding.evidence[:500],  # Truncate
            context=context
        )
        
        result = await self.think(prompt, ANALYST_SYSTEM_PROMPT)
        
        # Parse confidence from response
        confidence = self._extract_confidence(result["response"])
        
        return {
            "confidence": confidence,
            "analysis": result["response"],
            "reasoning": result["reasoning"],
            "recommendation": self._extract_recommendation(result["response"])
        }
    
    def _parse_findings(self, ai_response: str, tool: str, target: str) -> List[Finding]:
        """Parse findings from AI analysis response"""
        findings: List[Finding] = []
        severity_markers = ["critical", "high", "medium", "low", "info"]

        lines = [l.strip() for l in ai_response.splitlines() if l.strip()]
        current: Optional[Finding] = None

        for line in lines:
            # Match patterns like "[High]" or "1. [Critical]" or "HIGH:"
            import re
            sev_match = re.search(r"\[?\b(critical|high|medium|low|info)\b\]?", line, re.IGNORECASE)
            if sev_match:
                severity = sev_match.group(1).lower()
                # finalize previous
                if current:
                    findings.append(current)
                # derive title after the severity marker
                title_part = re.sub(r"^\s*\d+[\.\)]\s*", "", line)  # drop numbering
                title_part = re.sub(r"\[?\b(critical|high|medium|low|info)\b\]?:?", "", title_part, flags=re.IGNORECASE)
                title = title_part.strip(":- ").strip()
                if not title:
                    title = f"{severity.title()} finding"

                current = Finding(
                    id=f"{tool}_{len(findings)}_{datetime.now().timestamp()}",
                    severity=severity,
                    title=title[:200],
                    description="",
                    evidence="",
                    tool=tool,
                    target=target,
                    timestamp=datetime.now().isoformat()
                )
                continue

            if current:
                # Evidence line
                if "evidence:" in line.lower():
                    evidence_text = line.split("Evidence:")[-1].strip()
                    current.evidence = evidence_text
                else:
                    current.description += line + "\n"

        if current:
            findings.append(current)

        return findings
    
    def _format_findings_for_correlation(self) -> str:
        """Format findings for correlation analysis"""
        by_tool = {}
        for finding in self.memory.findings:
            if finding.tool not in by_tool:
                by_tool[finding.tool] = []
            by_tool[finding.tool].append(finding)
        
        formatted = []
        for tool, findings in by_tool.items():
            formatted.append(f"\n{tool.upper()}:")
            for f in findings:
                formatted.append(f"  [{f.severity.upper()}] {f.title}")
        
        return "\n".join(formatted)
    
    def _extract_confidence(self, response: str) -> int:
        """Extract confidence percentage from response"""
        if "CONFIDENCE:" in response:
            start = response.find("CONFIDENCE:") + len("CONFIDENCE:")
            end = start + 10
            confidence_str = response[start:end].strip()
            
            # Extract number
            import re
            match = re.search(r'(\d+)', confidence_str)
            if match:
                return int(match.group(1))
        
        return 50  # Default
    
    def _extract_recommendation(self, response: str) -> str:
        """Extract recommendation from response"""
        if "RECOMMENDATION:" in response:
            start = response.find("RECOMMENDATION:") + len("RECOMMENDATION:")
            recommendation = response[start:].strip()
            return recommendation.split('\n')[0]
        
        return "VERIFY_MANUALLY"
