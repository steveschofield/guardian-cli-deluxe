"""
Analyst Agent
Interprets scan results and identifies security vulnerabilities
"""

import re
import json
import html
from typing import Dict, Any, List, Optional
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

        # Reduce prompt bloat for Nmap XML by extracting only high-signal elements.
        if tool == "nmap" and output.lstrip().startswith("<?xml") and "<nmaprun" in output:
            hostscript_findings = self._extract_nmap_hostscript_findings(output, target)
            output = self._condense_nmap_xml(output)
        else:
            hostscript_findings = []

        # Reduce prompt bloat for Nuclei JSONL by stripping huge fields (request/response/template-encoded)
        # and keeping only high-signal, evidence-friendly elements.
        if tool == "nuclei":
            output = self._condense_nuclei_jsonl(output)

        # Truncate very long outputs (configurable)
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        max_chars = ai_cfg.get("max_tool_output_chars", 20000)
        try:
            max_chars = int(max_chars)
        except Exception:
            max_chars = 20000
        if max_chars > 0 and len(output) > max_chars:
            output = output[:max_chars] + "\n... (truncated)"
        
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
            if not f.evidence:
                continue

            evidence = f.evidence.strip()
            candidates = [
                evidence,
                evidence.strip("`"),
                evidence.strip("\"'"),
                evidence.strip("`\"'"),
            ]
            if not any(c and c.lower() in output_lower for c in candidates):
                continue

            # High/medium severity from low-signal tools is often speculative; downgrade unless we have a strong signature.
            if f.tool in low_signal_tools and f.severity in {"critical", "high", "medium"}:
                has_cve = bool(re.search(r"\bCVE-\d{4}-\d+\b", output, re.IGNORECASE) or re.search(r"\bCVE-\d{4}-\d+\b", evidence, re.IGNORECASE))
                has_strong_flag = any(token in evidence.lower() for token in ["cve", "vulnerab", "exploit", "sqli", "sql injection", "rce", "ssrf", "lfi", "rfi"])
                if not (has_cve or has_strong_flag):
                    f.severity = "low"

            filtered.append(f)
        findings = filtered

        findings = self._postprocess_findings(findings, tool=tool, output=output)

        # Merge in deterministic hostscript findings (e.g., smb-vuln-*), avoiding duplicates.
        if hostscript_findings:
            hostscript_findings = self._postprocess_findings(hostscript_findings, tool=tool, output=output)
            existing_keys = {
                (f.title.lower().strip(), (f.evidence or "").lower().strip()) for f in findings
            }
            for hf in hostscript_findings:
                key = (hf.title.lower().strip(), (hf.evidence or "").lower().strip())
                if key in existing_keys:
                    continue
                findings.append(hf)
                existing_keys.add(key)

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

    def _condense_nmap_xml(self, xml_text: str) -> str:
        """
        Condense Nmap XML into a smaller, evidence-friendly snippet set:
        - host status + hostnames
        - closed/open counts when present
        - open ports: <port>, <state>, <service>, and <script ...> start tags
        - hostscript: <script ...> start tags (vuln checks live here)

        Keeps verbatim XML tag strings so the model can cite evidence directly.
        """
        try:
            out: list[str] = []
            out.append("NMAP_XML_CONDENSED: true")

            # Host status line
            m = re.search(r"<status[^>]+/>", xml_text)
            if m:
                out.append(m.group(0))

            # Hostnames
            for hn in re.findall(r"<hostname[^>]+/>", xml_text):
                out.append(hn)

            # Extraports summary (closed/filtered counts)
            m = re.search(r"<extraports[^>]+>", xml_text)
            if m:
                out.append(m.group(0))

            # Extract open port blocks and then keep only high-signal tags from within each block.
            # NOTE: use regex word-boundaries like `\b` (not literal backslashes).
            port_blocks = re.findall(r"<port\b[\s\S]*?</port>", xml_text)
            open_blocks = [b for b in port_blocks if re.search(r'<state\b[^>]*state="open"', b)]

            out.append(f"OPEN_PORTS_FOUND: {len(open_blocks)}")

            for block in open_blocks:
                # Port header (includes protocol + portid)
                m = re.search(r"<port\b[^>]+>", block)
                if m:
                    out.append(m.group(0))

                m = re.search(r"<state\b[^>]+/>", block)
                if m:
                    out.append(m.group(0))

                m = re.search(r"<service\b[^>]+>", block)
                if m:
                    out.append(m.group(0))

                # Include script start tags (outputs like http-title, ssl-cert summary, etc.)
                scripts = re.findall(r"<script\b[^>]+>", block)
                # Keep at most a handful per port to prevent bloat.
                for s in scripts[:12]:
                    out.append(s)

                out.append("</port>")

            # Host-level scripts (e.g., smb-vuln-*).
            hostscript_match = re.search(r"<hostscript>([\s\S]*?)</hostscript>", xml_text)
            if hostscript_match:
                host_scripts = re.findall(r"<script\b[^>]+>", hostscript_match.group(1))
                out.append(f"HOSTSCRIPT_SCRIPTS_FOUND: {len(host_scripts)}")
                for s in host_scripts[:20]:
                    out.append(s)

            # Always include run summary if present
            m = re.search(r"<finished\\b[^>]+/>", xml_text)
            if m:
                out.append(m.group(0))

            return "\n".join(out)
        except Exception:
            return xml_text

    def _extract_nmap_hostscript_findings(self, xml_text: str, target: str) -> List[Finding]:
        """
        Extract high-signal vulnerabilities/weaknesses from Nmap <hostscript> output.
        This is deterministic to avoid LLM misses on critical findings.
        """
        findings: List[Finding] = []
        hostscript_match = re.search(r"<hostscript>([\s\S]*?)</hostscript>", xml_text)
        if not hostscript_match:
            return findings

        script_tags = re.findall(r"<script\b[^>]+>", hostscript_match.group(1))
        for tag in script_tags:
            id_match = re.search(r'id="([^"]+)"', tag)
            out_match = re.search(r'output="([^"]*)"', tag)
            if not id_match or not out_match:
                continue

            script_id = id_match.group(1)
            output_raw = html.unescape(out_match.group(1))
            output_text = output_raw.strip()
            if not output_text:
                continue

            lower = output_text.lower()
            if lower in {"false", "true"}:
                continue
            if "nt_status_access_denied" in lower or "access_denied" in lower:
                continue
            if "no reply from server" in lower and "vulnerable" not in lower:
                continue

            title = ""
            severity = ""
            description = ""
            evidence = ""

            if "vulnerable" in lower:
                # Try to extract the first meaningful title line after VULNERABLE:
                lines = [l.strip() for l in output_text.splitlines() if l.strip()]
                if lines and "vulnerable" in lines[0].lower() and len(lines) > 1:
                    title = lines[1]
                elif len(lines) >= 1:
                    title = lines[0]

                if not title:
                    title = f"Nmap hostscript {script_id} reported VULNERABLE"

                if "critical" in lower:
                    severity = "critical"
                else:
                    risk_match = re.search(r"risk factor:\\s*(\\w+)", output_text, re.IGNORECASE)
                    if risk_match:
                        sev = risk_match.group(1).lower()
                        if sev in {"high", "medium", "low"}:
                            severity = sev
                    if not severity:
                        severity = "high"

                description = output_text
                evidence = " | ".join(lines[:2]) if lines else output_text

            elif "message_signing: disabled" in lower:
                title = "SMB signing disabled"
                severity = "medium"
                description = output_text
                evidence = "message_signing: disabled"

            elif "message signing enabled but not required" in lower:
                title = "SMB signing not required (SMB2)"
                severity = "medium"
                description = output_text
                evidence = "Message signing enabled but not required"

            if not title or not severity:
                continue

            finding = Finding(
                id=f"nmap_hostscript_{script_id}_{datetime.now().timestamp()}",
                severity=severity,
                title=title[:200],
                description=description[:2000],
                evidence=evidence[:500],
                tool="nmap",
                target=target,
                timestamp=datetime.now().isoformat(),
            )
            findings.append(finding)

        return findings

    def _condense_nuclei_jsonl(self, text: str) -> str:
        """
        Condense Nuclei JSONL into a smaller, evidence-friendly snippet set:
        - summary counts by severity
        - up to N minimal JSON objects (1 per match), stripping very large fields

        Keeps verbatim JSON (minified) so the model can cite evidence directly.
        """
        text = (text or "").strip()
        if not text:
            return text

        # Nuclei can emit very large JSON fields (e.g., template-encoded, request, response).
        # We keep only high-signal keys needed for triage and evidence.
        drop_keys = {
            "template-encoded",
            "request",
            "response",
            "curl-command",
            "raw-request",
            "raw-response",
            "matcher-status",
        }

        lines = [ln for ln in text.splitlines() if ln.strip()]
        # Some environments may produce a single giant JSON object without newlines.
        if len(lines) == 1 and lines[0].lstrip().startswith("{") and lines[0].rstrip().endswith("}"):
            candidates = [lines[0]]
        else:
            candidates = lines

        items: list[dict[str, Any]] = []
        for ln in candidates:
            if not ln.lstrip().startswith("{"):
                continue
            try:
                obj = json.loads(ln)
            except Exception:
                continue

            minimal: dict[str, Any] = {}
            for k, v in obj.items():
                if k in drop_keys:
                    continue
                minimal[k] = v

            # Keep a stable, compact subset if present.
            info = minimal.get("info") if isinstance(minimal.get("info"), dict) else {}
            slim = {
                "template-id": minimal.get("template-id") or minimal.get("templateID") or minimal.get("template"),
                "name": info.get("name"),
                "severity": (info.get("severity") or "").lower() if isinstance(info.get("severity"), str) else info.get("severity"),
                "type": minimal.get("type"),
                "matched-at": minimal.get("matched-at") or minimal.get("matched") or minimal.get("url"),
                "host": minimal.get("host") or minimal.get("ip"),
                "timestamp": minimal.get("timestamp"),
                "reference": info.get("reference"),
                "tags": info.get("tags"),
            }
            # Remove empty fields
            slim = {k: v for k, v in slim.items() if v not in (None, "", [], {})}
            items.append(slim)

        if not items:
            return text

        by_sev: dict[str, int] = {}
        for it in items:
            sev = it.get("severity") or "unknown"
            if isinstance(sev, str):
                sev = sev.lower()
            by_sev[str(sev)] = by_sev.get(str(sev), 0) + 1

        # Keep the first N for evidence; for larger scans, this prevents prompt bloat.
        max_items = 50
        kept = items[:max_items]

        out: list[str] = []
        out.append("NUCLEI_JSONL_CONDENSED: true")
        out.append(f"NUCLEI_MATCHES: {len(items)}")
        out.append("NUCLEI_BY_SEVERITY: " + json.dumps(by_sev, sort_keys=True))
        out.append("NUCLEI_RESULTS_JSON:")
        for it in kept:
            out.append(json.dumps(it, separators=(",", ":"), ensure_ascii=False))
        if len(items) > max_items:
            out.append(f"... ({len(items) - max_items} more results omitted)")
        return "\n".join(out)

    def _postprocess_findings(self, findings: List[Finding], tool: str, output: str) -> List[Finding]:
        """
        Apply conservative normalization rules so we don't overstate impact from low-signal inputs.
        """
        for f in findings:
            ev = (f.evidence or "").lower()

            # Header-only observations are usually informational without endpoint context.
            if "access-control-allow-origin" in ev and "*" in ev:
                if f.severity in {"critical", "high", "medium"}:
                    f.severity = "low"
                if not f.title:
                    f.title = "Permissive CORS policy"

            if "feature-policy" in ev or "permissions-policy" in ev:
                f.severity = "info"
                if not f.title:
                    f.title = "Browser feature policy header present"

            # "Service exposed" is generally informational unless coupled with auth bypass, CVE, etc.
            if tool in {"nmap", "httpx"} and ("port" in ev or "scheme" in ev) and f.severity in {"critical", "high", "medium"}:
                if not re.search(r"\bCVE-\d{4}-\d+\b", output, re.IGNORECASE):
                    f.severity = "info"

        return findings
    
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

        lines = [l.strip() for l in ai_response.splitlines() if l.strip()]
        current: Optional[Finding] = None

        for line in lines:
            # Match patterns like "[High]" or "1. [Critical]" or "HIGH:"
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
