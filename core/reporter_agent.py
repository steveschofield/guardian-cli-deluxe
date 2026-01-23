"""
Reporter Agent
Generates professional penetration testing reports
"""

from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime
import shlex
import json
from core.agent import BaseAgent
from ai.prompt_templates import (
    REPORTER_SYSTEM_PROMPT,
    REPORTER_EXECUTIVE_SUMMARY_PROMPT,
    REPORTER_TECHNICAL_FINDINGS_PROMPT,
    REPORTER_REMEDIATION_PROMPT,
    REPORTER_AI_TRACE_PROMPT
)
from utils.exploit_cache import ExploitLookup
from utils.finding_deduplicator import FindingDeduplicator
from utils.confidence_scorer import ConfidenceScorer
from utils.osint import OSINTEnricher


class ReporterAgent(BaseAgent):
    """Agent that generates professional penetration testing reports"""

    def __init__(self, config, llm_client, memory):
        super().__init__("Reporter", config, llm_client, memory)
        self.osint_enricher = OSINTEnricher(config, logger=self.logger)
    
    async def execute(self, format: str = "markdown") -> Dict[str, Any]:
        """
        Generate a complete penetration testing report
        
        Args:
            format: Report format (markdown, html, json)
        
        Returns:
            Dict with report content and metadata
        """
        self.log_action("GeneratingReport", f"Format: {format}")
        
        # Reset per-report cache
        self._report_findings_cache = None

        # Generate all sections
        executive_summary = await self.generate_executive_summary()
        technical_findings = await self.generate_technical_findings()
        remediation = await self.generate_remediation_plan()
        ai_trace = await self.generate_ai_trace()
        zap_summary = await self.generate_zap_summary()

        # Assemble report
        if format == "markdown":
            report_content = await self._assemble_markdown_report(
                executive_summary,
                technical_findings,
                remediation,
                ai_trace,
                zap_summary
            )
        elif format == "html":
            report_content = self._assemble_html_report(
                executive_summary,
                technical_findings,
                remediation,
                ai_trace
            )
        elif format == "json":
            report_content = self._assemble_json_report(
                executive_summary,
                technical_findings,
                remediation,
                ai_trace
            )
        else:
            raise ValueError(f"Unknown format: {format}")
        
        return {
            "content": report_content,
            "format": format,
            "session_id": self.memory.session_id,
            "target": self.memory.target,
            "timestamp": datetime.now().isoformat()
        }
    
    async def generate_executive_summary(self) -> str:
        """Generate executive summary for non-technical audience"""
        findings = self._get_report_findings()
        summary = self._summarize_findings(findings)
        
        # Get top critical issues
        critical_findings = [f for f in findings if f.severity.lower() == "critical"]
        high_findings = [f for f in findings if f.severity.lower() == "high"]
        
        top_issues = []
        for f in (critical_findings + high_findings)[:3]:
            top_issues.append(f"- {f.title}")
        
        prompt = REPORTER_EXECUTIVE_SUMMARY_PROMPT.format(
            target=self.memory.target,
            scope="Full penetration test",
            duration=self._calculate_duration(),
            findings_count=len(findings),
            critical_count=summary["critical"],
            high_count=summary["high"],
            medium_count=summary["medium"],
            low_count=summary["low"],
            top_issues="\n".join(top_issues) if top_issues else "No critical issues found"
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return result["response"]
    
    async def generate_technical_findings(self) -> str:
        """Generate detailed technical findings section"""
        # Format findings for AI
        findings_text = self._format_findings_detailed()
        
        prompt = REPORTER_TECHNICAL_FINDINGS_PROMPT.format(
            findings=findings_text
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return result["response"]
    
    async def generate_remediation_plan(self) -> str:
        """Generate prioritized remediation recommendations"""
        findings_text = self._format_findings_detailed()
        
        # Get affected systems
        affected = set()
        for f in self.memory.findings:
            affected.add(f.target)
        
        prompt = REPORTER_REMEDIATION_PROMPT.format(
            findings=findings_text,
            affected_systems="\n".join(f"- {s}" for s in affected)
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return result["response"]
    
    async def generate_ai_trace(self) -> str:
        """Generate AI decision trace for transparency"""
        ai_decisions = "\n".join([
            f"- [{d['agent']}] {d['decision']} (Reasoning: {d['reasoning'][:100]}...)"
            for d in self.memory.ai_decisions
        ])
        
        workflow = f"Phase: {self.memory.current_phase}\nCompleted Actions: {len(self.memory.completed_actions)}"
        
        prompt = REPORTER_AI_TRACE_PROMPT.format(
            ai_decisions=ai_decisions or "No AI decisions recorded",
            workflow=workflow
        )
        
        result = await self.think(prompt, REPORTER_SYSTEM_PROMPT)
        return result["response"]

    async def generate_zap_summary(self) -> str:
        """
        Generate ZAP findings summary section with links to detailed reports.
        Returns empty string if no ZAP findings exist.
        """
        # Check if ZAP was executed
        zap_executions = [
            exec for exec in self.memory.tool_executions
            if exec.tool == "zap"
        ]

        if not zap_executions:
            return ""

        # Find ZAP report files
        session_id = self.memory.session_id
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        zap_dir = output_dir / session_id / "zap"

        if not zap_dir.exists():
            return ""

        # Load ZAP JSON to get alert counts
        zap_json_files = list(zap_dir.glob("zap_*.json"))
        if not zap_json_files:
            return ""

        zap_json = zap_json_files[0]  # Use most recent
        try:
            with open(zap_json) as f:
                zap_data = json.load(f)
            alerts = zap_data.get("alerts", [])

            # Count by severity
            severity_counts = {}
            for alert in alerts:
                risk = alert.get("risk", "Unknown")
                severity_counts[risk] = severity_counts.get(risk, 0) + 1

            # Build summary text
            summary_parts = [
                "## ZAP Scan Summary",
                "",
                f"OWASP ZAP identified **{len(alerts)} potential security issues** across the target application.",
                "",
                "### Severity Breakdown",
                "",
                "| Severity | Count |",
                "|----------|-------|",
            ]

            for severity in ["High", "Medium", "Low", "Informational"]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    summary_parts.append(f"| {severity} | {count} |")

            summary_parts.extend([
                "",
                "### Detailed Reports",
                "",
                f"Full ZAP scan results are available in the following files:",
                "",
                f"- **JSON Report**: `zap/{zap_json.name}`",
                f"- **HTML Report**: `zap/{zap_json.stem}.html`",
                f"- **Markdown Report**: `zap/{zap_json.stem}.md`",
                "",
                "The findings below include a curated selection of the most critical ZAP discoveries, "
                "filtered by confidence and exploitability.",
                ""
            ])

            return "\n".join(summary_parts)

        except Exception as e:
            self.logger.warning(f"Failed to load ZAP summary: {e}")
            return ""

    async def _assemble_markdown_report(
        self,
        exec_summary: str,
        technical: str,
        remediation: str,
        ai_trace: str,
        zap_summary: str = ""
    ) -> str:
        """Assemble Markdown report"""
        findings = self._get_report_findings()
        summary = self._summarize_findings(findings)
        evidence_section = self._format_evidence_markdown()

        # Build ZAP section if present
        zap_section = f"\n\n{zap_summary}\n" if zap_summary else ""

        # Build SAN section if certificate info available
        cert_info = self.memory.context.get("certificate_info", {})
        san_list = cert_info.get("san", [])
        if san_list and isinstance(san_list, list):
            san_display = "\n".join([f"  - {san}" for san in san_list])
            san_section = f"\n- **Subject Alternative Names (SAN)**:\n{san_display}"
        else:
            san_section = "\n- **Subject Alternative Names (SAN)**: No additional SAN attributes listed"

        report = f"""# Penetration Test Report

## Target Information
- **Target**: {self.memory.target}
- **Session ID**: {self.memory.session_id}
- **Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Duration**: {self._calculate_duration()}{san_section}

## Executive Summary

{exec_summary}

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {summary['critical']} |
| High     | {summary['high']} |
| Medium   | {summary['medium']} |
| Low      | {summary['low']} |
| Info     | {summary['info']} |
| **Total** | **{len(findings)}** |
{zap_section}
## Technical Findings

{technical}
{evidence_section}

## Standards Mapping

{self._format_standards_mapping_markdown()}

## Exploitation References

{self._format_exploit_references_markdown()}

## Remediation Plan

{remediation}

## AI Decision Trace

{ai_trace}

## Tool Summary

{self._format_tool_summary_markdown()}

## Tools Executed

{self._format_tool_executions()}

---
*Report generated by Guardian AI Pentest Tool*
"""
        return report
    
    def _assemble_html_report(
        self,
        exec_summary: str,
        technical: str,
        remediation: str,
        ai_trace: str
    ) -> str:
        """Assemble HTML report"""
        findings = self._get_report_findings()
        summary = self._summarize_findings(findings)
        evidence_section = self._format_evidence_html()
        
        # Convert markdown-style content to HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - {self.memory.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #3498db; }}
        .info {{ color: #95a5a6; }}
        .summary {{ background-color: #ecf0f1; padding: 20px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>🔐 Penetration Test Report</h1>
    
    <div class="summary">
        <h3>Target Information</h3>
        <p><strong>Target:</strong> {self.memory.target}</p>
        <p><strong>Session ID:</strong> {self.memory.session_id}</p>
        <p><strong>Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Duration:</strong> {self._calculate_duration()}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <div>{self._markdown_to_html(exec_summary)}</div>
    
    <h2>Findings Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td class="critical">Critical</td><td>{summary['critical']}</td></tr>
        <tr><td class="high">High</td><td>{summary['high']}</td></tr>
        <tr><td class="medium">Medium</td><td>{summary['medium']}</td></tr>
        <tr><td class="low">Low</td><td>{summary['low']}</td></tr>
        <tr><td class="info">Info</td><td>{summary['info']}</td></tr>
        <tr><th>Total</th><th>{len(findings)}</th></tr>
    </table>
    
    <h2>Technical Findings</h2>
    <div>{self._markdown_to_html(technical)}</div>
{evidence_section}

    <h2>Standards Mapping</h2>
    {self._format_standards_mapping_html()}

    <h2>Exploitation References</h2>
    {self._format_exploit_references_html()}
    
    <h2>Remediation Plan</h2>
    <div>{self._markdown_to_html(remediation)}</div>
    
    <h2>AI Decision Trace</h2>
    <div>{self._markdown_to_html(ai_trace)}</div>

    <h2>Tool Summary</h2>
    {self._format_tool_summary_html()}
    
    <footer>
        <hr>
        <p><em>Report generated by Guardian AI Pentest Tool</em></p>
    </footer>
</body>
</html>"""
        return html
    
    def _assemble_json_report(
        self,
        exec_summary: str,
        technical: str,
        remediation: str,
        ai_trace: str
    ) -> str:
        """Assemble JSON report"""
        import json
        from dataclasses import asdict
        
        findings = self._get_report_findings()
        report = {
            "metadata": {
                "target": self.memory.target,
                "session_id": self.memory.session_id,
                "timestamp": datetime.now().isoformat(),
                "duration": self._calculate_duration()
            },
            "executive_summary": exec_summary,
            "findings_summary": self._summarize_findings(findings),
            "findings": [asdict(f) for f in findings],
            "technical_findings": technical,
            "exploit_lookup": self._get_exploit_lookup(),
            "remediation_plan": remediation,
            "ai_trace": ai_trace,
            "tool_executions": [asdict(t) for t in self.memory.tool_executions],
            "tool_summary": self._get_tool_summary(),
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def _calculate_duration(self) -> str:
        """Calculate test duration"""
        start = datetime.fromisoformat(self.memory.start_time)
        end = datetime.now()
        duration = end - start
        
        hours = duration.seconds // 3600
        minutes = (duration.seconds % 3600) // 60
        
        return f"{hours}h {minutes}m"
    
    def _format_findings_detailed(self) -> str:
        """Format findings for AI consumption"""
        formatted = []
        findings = self._get_report_findings()
        exploit_lookup = self._get_exploit_lookup()
        matches = exploit_lookup.get("matches", {}) if isinstance(exploit_lookup, dict) else {}

        # Get OSINT enrichment data
        osint_data = self.osint_enricher.enrich_findings(findings)

        for f in findings:
            cvss = self._format_cvss_display(f)
            cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "Unmapped"
            owasp = ", ".join(f.owasp_categories) if f.owasp_categories else "Unmapped"
            confidence = getattr(f, "confidence", None) or "unknown"

            # Build exploit information section
            exploit_info = []

            # Add CVE IDs if present
            if f.cve_ids:
                exploit_info.append(f"CVE IDs: {', '.join(f.cve_ids)}")

            # OSINT: Check CISA KEV status (CRITICAL PRIORITY)
            enrichment = osint_data.get(f.id, {})
            kev_status = enrichment.get("kev_status", {})
            for cve_id, kev_entry in kev_status.items():
                exploit_info.append(f"🔥 CISA KEV: {cve_id} - ACTIVELY EXPLOITED IN THE WILD")
                if kev_entry.get("ransomware_use"):
                    exploit_info.append(f"   ⚠️ RANSOMWARE ASSOCIATED")
                exploit_info.append(f"   Required Action: {kev_entry.get('required_action')}")
                exploit_info.append(f"   Government Deadline: {kev_entry.get('due_date')}")

            # Add known exploits from database lookup
            entry = matches.get(f.id)
            if entry:
                metasploit = entry.get("metasploit", [])
                exploitdb = entry.get("exploitdb", [])

                if metasploit:
                    msf_names = [m.get("name") or m.get("module", "") for m in metasploit[:3]]
                    exploit_info.append(f"Known Metasploit Modules: {', '.join(msf_names)}")

                if exploitdb:
                    edb_ids = [f"EDB-{e.get('id')}" for e in exploitdb[:3] if e.get('id')]
                    exploit_info.append(f"Known Exploit-DB: {', '.join(edb_ids)}")

            # OSINT: Add GitHub PoCs
            github_pocs = enrichment.get("github_pocs", [])
            if github_pocs:
                exploit_info.append(f"GitHub PoCs ({len(github_pocs)} repositories):")
                for poc in github_pocs[:3]:  # Top 3
                    exploit_info.append(f"  - {poc['name']} ⭐ {poc['stars']} stars - {poc['url']}")

            # OSINT: Add Vulners data
            vulners_data = enrichment.get("vulners_data", {})
            for cve_id, vdata in vulners_data.items():
                if vdata.get("ai_score"):
                    exploit_info.append(f"Vulners AI Risk Score: {vdata['ai_score']}/10")
                if vdata.get("exploit_count"):
                    exploit_info.append(f"Total Exploits (all sources): {vdata['exploit_count']}")

            # Add exploitation attempt status if auto-exploit was used
            if f.metadata.get("exploitation_attempted"):
                if f.metadata.get("exploitation_successful"):
                    exploit_module = f.metadata.get("exploit_module", "Unknown")
                    exploit_info.append(f"⚠️ EXPLOITATION SUCCESSFUL using {exploit_module}")
                elif f.metadata.get("exploitation_error"):
                    exploit_info.append(f"Exploitation attempted but failed: {f.metadata.get('exploitation_error')}")
                else:
                    exploit_info.append("Exploitation attempted but unsuccessful")
            elif f.metadata.get("exploitdb_available"):
                edb_count = len(f.metadata.get("exploitdb_ids", []))
                exploit_info.append(f"{edb_count} Exploit-DB exploit(s) available for manual use")

            exploit_section = "\n".join(exploit_info) if exploit_info else "No public exploits found"

            formatted.append(f"""
[{f.severity.upper()}] {f.title}
Tool: {f.tool}
Target: {f.target}
CVSS: {cvss}
CWE: {cwe}
OWASP: {owasp}
Confidence: {confidence}
Description: {f.description[:200]}
Evidence: {f.evidence[:200]}
Exploitation Information:
{exploit_section}
""")

        return "\n---\n".join(formatted) if formatted else "No findings"
    
    def _format_tool_executions(self) -> str:
        """Format tool executions for report"""
        if not self.memory.tool_executions:
            return "No tools executed"
        
        formatted = []
        for t in self.memory.tool_executions:
            formatted.append(f"- **{t.tool}**: {t.command} (Duration: {t.duration:.2f}s)")
        
        return "\n".join(formatted)

    def _format_cvss_display(self, finding) -> str:
        if finding.cvss_score is None:
            return "N/A"

        try:
            score = f"{float(finding.cvss_score):.1f}"
        except (TypeError, ValueError):
            score = str(finding.cvss_score)
        suffix = " (est.)" if finding.cvss_score_source == "estimated" else ""
        if finding.cvss_vector:
            return f"{score} ({finding.cvss_vector})"
        return f"{score}{suffix}"

    def _get_tool_summary(self) -> List[Dict[str, Any]]:
        summary: Dict[str, Dict[str, Any]] = {}
        ordered_tools: List[str] = []
        for execution in self.memory.tool_executions:
            tool = execution.tool
            if tool not in summary:
                summary[tool] = {
                    "tool": tool,
                    "runs": 0,
                    "success": 0,
                    "failed": 0,
                    "skipped": 0,
                    "last_exit_code": execution.exit_code,
                }
                ordered_tools.append(tool)

            entry = summary[tool]
            entry["runs"] += 1
            entry["last_exit_code"] = execution.exit_code
            output_lower = (execution.output or "").lower()
            if "skipped:" in output_lower:
                entry["skipped"] += 1
            elif execution.success:  # Use tool-specific success determination
                entry["success"] += 1
            else:
                entry["failed"] += 1

        return [summary[t] for t in ordered_tools]

    def _format_tool_summary_markdown(self) -> str:
        summary = self._get_tool_summary()
        if not summary:
            return "No tool executions recorded"

        lines = [
            "| Tool | Runs | Success | Failed | Skipped | Last Exit |",
            "|------|------|---------|--------|---------|-----------|",
        ]
        for item in summary:
            lines.append(
                f"| {item['tool']} | {item['runs']} | {item['success']} | "
                f"{item['failed']} | {item['skipped']} | {item['last_exit_code']} |"
            )
        return "\n".join(lines)

    def _format_tool_summary_html(self) -> str:
        summary = self._get_tool_summary()
        if not summary:
            return "<p>No tool executions recorded.</p>"

        rows = []
        for item in summary:
            rows.append(
                "<tr>"
                f"<td>{item['tool']}</td>"
                f"<td>{item['runs']}</td>"
                f"<td>{item['success']}</td>"
                f"<td>{item['failed']}</td>"
                f"<td>{item['skipped']}</td>"
                f"<td>{item['last_exit_code']}</td>"
                "</tr>"
            )

        return (
            "<table>"
            "<tr><th>Tool</th><th>Runs</th><th>Success</th><th>Failed</th>"
            "<th>Skipped</th><th>Last Exit</th></tr>"
            + "".join(rows)
            + "</table>"
        )

    def _get_exploit_lookup(self) -> Dict[str, Any]:
        cached = getattr(self, "_exploit_lookup", None)
        if isinstance(cached, dict):
            return cached

        lookup = ExploitLookup(self.config, logger=self.logger)
        result = lookup.lookup_findings(self._get_report_findings())
        self._exploit_lookup = result
        return result

    def _format_standards_mapping_markdown(self) -> str:
        findings = self._get_report_findings()
        if not findings:
            return "No findings to map"

        exploit_lookup = self._get_exploit_lookup()
        matches = exploit_lookup.get("matches", {}) if isinstance(exploit_lookup, dict) else {}

        # Get OSINT enrichment data for KEV status
        osint_data = self.osint_enricher.enrich_findings(findings)

        lines = [
            "| Severity | Finding | CVSS | OWASP | CWE | Exploit Status |",
            "|----------|---------|------|-------|-----|----------------|",
        ]
        for f in findings:
            cvss = self._format_cvss_display(f)
            owasp = ", ".join(f.owasp_categories) if f.owasp_categories else "Unmapped"
            cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "Unmapped"

            # Determine exploit status (KEV takes highest priority)
            exploit_status = "N/A"

            # Check CISA KEV status first (highest priority)
            enrichment = osint_data.get(f.id, {})
            if enrichment.get("kev_status"):
                exploit_status = "🔥🔥 CISA KEV - IN THE WILD"
            elif f.metadata.get("exploitation_successful"):
                exploit_status = "🔥 EXPLOITED"
            elif f.metadata.get("exploitation_attempted"):
                exploit_status = "⚠️ Attempted"
            elif matches.get(f.id):
                entry = matches[f.id]
                msf_count = len(entry.get("metasploit", []))
                edb_count = len(entry.get("exploitdb", []))
                if msf_count > 0 or edb_count > 0:
                    exploit_status = f"💣 Available (MSF:{msf_count}, EDB:{edb_count})"

            lines.append(
                f"| {f.severity.upper()} | {f.title} | {cvss} | {owasp} | {cwe} | {exploit_status} |"
            )
        return "\n".join(lines)

    def _format_standards_mapping_html(self) -> str:
        findings = self._get_report_findings()
        if not findings:
            return "<p>No findings to map.</p>"

        import html as _html

        exploit_lookup = self._get_exploit_lookup()
        matches = exploit_lookup.get("matches", {}) if isinstance(exploit_lookup, dict) else {}

        # Get OSINT enrichment data for KEV status
        osint_data = self.osint_enricher.enrich_findings(findings)

        rows = []
        for f in findings:
            cvss = self._format_cvss_display(f)
            owasp = ", ".join(f.owasp_categories) if f.owasp_categories else "Unmapped"
            cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "Unmapped"

            # Determine exploit status (KEV takes highest priority)
            exploit_status = "N/A"

            # Check CISA KEV status first
            enrichment = osint_data.get(f.id, {})
            if enrichment.get("kev_status"):
                exploit_status = "🔥🔥 CISA KEV - IN THE WILD"
            elif f.metadata.get("exploitation_successful"):
                exploit_status = "🔥 EXPLOITED"
            elif f.metadata.get("exploitation_attempted"):
                exploit_status = "⚠️ Attempted"
            elif matches.get(f.id):
                entry = matches[f.id]
                msf_count = len(entry.get("metasploit", []))
                edb_count = len(entry.get("exploitdb", []))
                if msf_count > 0 or edb_count > 0:
                    exploit_status = f"💣 Available (MSF:{msf_count}, EDB:{edb_count})"

            rows.append(
                "<tr>"
                f"<td>{_html.escape(f.severity.upper())}</td>"
                f"<td>{_html.escape(f.title)}</td>"
                f"<td>{_html.escape(cvss)}</td>"
                f"<td>{_html.escape(owasp)}</td>"
                f"<td>{_html.escape(cwe)}</td>"
                f"<td>{_html.escape(exploit_status)}</td>"
                "</tr>"
            )

        return (
            "<table>"
            "<tr><th>Severity</th><th>Finding</th><th>CVSS</th><th>OWASP</th><th>CWE</th><th>Exploit Status</th></tr>"
            + "".join(rows)
            + "</table>"
        )

    def _format_exploit_references_markdown(self) -> str:
        lookup = self._get_exploit_lookup()
        matches = lookup.get("matches", {}) if isinstance(lookup, dict) else {}
        status = lookup.get("status", {}) if isinstance(lookup, dict) else {}

        if not matches:
            return self._format_exploit_status_markdown(status) or "No matching public exploit references found"

        lines = [
            "| Severity | Finding | CVEs | Metasploit | Exploit-DB |",
            "|----------|---------|------|------------|------------|",
        ]

        findings = self._get_report_findings()
        for f in findings:
            entry = matches.get(f.id)
            if not entry:
                continue
            cves = ", ".join(entry.get("cves", [])) or "None"
            metasploit = _format_metasploit_refs(entry.get("metasploit", []))
            exploitdb = _format_exploitdb_refs(entry.get("exploitdb", []))
            lines.append(
                f"| {f.severity.upper()} | {f.title} | {cves} | {metasploit} | {exploitdb} |"
            )

        note = self._format_exploit_status_markdown(status)
        if note:
            lines.append("")
            lines.append(note)

        return "\n".join(lines)

    def _format_exploit_references_html(self) -> str:
        lookup = self._get_exploit_lookup()
        matches = lookup.get("matches", {}) if isinstance(lookup, dict) else {}
        status = lookup.get("status", {}) if isinstance(lookup, dict) else {}

        if not matches:
            note = self._format_exploit_status_html(status)
            return note or "<p>No matching public exploit references found.</p>"

        import html as _html

        rows = []
        findings = self._get_report_findings()
        for f in findings:
            entry = matches.get(f.id)
            if not entry:
                continue
            cves = ", ".join(entry.get("cves", [])) or "None"
            metasploit = _format_metasploit_refs(entry.get("metasploit", []), html=True)
            exploitdb = _format_exploitdb_refs(entry.get("exploitdb", []), html=True)
            rows.append(
                "<tr>"
                f"<td>{_html.escape(f.severity.upper())}</td>"
                f"<td>{_html.escape(f.title)}</td>"
                f"<td>{_html.escape(cves)}</td>"
                f"<td>{metasploit}</td>"
                f"<td>{exploitdb}</td>"
                "</tr>"
            )

        table = (
            "<table>"
            "<tr><th>Severity</th><th>Finding</th><th>CVEs</th><th>Metasploit</th><th>Exploit-DB</th></tr>"
            + "".join(rows)
            + "</table>"
        )

        note = self._format_exploit_status_html(status)
        return table + (note or "")

    def _format_exploit_status_markdown(self, status: Dict[str, Any]) -> str:
        bits = []
        for name in ("exploitdb", "metasploit"):
            entry = status.get(name, {})
            if not entry:
                continue
            state = entry.get("state", "unknown")
            count = entry.get("count")
            source = entry.get("source")
            detail = f"{name}: {state}"
            if count is not None:
                detail += f" ({count})"
            if source:
                detail += f" from {source}"
            bits.append(detail)
        if not bits:
            return ""
        return "Exploit lookup status: " + "; ".join(bits)

    def _format_exploit_status_html(self, status: Dict[str, Any]) -> str:
        msg = self._format_exploit_status_markdown(status)
        if not msg:
            return ""
        import html as _html
        return f"<p><em>{_html.escape(msg)}</em></p>"

    def _collect_evidence_entries(self) -> List[Dict[str, str]]:
        evidence_files = self._extract_evidence_files()
        entries: List[Dict[str, str]] = []
        for f in self._get_report_findings():
            evidence = (f.evidence or "").strip()
            if not evidence:
                continue
            compact = " ".join(evidence.split())
            files = evidence_files.get(f.tool, [])
            entries.append({
                "title": f.title,
                "severity": f.severity.upper(),
                "tool": f.tool,
                "target": f.target,
                "evidence": compact[:500],
                "evidence_files": ", ".join(files) if files else "",
            })
        return entries

    def _format_evidence_markdown(self) -> str:
        entries = self._collect_evidence_entries()
        if not entries:
            return ""
        lines = ["", "## Evidence", ""]
        for e in entries:
            file_part = f" Evidence file: {e['evidence_files']}" if e.get("evidence_files") else ""
            lines.append(
                f"- **[{e['severity']}] {e['title']}** (Tool: {e['tool']}, Target: {e['target']}) "
                f"Evidence: {e['evidence']}{file_part}"
            )
        return "\n".join(lines)

    def _format_evidence_html(self) -> str:
        entries = self._collect_evidence_entries()
        if not entries:
            return ""
        import html as _html
        items = []
        for e in entries:
            file_part = f" Evidence file: {_html.escape(e['evidence_files'])}" if e.get("evidence_files") else ""
            item = (
                f"<li><strong>[{_html.escape(e['severity'])}] {_html.escape(e['title'])}</strong> "
                f"(Tool: {_html.escape(e['tool'])}, Target: {_html.escape(e['target'])}) "
                f"Evidence: {_html.escape(e['evidence'])}{file_part}</li>"
            )
            items.append(item)
        return "\n    <h2>Evidence</h2>\n    <ul>\n        " + "\n        ".join(items) + "\n    </ul>\n"

    def _extract_evidence_files(self) -> Dict[str, List[str]]:
        evidence: Dict[str, List[str]] = {}
        for execution in self.memory.tool_executions:
            tool = execution.tool
            cmd = execution.command or ""
            try:
                tokens = shlex.split(cmd)
            except Exception:
                tokens = cmd.split()

            files: List[str] = []
            # Nuclei JSONL output file.
            for i, tok in enumerate(tokens):
                if tok == "-o" and i + 1 < len(tokens):
                    files.append(tokens[i + 1])
                if tok.startswith("-o") and len(tok) > 2:
                    files.append(tok[2:])
                if tok == "--report-path" and i + 1 < len(tokens):
                    files.append(tokens[i + 1])

            if files:
                existing = evidence.setdefault(tool, [])
                for f in files:
                    if f and f not in existing:
                        existing.append(f)
        return evidence
    
    def _markdown_to_html(self, markdown: str) -> str:
        """Simple markdown to HTML conversion"""
        # Basic conversion - in production, use a proper library
        html = markdown.replace('\n\n', '</p><p>')
        html = f'<p>{html}</p>'
        html = html.replace('**', '<strong>').replace('**', '</strong>')
        html = html.replace('*', '<em>').replace('*', '</em>')
        return html

    def _get_report_findings(self):
        cached = getattr(self, "_report_findings_cache", None)
        if cached is not None:
            return cached

        findings = [f for f in self.memory.findings if not f.false_positive]

        deduper = FindingDeduplicator(self.config)
        findings = deduper.deduplicate(findings)

        reporting_cfg = (self.config or {}).get("reporting", {}) or {}
        if reporting_cfg.get("enable_confidence_scoring", True):
            scorer = ConfidenceScorer(self.config)
            for f in findings:
                if not getattr(f, "confidence", None):
                    scorer.enrich_finding_with_confidence(f)
            if reporting_cfg.get("filter_low_confidence", False) and not scorer.verbose:
                findings = scorer.filter_findings_by_confidence(findings)

        self._report_findings_cache = findings
        return findings

    def _summarize_findings(self, findings: List) -> Dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = (finding.severity or "").lower()
            if severity in summary:
                summary[severity] += 1
        return summary


def _format_metasploit_refs(items: List[Dict[str, Any]], html: bool = False) -> str:
    if not items:
        return "None"

    parts: List[str] = []
    for item in items:
        label = item.get("name") or item.get("module") or "Metasploit module"
        url = item.get("url")
        if html and url:
            import html as _html
            parts.append(f'<a href="{_html.escape(url)}">{_html.escape(label)}</a>')
        elif url:
            parts.append(f"[{label}]({url})")
        else:
            parts.append(label)
    sep = "<br>" if html else "<br>"
    return sep.join(parts)


def _format_exploitdb_refs(items: List[Dict[str, Any]], html: bool = False) -> str:
    if not items:
        return "None"

    parts: List[str] = []
    for item in items:
        exploit_id = item.get("id")
        label = f"EDB-{exploit_id}" if exploit_id else (item.get("description") or "Exploit-DB")
        url = item.get("url")
        if html and url:
            import html as _html
            parts.append(f'<a href="{_html.escape(url)}">{_html.escape(label)}</a>')
        elif url:
            parts.append(f"[{label}]({url})")
        else:
            parts.append(label)
    sep = "<br>" if html else "<br>"
    return sep.join(parts)
