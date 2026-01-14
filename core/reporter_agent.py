"""
Reporter Agent
Generates professional penetration testing reports
"""

from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime
import shlex
from core.agent import BaseAgent
from ai.prompt_templates import (
    REPORTER_SYSTEM_PROMPT,
    REPORTER_EXECUTIVE_SUMMARY_PROMPT,
    REPORTER_TECHNICAL_FINDINGS_PROMPT,
    REPORTER_REMEDIATION_PROMPT,
    REPORTER_AI_TRACE_PROMPT
)


class ReporterAgent(BaseAgent):
    """Agent that generates professional penetration testing reports"""
    
    def __init__(self, config, llm_client, memory):
        super().__init__("Reporter", config, llm_client, memory)
    
    async def execute(self, format: str = "markdown") -> Dict[str, Any]:
        """
        Generate a complete penetration testing report
        
        Args:
            format: Report format (markdown, html, json)
        
        Returns:
            Dict with report content and metadata
        """
        self.log_action("GeneratingReport", f"Format: {format}")
        
        # Generate all sections
        executive_summary = await self.generate_executive_summary()
        technical_findings = await self.generate_technical_findings()
        remediation = await self.generate_remediation_plan()
        ai_trace = await self.generate_ai_trace()
        
        # Assemble report
        if format == "markdown":
            report_content = self._assemble_markdown_report(
                executive_summary,
                technical_findings,
                remediation,
                ai_trace
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
        summary = self.memory.get_findings_summary()
        
        # Get top critical issues
        critical_findings = self.memory.get_findings_by_severity("critical")
        high_findings = self.memory.get_findings_by_severity("high")
        
        top_issues = []
        for f in (critical_findings + high_findings)[:3]:
            top_issues.append(f"- {f.title}")
        
        prompt = REPORTER_EXECUTIVE_SUMMARY_PROMPT.format(
            target=self.memory.target,
            scope="Full penetration test",
            duration=self._calculate_duration(),
            findings_count=len(self.memory.findings),
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
    
    def _assemble_markdown_report(
        self,
        exec_summary: str,
        technical: str,
        remediation: str,
        ai_trace: str
    ) -> str:
        """Assemble Markdown report"""
        summary = self.memory.get_findings_summary()
        evidence_section = self._format_evidence_markdown()
        
        report = f"""# Penetration Test Report

## Target Information
- **Target**: {self.memory.target}
- **Session ID**: {self.memory.session_id}
- **Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Duration**: {self._calculate_duration()}

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
| **Total** | **{len(self.memory.findings)}** |

## Technical Findings

{technical}
{evidence_section}

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
        summary = self.memory.get_findings_summary()
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
        <tr><th>Total</th><th>{len(self.memory.findings)}</th></tr>
    </table>
    
    <h2>Technical Findings</h2>
    <div>{self._markdown_to_html(technical)}</div>
{evidence_section}
    
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
        
        report = {
            "metadata": {
                "target": self.memory.target,
                "session_id": self.memory.session_id,
                "timestamp": datetime.now().isoformat(),
                "duration": self._calculate_duration()
            },
            "executive_summary": exec_summary,
            "findings_summary": self.memory.get_findings_summary(),
            "findings": [asdict(f) for f in self.memory.findings],
            "technical_findings": technical,
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
        
        for f in self.memory.findings:
            formatted.append(f"""
[{f.severity.upper()}] {f.title}
Tool: {f.tool}
Target: {f.target}
Description: {f.description[:200]}
Evidence: {f.evidence[:200]}
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
            elif execution.exit_code == 0:
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

    def _collect_evidence_entries(self) -> List[Dict[str, str]]:
        evidence_files = self._extract_evidence_files()
        entries: List[Dict[str, str]] = []
        for f in self.memory.findings:
            if f.false_positive:
                continue
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
