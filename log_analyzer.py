#!/usr/bin/env python3
"""
Guardian CLI Log Analyzer and Validator
========================================

Analyzes Guardian CLI logs and session data to validate test runs,
identify issues, and generate insights.

Usage:
    # Analyze latest session
    python log_analyzer.py --session latest

    # Analyze specific session
    python log_analyzer.py --session 20250124_120000

    # Analyze all sessions and generate comparison report
    python log_analyzer.py --compare-all

    # Check for specific issues
    python log_analyzer.py --session latest --check-errors --check-coverage
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import print as rprint

console = Console()


@dataclass
class ToolExecution:
    """Tool execution details"""
    tool: str
    exit_code: int
    duration: float
    output_size: int
    timestamp: str
    findings_count: int = 0
    errors: List[str] = None


@dataclass
class SessionAnalysis:
    """Complete session analysis"""
    session_id: str
    target: str
    workflow: str
    start_time: datetime
    end_time: Optional[datetime]
    duration_seconds: float

    # Tool execution stats
    total_tools: int
    successful_tools: int
    failed_tools: int
    skipped_tools: int
    tool_executions: List[ToolExecution]

    # Finding stats
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_tool: Dict[str, int]

    # Quality metrics
    coverage_score: float  # 0-100
    error_rate: float  # 0-100
    efficiency_score: float  # 0-100

    # Issues and warnings
    errors: List[str]
    warnings: List[str]
    recommendations: List[str]


class LogAnalyzer:
    """Analyzes Guardian CLI logs and sessions"""

    def __init__(self, reports_dir: str = "reports", logs_dir: str = "logs"):
        self.reports_dir = Path(reports_dir)
        self.logs_dir = Path(logs_dir)

    def find_session_file(self, session_id: str) -> Optional[Path]:
        """Find session file by ID or 'latest'"""
        if session_id == "latest":
            sessions = sorted(self.reports_dir.glob("session_*.json"))
            return sessions[-1] if sessions else None
        else:
            session_file = self.reports_dir / f"session_{session_id}.json"
            return session_file if session_file.exists() else None

    def load_session(self, session_id: str) -> Optional[Dict]:
        """Load session data from JSON"""
        session_file = self.find_session_file(session_id)
        if not session_file:
            console.print(f"[red]Session file not found: {session_id}[/red]")
            return None

        try:
            with open(session_file) as f:
                return json.load(f)
        except Exception as e:
            console.print(f"[red]Failed to load session: {e}[/red]")
            return None

    def analyze_session(self, session_id: str) -> Optional[SessionAnalysis]:
        """Perform comprehensive session analysis"""
        console.print(f"[cyan]Analyzing session: {session_id}[/cyan]")

        session_data = self.load_session(session_id)
        if not session_data:
            return None

        # Parse basic info
        actual_session_id = session_data.get("session_id", session_id)
        target = session_data.get("target", "unknown")
        workflow = session_data.get("workflow", "unknown")

        start_time_str = session_data.get("start_time")
        end_time_str = session_data.get("end_time")

        start_time = datetime.fromisoformat(start_time_str) if start_time_str else None
        end_time = datetime.fromisoformat(end_time_str) if end_time_str else None

        duration = 0.0
        if start_time and end_time:
            duration = (end_time - start_time).total_seconds()

        # Analyze tool executions
        tool_executions_data = session_data.get("tool_executions", [])
        tool_executions = []
        successful_count = 0
        failed_count = 0
        skipped_count = 0

        for te in tool_executions_data:
            tool_name = te.get("tool", "unknown")
            exit_code = te.get("exit_code", -1)
            output = te.get("output", "")

            # Check if skipped
            is_skipped = "skipped:" in output.lower()

            if is_skipped:
                skipped_count += 1
            elif exit_code == 0:
                successful_count += 1
            else:
                failed_count += 1

            tool_exec = ToolExecution(
                tool=tool_name,
                exit_code=exit_code,
                duration=te.get("duration", 0.0),
                output_size=len(output),
                timestamp=te.get("timestamp", ""),
                errors=[]
            )

            # Extract errors from output
            if exit_code != 0 and not is_skipped:
                error_patterns = [
                    r"error:?\s*(.*)",
                    r"failed:?\s*(.*)",
                    r"exception:?\s*(.*)",
                ]
                for pattern in error_patterns:
                    matches = re.findall(pattern, output.lower())
                    tool_exec.errors.extend(matches[:3])  # Max 3 errors per tool

            tool_executions.append(tool_exec)

        # Analyze findings
        findings_data = session_data.get("findings", [])
        findings_by_severity = defaultdict(int)
        findings_by_tool = defaultdict(int)

        for finding in findings_data:
            severity = finding.get("severity", "info").lower()
            tool = finding.get("tool", "unknown")

            findings_by_severity[severity] += 1
            findings_by_tool[tool] += 1

        # Calculate quality metrics
        coverage_score = self._calculate_coverage(tool_executions, workflow)
        error_rate = (failed_count / len(tool_executions) * 100) if tool_executions else 0
        efficiency_score = self._calculate_efficiency(tool_executions, findings_data)

        # Generate issues and recommendations
        errors, warnings, recommendations = self._analyze_issues(
            tool_executions, findings_data, coverage_score, error_rate
        )

        analysis = SessionAnalysis(
            session_id=actual_session_id,
            target=target,
            workflow=workflow,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            total_tools=len(tool_executions),
            successful_tools=successful_count,
            failed_tools=failed_count,
            skipped_tools=skipped_count,
            tool_executions=tool_executions,
            total_findings=len(findings_data),
            findings_by_severity=dict(findings_by_severity),
            findings_by_tool=dict(findings_by_tool),
            coverage_score=coverage_score,
            error_rate=error_rate,
            efficiency_score=efficiency_score,
            errors=errors,
            warnings=warnings,
            recommendations=recommendations
        )

        return analysis

    def _calculate_coverage(self, tool_executions: List[ToolExecution], workflow: str) -> float:
        """Calculate test coverage score (0-100)"""
        # Expected tools for each workflow type
        expected_tools_by_workflow = {
            "recon": ["nmap", "subfinder", "httpx", "dnsx", "nuclei"],
            "web": ["httpx", "katana", "feroxbuster", "nuclei", "nikto", "arjun"],
            "network": ["nmap", "masscan", "nuclei", "enum4linux"],
            "autonomous": []  # Variable
        }

        expected_tools = expected_tools_by_workflow.get(workflow, [])
        if not expected_tools:
            return 100.0  # Can't measure coverage for autonomous

        executed_tools = {te.tool for te in tool_executions if te.exit_code == 0}
        coverage = len(executed_tools.intersection(expected_tools)) / len(expected_tools) * 100

        return coverage

    def _calculate_efficiency(self, tool_executions: List[ToolExecution], findings: List[Dict]) -> float:
        """Calculate efficiency score (findings per tool execution)"""
        if not tool_executions:
            return 0.0

        # Efficiency = (findings / successful_tools) * 10, capped at 100
        successful_tools = sum(1 for te in tool_executions if te.exit_code == 0)
        if successful_tools == 0:
            return 0.0

        efficiency = (len(findings) / successful_tools) * 10
        return min(efficiency, 100.0)

    def _analyze_issues(
        self,
        tool_executions: List[ToolExecution],
        findings: List[Dict],
        coverage: float,
        error_rate: float
    ) -> Tuple[List[str], List[str], List[str]]:
        """Analyze session for errors, warnings, and recommendations"""
        errors = []
        warnings = []
        recommendations = []

        # Check for high error rate
        if error_rate > 30:
            errors.append(f"High tool failure rate: {error_rate:.1f}%")
            recommendations.append("Review tool configurations and dependencies")

        # Check for low coverage
        if coverage < 60:
            warnings.append(f"Low test coverage: {coverage:.1f}%")
            recommendations.append("Ensure all required tools are installed and configured")

        # Check for no findings
        if not findings:
            warnings.append("No vulnerabilities found")
            recommendations.append("Verify target is reachable and tools are working correctly")

        # Check for failed critical tools
        critical_tools = ["nmap", "nuclei", "httpx"]
        failed_critical = [te.tool for te in tool_executions if te.tool in critical_tools and te.exit_code != 0]

        if failed_critical:
            errors.append(f"Critical tools failed: {', '.join(failed_critical)}")
            recommendations.append(f"Fix issues with: {', '.join(failed_critical)}")

        # Check for tool errors
        tools_with_errors = [te.tool for te in tool_executions if te.errors]
        if tools_with_errors:
            warnings.append(f"Tools with errors: {', '.join(set(tools_with_errors))}")

        # Check for very long duration
        avg_duration = sum(te.duration for te in tool_executions) / len(tool_executions) if tool_executions else 0
        if avg_duration > 300:  # > 5 minutes per tool
            warnings.append(f"Long average tool duration: {avg_duration:.1f}s")
            recommendations.append("Consider optimizing tool timeout settings")

        # Check findings distribution
        critical_findings = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        if critical_findings > 10:
            warnings.append(f"High number of critical findings: {critical_findings}")
            recommendations.append("Prioritize remediation of critical vulnerabilities")

        return errors, warnings, recommendations

    def display_analysis(self, analysis: SessionAnalysis):
        """Display analysis results in rich format"""
        console.print("\n")
        console.print(Panel.fit(
            f"[bold cyan]Session Analysis: {analysis.session_id}[/bold cyan]\n"
            f"Target: {analysis.target}\n"
            f"Workflow: {analysis.workflow}\n"
            f"Duration: {analysis.duration_seconds:.1f}s",
            border_style="cyan"
        ))

        # Quality Scores
        console.print("\n[bold yellow]Quality Metrics[/bold yellow]")
        scores_table = Table(show_header=False)
        scores_table.add_column("Metric", style="cyan")
        scores_table.add_column("Score", justify="right")

        coverage_color = "green" if analysis.coverage_score >= 80 else "yellow" if analysis.coverage_score >= 60 else "red"
        error_color = "green" if analysis.error_rate < 10 else "yellow" if analysis.error_rate < 30 else "red"
        efficiency_color = "green" if analysis.efficiency_score >= 50 else "yellow" if analysis.efficiency_score >= 30 else "red"

        scores_table.add_row("Coverage", f"[{coverage_color}]{analysis.coverage_score:.1f}%[/{coverage_color}]")
        scores_table.add_row("Error Rate", f"[{error_color}]{analysis.error_rate:.1f}%[/{error_color}]")
        scores_table.add_row("Efficiency", f"[{efficiency_color}]{analysis.efficiency_score:.1f}[/{efficiency_color}]")

        console.print(scores_table)

        # Tool Execution Summary
        console.print("\n[bold yellow]Tool Execution Summary[/bold yellow]")
        tools_table = Table()
        tools_table.add_column("Total", justify="right")
        tools_table.add_column("Success", justify="right", style="green")
        tools_table.add_column("Failed", justify="right", style="red")
        tools_table.add_column("Skipped", justify="right", style="yellow")

        tools_table.add_row(
            str(analysis.total_tools),
            str(analysis.successful_tools),
            str(analysis.failed_tools),
            str(analysis.skipped_tools)
        )

        console.print(tools_table)

        # Findings Summary
        console.print("\n[bold yellow]Findings Summary[/bold yellow]")
        findings_table = Table()
        findings_table.add_column("Severity", style="cyan")
        findings_table.add_column("Count", justify="right")

        severity_order = ["critical", "high", "medium", "low", "info"]
        for severity in severity_order:
            count = analysis.findings_by_severity.get(severity, 0)
            if count > 0:
                severity_style = {
                    "critical": "bold red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "white"
                }.get(severity, "white")

                findings_table.add_row(
                    f"[{severity_style}]{severity.upper()}[/{severity_style}]",
                    str(count)
                )

        console.print(findings_table)

        # Top Finding Tools
        if analysis.findings_by_tool:
            console.print("\n[bold yellow]Top Finding Tools[/bold yellow]")
            top_tools = sorted(analysis.findings_by_tool.items(), key=lambda x: x[1], reverse=True)[:5]

            tools_findings_table = Table()
            tools_findings_table.add_column("Tool", style="cyan")
            tools_findings_table.add_column("Findings", justify="right")

            for tool, count in top_tools:
                tools_findings_table.add_row(tool, str(count))

            console.print(tools_findings_table)

        # Issues and Recommendations
        if analysis.errors:
            console.print("\n[bold red]Errors[/bold red]")
            for error in analysis.errors:
                console.print(f"  ✗ {error}")

        if analysis.warnings:
            console.print("\n[bold yellow]Warnings[/bold yellow]")
            for warning in analysis.warnings:
                console.print(f"  ⚠ {warning}")

        if analysis.recommendations:
            console.print("\n[bold green]Recommendations[/bold green]")
            for rec in analysis.recommendations:
                console.print(f"  💡 {rec}")

    def compare_sessions(self, session_ids: List[str]):
        """Compare multiple sessions"""
        console.print(f"[cyan]Comparing {len(session_ids)} sessions...[/cyan]\n")

        analyses = []
        for session_id in session_ids:
            analysis = self.analyze_session(session_id)
            if analysis:
                analyses.append(analysis)

        if not analyses:
            console.print("[red]No valid sessions to compare[/red]")
            return

        # Comparison table
        table = Table(title="Session Comparison")
        table.add_column("Session ID", style="cyan")
        table.add_column("Target")
        table.add_column("Workflow")
        table.add_column("Duration (s)", justify="right")
        table.add_column("Tools", justify="right")
        table.add_column("Findings", justify="right")
        table.add_column("Coverage %", justify="right")
        table.add_column("Error %", justify="right")

        for analysis in analyses:
            coverage_color = "green" if analysis.coverage_score >= 80 else "yellow" if analysis.coverage_score >= 60 else "red"
            error_color = "green" if analysis.error_rate < 10 else "yellow" if analysis.error_rate < 30 else "red"

            table.add_row(
                analysis.session_id[:16] + "...",
                analysis.target[:20],
                analysis.workflow,
                f"{analysis.duration_seconds:.1f}",
                f"{analysis.successful_tools}/{analysis.total_tools}",
                str(analysis.total_findings),
                f"[{coverage_color}]{analysis.coverage_score:.1f}[/{coverage_color}]",
                f"[{error_color}]{analysis.error_rate:.1f}[/{error_color}]"
            )

        console.print(table)

        # Calculate trends
        avg_coverage = sum(a.coverage_score for a in analyses) / len(analyses)
        avg_error_rate = sum(a.error_rate for a in analyses) / len(analyses)
        avg_findings = sum(a.total_findings for a in analyses) / len(analyses)

        console.print(f"\n[bold cyan]Averages:[/bold cyan]")
        console.print(f"  Coverage: {avg_coverage:.1f}%")
        console.print(f"  Error Rate: {avg_error_rate:.1f}%")
        console.print(f"  Findings per Session: {avg_findings:.1f}")

    def generate_analysis_report(self, analysis: SessionAnalysis, output_file: Path):
        """Generate JSON analysis report"""
        report_data = asdict(analysis)

        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        console.print(f"[green]✓ Analysis report saved: {output_file}[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="Guardian CLI Log Analyzer and Validator"
    )

    parser.add_argument("--session", type=str, default="latest", help="Session ID or 'latest'")
    parser.add_argument("--compare-all", action="store_true", help="Compare all sessions")
    parser.add_argument("--check-errors", action="store_true", help="Focus on error analysis")
    parser.add_argument("--check-coverage", action="store_true", help="Focus on coverage analysis")
    parser.add_argument("--output", type=str, help="Output file for analysis report")
    parser.add_argument("--reports-dir", type=str, default="reports", help="Reports directory")

    args = parser.parse_args()

    analyzer = LogAnalyzer(reports_dir=args.reports_dir)

    if args.compare_all:
        # Find all sessions
        session_files = sorted(analyzer.reports_dir.glob("session_*.json"))
        session_ids = [f.stem.replace("session_", "") for f in session_files]

        if not session_ids:
            console.print("[red]No sessions found[/red]")
            sys.exit(1)

        analyzer.compare_sessions(session_ids)

    else:
        # Analyze single session
        analysis = analyzer.analyze_session(args.session)

        if not analysis:
            sys.exit(1)

        analyzer.display_analysis(analysis)

        if args.output:
            output_path = Path(args.output)
            analyzer.generate_analysis_report(analysis, output_path)


if __name__ == "__main__":
    main()
