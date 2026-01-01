"""
Workflow orchestration engine
Coordinates agents and manages pentest execution flow
"""

import asyncio
import re
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

from core.agent import BaseAgent
from core.planner import PlannerAgent
from core.memory import PentestMemory, ToolExecution, Finding
from ai.provider_factory import get_llm_client
from utils.logger import get_logger
from utils.scope_validator import ScopeValidator


class WorkflowEngine:
    """Orchestrates the penetration testing workflow"""
    
    def __init__(self, config: Dict[str, Any], target: str):
        self.config = config
        self.target = target
        self.logger = get_logger(config)
        
        # Initialize components
        self.memory = PentestMemory(target)
        self.scope_validator = ScopeValidator(config)
        self.llm_client = get_llm_client(config)

        # Initialize all agents
        from core.planner import PlannerAgent
        from core.tool_agent import ToolAgent
        from core.analyst_agent import AnalystAgent
        from core.reporter_agent import ReporterAgent

        self.planner = PlannerAgent(config, self.llm_client, self.memory)
        self.tool_agent = ToolAgent(config, self.llm_client, self.memory)
        self.analyst = AnalystAgent(config, self.llm_client, self.memory)
        self.reporter = ReporterAgent(config, self.llm_client, self.memory)

        # Log tool availability up front
        try:
            self.tool_agent.log_tool_availability()
        except Exception as e:
            self.logger.warning(f"Tool availability check failed: {e}")
        
        # Workflow state
        self.is_running = False
        self.current_step = 0
        self.max_steps = config.get("workflows", {}).get("max_steps", 20)
        self._step_durations: List[float] = []
    
    async def run_workflow(self, workflow_name: str) -> Dict[str, Any]:
        """
        Run a predefined workflow
        
        Args:
            workflow_name: Name of workflow (recon, web_pentest, network_pentest)
        
        Returns:
            Workflow results and findings
        """
        self.logger.info(f"Starting workflow: {workflow_name} for target: {self.target}")
        
        # Validate target
        is_valid, reason = self.scope_validator.validate_target(self.target)
        if not is_valid:
            self.logger.error(f"Target validation failed: {reason}")
            raise ValueError(f"Invalid target: {reason}")
        
        self.is_running = True
        self.memory.update_phase(f"{workflow_name}_workflow")
        
        try:
            # Load workflow steps
            steps = self._load_workflow(workflow_name)
            
            # Execute workflow steps
            for step in steps:
                if not self.is_running:
                    break
                self._log_progress(prefix="Workflow", total=len(steps), current=self.current_step)
                self.logger.info(f"Executing step: {step['name']}")
                step_started = datetime.now()
                await self._execute_step(step)
                self._record_step_duration(step_started)
                self.current_step += 1
            
            # Generate final analysis
            analysis = await self.planner.analyze_results()
            
            # Save final state
            self._save_session()
            
            return {
                "status": "completed",
                "findings": len(self.memory.findings),
                "analysis": analysis,
                "session_id": self.memory.session_id
            }
            
        except Exception as e:
            self.logger.error(f"Workflow failed: {e}")
            self._save_session()
            raise
        finally:
            self.is_running = False
    
    async def run_autonomous(self) -> Dict[str, Any]:
        """
        Run autonomous pentest where AI decides each step
        
        Returns:
            Final results
        """
        self.logger.info(f"Starting autonomous pentest for target: {self.target}")
        
        # Validate target
        is_valid, reason = self.scope_validator.validate_target(self.target)
        if not is_valid:
            raise ValueError(f"Invalid target: {reason}")
        
        self.is_running = True
        self.memory.update_phase("reconnaissance")
        
        try:
            while self.is_running and self.current_step < self.max_steps:
                # Ask planner for next action
                decision = await self.planner.decide_next_action()
                
                self.logger.info(f"AI Decision: {decision.get('next_action')}")
                self.logger.debug(f"Reasoning: {decision.get('reasoning', 'N/A')}")
                self._log_progress(prefix="Autonomous", total=self.max_steps, current=self.current_step)
                
                # Check if we should stop
                if decision.get("next_action", "").lower() in ["done", "complete", "finish"]:
                    self.logger.info("Planner decided workflow is complete")
                    break
                
                # Execute the decided action
                step_started = datetime.now()
                await self._execute_ai_decision(decision)
                self._record_step_duration(step_started)
                
                self.current_step += 1
                
                # Progress phase if needed
                self._maybe_advance_phase()
            
            # Final analysis
            analysis = await self.planner.analyze_results()
            
            self._save_session()
            
            return {
                "status": "completed",
                "findings": len(self.memory.findings),
                "analysis": analysis,
                "session_id": self.memory.session_id
            }
            
        except Exception as e:
            self.logger.error(f"Autonomous workflow failed: {e}")
            self._save_session()
            raise
        finally:
            self.is_running = False
    
    def stop(self):
        """Stop the workflow"""
        self.logger.info("Stopping workflow")
        self.is_running = False
    
    async def _execute_step(self, step: Dict[str, Any]):
        """Execute a workflow step"""
        step_type = step.get("type", "tool")
        
        if step_type == "tool":
            # Use Tool Agent to select and execute tool
            tool_name = step["tool"]
            objective = step.get("objective", f"Execute {tool_name}")
            
            self.logger.info(f"Tool Agent selecting tool: {tool_name}")
            
            # Tool Agent executes the tool
            result = await self.tool_agent.execute_tool(
                tool_name=tool_name,
                target=self.target,
                **step.get("parameters", {})
            )
            
            if result.get("success"):
                # Use Analyst Agent to interpret results
                self.logger.info("Analyst Agent analyzing results...")
                analysis = await self.analyst.interpret_output(
                    tool=tool_name,
                    target=self.target,
                    command=result.get("command", ""),
                    output=result.get("raw_output", "")
                )
                
                self.logger.info(f"Found {len(analysis['findings'])} findings from {tool_name}")
                
                # Update last tool execution with findings count
                if self.memory.tool_executions:
                    self.memory.tool_executions[-1].findings_count = len(analysis["findings"])
            else:
                self.logger.warning(f"Tool execution failed: {result.get('error')}")
            
        elif step_type == "analysis":
            # AI analysis step
            self.logger.info("Running correlation analysis...")
            analysis = await self.analyst.correlate_findings()
            self.logger.info("Correlation analysis complete")
            
        elif step_type == "report":
            # Generate report
            output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
            output_dir.mkdir(parents=True, exist_ok=True)

            # Always generate markdown and html
            for fmt, ext in (("markdown", "md"), ("html", "html")):
                self.logger.info(f"Generating {fmt} report...")
                report = await self.reporter.execute(format=fmt)
                report_file = output_dir / f"report_{self.memory.session_id}.{ext}"
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(report["content"])
                self.logger.info(f"Report saved to: {report_file}")
        
        self.memory.mark_action_complete(step["name"])
    
    async def _execute_ai_decision(self, decision: Dict[str, Any]):
        """Execute an AI-decided action"""
        action = decision.get("next_action", "")
        
        self.logger.info(f"Executing AI decision: {action}")

        if not action or action == "unknown":
            self.logger.warning("Skipping AI decision because action is unknown/empty")
            self.memory.mark_action_complete(action or "unknown")
            return
        # Skip domain-only actions on IP targets but attempt reverse DNS for recon value
        from utils.helpers import is_valid_ip, reverse_lookup_ip, fetch_tls_names, extract_domain_from_url
        target_host = extract_domain_from_url(self.target) or self.target
        if is_valid_ip(target_host) and action in {"subdomain_enumeration", "dns_enumeration"}:
            hostname = reverse_lookup_ip(target_host)
            if hostname:
                self.logger.info(f"Reverse DNS for {target_host}: {hostname}")
                self.memory.update_context("discovered_assets", [hostname])
                # record as a pseudo tool execution for traceability
                from core.memory import ToolExecution
                self.memory.add_tool_execution(ToolExecution(
                    tool="reverse_dns",
                    command=f"PTR {target_host}",
                    target=target_host,
                    timestamp=datetime.now().isoformat(),
                    exit_code=0,
                    output=hostname,
                    duration=0.0
                ))
            else:
                self.logger.info(f"Reverse DNS for {target_host}: no PTR found")

            # Try to harvest TLS SAN/CN names if 443 is listening
            tls_names = fetch_tls_names(target_host, 443)
            if tls_names:
                self.logger.info(f"TLS names for {target_host}: {', '.join(tls_names)}")
                self.memory.update_context("discovered_assets", tls_names)
                from core.memory import ToolExecution
                self.memory.add_tool_execution(ToolExecution(
                    tool="tls_cert_probe",
                    command=f"TLS SAN/CN from {target_host}:443",
                    target=target_host,
                    timestamp=datetime.now().isoformat(),
                    exit_code=0,
                    output=", ".join(tls_names),
                    duration=0.0
                ))
            else:
                self.logger.info(f"TLS names for {target_host}: none or TLS unavailable")

            self.memory.mark_action_complete(action)
            return
        
        # Use Tool Agent to select appropriate tool
        try:
            tool_selection = await self.tool_agent.execute(
                objective=action,
                target=self.target
            )

            if not tool_selection.get("tool"):
                self.logger.warning("Tool selection returned no tool; skipping execution")
                self.memory.mark_action_complete(action)
                return
            
            # Execute selected tool with parsed arguments when possible
            tool_kwargs: Dict[str, Any] = {}
            args = tool_selection.get("arguments", "") or ""
            if tool_selection["tool"] == "nmap" and args:
                if "-p-" in args:
                    tool_kwargs["ports"] = "1-65535"
                else:
                    import re
                    port_match = re.search(r"-p\\s*([0-9,\\-]+)", args)
                    if port_match:
                        tool_kwargs["ports"] = port_match.group(1)
                if "-sS" in args:
                    tool_kwargs["scan_type"] = "-sS"

            result = await self.tool_agent.execute_tool(
                tool_name=tool_selection["tool"],
                target=self.target,
                **tool_kwargs
            )
            
            if result.get("success"):
                # Analyze with Analyst Agent
                analysis = await self.analyst.interpret_output(
                    tool=tool_selection["tool"],
                    target=self.target,
                    command=result.get("command", ""),
                    output=result.get("raw_output", "")
                )
                self.logger.info(f"Found {len(analysis['findings'])} new findings")
                if self.memory.tool_executions:
                    self.memory.tool_executions[-1].findings_count = len(analysis["findings"])
            
        except Exception as e:
            self.logger.error(f"Failed to execute AI decision: {e}")
        
        self.memory.mark_action_complete(action)
    
    def _load_workflow(self, workflow_name: str) -> List[Dict[str, Any]]:
        """Load workflow definition"""
        # Predefined workflows
        workflows = {
            "recon": [
                {"name": "subdomain_discovery", "type": "tool", "tool": "subfinder"},
                {"name": "port_scanning", "type": "tool", "tool": "nmap"},
                {"name": "web_probing", "type": "tool", "tool": "httpx"},
                {"name": "analysis", "type": "analysis"},
            ],
            "web": [
                {"name": "web_discovery", "type": "tool", "tool": "httpx"},
                {"name": "vulnerability_scan", "type": "tool", "tool": "nuclei"},
                {"name": "analysis", "type": "analysis"},
            ],
            "network": [
                {"name": "port_scan", "type": "tool", "tool": "nmap"},
                {"name": "service_detection", "type": "tool", "tool": "nmap"},
                {"name": "vulnerability_scan", "type": "tool", "tool": "nuclei"},
                {"name": "analysis", "type": "analysis"},
            ]
        }
        
        return workflows.get(workflow_name, workflows["recon"])
    
    def _maybe_advance_phase(self):
        """Advance to next phase based on progress"""
        phases = ["reconnaissance", "scanning", "analysis", "reporting"]
        current_idx = phases.index(self.memory.current_phase) if self.memory.current_phase in phases else 0
        
        # Simple heuristic: advance after certain number of steps
        if self.current_step % 5 == 0 and current_idx < len(phases) - 1:
            new_phase = phases[current_idx + 1]
            self.logger.info(f"Advancing to phase: {new_phase}")
            self.memory.update_phase(new_phase)
    
    def _save_session(self):
        """Save session state"""
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        state_file = output_dir / f"session_{self.memory.session_id}.json"
        self.memory.save_state(state_file)
        self.logger.info(f"Session saved to: {state_file}")

        # Export helper files for manual testing (URLs, payloads/commands)
        urls = self._extract_urls()
        if urls:
            urls_file = output_dir / f"urls_{self.memory.session_id}.txt"
            with open(urls_file, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(set(urls))))
            self.logger.info(f"Exported URLs for manual testing: {urls_file}")

        commands = [te.command for te in self.memory.tool_executions if te.command]
        if commands:
            payloads_file = output_dir / f"payloads_{self.memory.session_id}.txt"
            with open(payloads_file, "w", encoding="utf-8") as f:
                f.write("\n".join(commands))
            self.logger.info(f"Exported tool commands: {payloads_file}")

    def _extract_urls(self) -> List[str]:
        """Collect URLs from tool outputs and commands for export."""
        urls = []
        url_regex = re.compile(r"https?://[^\s\"'>]+")
        for te in self.memory.tool_executions:
            if te.command:
                urls.extend(url_regex.findall(te.command))
            if te.output:
                urls.extend(url_regex.findall(te.output))
        return urls

    def _record_step_duration(self, started_at: datetime):
        """Track step duration for rough ETA logging."""
        elapsed = (datetime.now() - started_at).total_seconds()
        self._step_durations.append(elapsed)
        # Keep the last 10 samples for rolling average
        if len(self._step_durations) > 10:
            self._step_durations.pop(0)

    def _log_progress(self, prefix: str, total: int, current: int):
        """Log a simple progress bar and ETA."""
        current_display = current + 1  # zero-based internal counter
        bar_width = 20
        pct = min(max(current / max(total, 1), 0), 1.0)
        filled = int(bar_width * pct)
        bar = "#" * filled + "-" * (bar_width - filled)

        avg = sum(self._step_durations) / len(self._step_durations) if self._step_durations else None
        remaining = max(total - current, 0)
        eta = f"ETA ~{int(avg * remaining)}s" if avg else "ETA n/a"

        self.logger.info(f"{prefix} Progress [{bar}] {current_display}/{total} ({int(pct*100)}%) {eta}")
