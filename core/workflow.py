"""
Workflow orchestration engine
Coordinates agents and manages pentest execution flow
"""

import asyncio
import re
import os
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

from core.agent import BaseAgent
from core.planner import PlannerAgent
from core.memory import PentestMemory, ToolExecution, Finding
from ai.provider_factory import get_llm_client
from utils.logger import get_logger
from utils.session_paths import apply_session_paths
from utils.scope_validator import ScopeValidator
from utils.error_handler import ErrorHandler, with_error_handling, GuardianError, ToolExecutionError
from utils.circuit_breaker import EnhancedErrorHandler


class WorkflowEngine:
    """Orchestrates the penetration testing workflow"""
    
    def __init__(self, config: Dict[str, Any], target: str):
        self.config = config or {}
        self.target = target

        # Initialize session memory early so output paths can use session id.
        self.memory = PentestMemory(target)
        self._configure_session_outputs()

        self.logger = get_logger(self.config)

        # Initialize LLM logging
        from utils.llm_logger import init_llm_logger
        init_llm_logger(self.config)

        # Preflight checks for common LLM auth failures so we fail early with actionable guidance.
        self._preflight_llm_auth()
        
        # Initialize components
        self.scope_validator = ScopeValidator(self.config)
        self.llm_client = get_llm_client(self.config)
        self.error_handler = ErrorHandler(self.config)
        self.enhanced_error_handler = EnhancedErrorHandler(self.config)

        # Initialize all agents
        from core.planner import PlannerAgent
        from core.tool_agent import ToolAgent
        from core.analyst_agent import AnalystAgent
        from core.reporter_agent import ReporterAgent

        self.planner = PlannerAgent(self.config, self.llm_client, self.memory)
        self.tool_agent = ToolAgent(self.config, self.llm_client, self.memory)
        self.analyst = AnalystAgent(self.config, self.llm_client, self.memory)
        self.reporter = ReporterAgent(self.config, self.llm_client, self.memory)

        # Log tool availability up front
        try:
            self.tool_agent.log_tool_availability()
        except Exception as e:
            self.logger.warning(f"Tool availability check failed: {e}")
        
        # Workflow state
        self.is_running = False
        self.current_step = 0
        self.max_steps = self.config.get("workflows", {}).get("max_steps", 20)
        self._step_durations: List[float] = []
        self._scope_cache: Dict[str, bool] = {}

    def _configure_session_outputs(self) -> None:
        apply_session_paths(self.config, self.memory.session_id)

    def _log_tool_execution(self, tool: str, args: Dict[str, Any], result: Optional[Dict[str, Any]]) -> None:
        logging_cfg = (self.config or {}).get("logging", {}) or {}
        if not logging_cfg.get("log_tool_executions", False):
            return

        result_text = ""
        if isinstance(result, dict):
            result_text = result.get("raw_output") or result.get("error") or ""
        elif result is not None:
            result_text = str(result)

        self.logger.log_tool_execution(tool=tool, args=args or {}, result=result_text or None)

    def _preflight_llm_auth(self) -> None:
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        provider = (ai_cfg.get("provider") or "gemini").lower()

        if provider != "gemini":
            return

        vertexai = bool(ai_cfg.get("vertexai", False) or ai_cfg.get("use_vertexai", False))
        has_api_key = bool(os.getenv("GOOGLE_API_KEY"))

        # If vertexai is explicitly enabled, or no API key is present, users likely intend ADC.
        if not vertexai and has_api_key:
            return

        project = (
            ai_cfg.get("project")
            or ai_cfg.get("project_id")
            or ai_cfg.get("gcp_project")
            or os.getenv("GOOGLE_CLOUD_PROJECT")
        )
        if not project:
            self.logger.error(
                "Gemini is configured without GOOGLE_API_KEY. For Vertex AI/ADC, set `ai.project` "
                "(project id or project number) in your config and run `gcloud auth application-default login`."
            )
            raise ValueError("Missing Gemini project for Vertex AI/ADC auth.")

        # Fast local check for ADC file. (Google auth will still be the source of truth.)
        adc_env = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        adc_default = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
        has_adc = bool(adc_env and Path(adc_env).exists()) or adc_default.exists()
        if not has_adc:
            self.logger.error(
                "Gemini Vertex AI requires Application Default Credentials (ADC) but none were found. "
                "Run `gcloud auth application-default login` and re-run Guardian."
            )
            raise ValueError("Missing ADC credentials for Gemini Vertex AI.")
    
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
        is_valid, reason = self.scope_validator.validate_target_resolved(self.target)
        if not is_valid:
            self.logger.error(f"Target validation failed: {reason}")
            raise ValueError(f"Invalid target: {reason}")
        
        self.is_running = True
        self.memory.update_phase(f"{workflow_name}_workflow")
        
        try:
            # Load workflow steps
            steps = self._load_workflow(workflow_name)
            if not steps:
                raise ValueError(f"No workflow found for '{workflow_name}'")
            
            # Execute workflow steps
            for step in steps:
                if not self.is_running:
                    break
                self._log_progress(prefix="Workflow", total=len(steps), current=self.current_step)
                self.logger.info(f"Executing step: {step['name']}")
                step_started = datetime.now()
                await self._execute_step(step, workflow_name)
                if self._should_run_planner(step):
                    decision = await self.planner.decide_next_action()
                    self.logger.info(f"Planner checkpoint decision after {step['name']}: {decision.get('next_action')}")
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
            error_result = self.error_handler.handle_error(e, {"workflow": workflow_name, "target": self.target})
            self._save_session()
            if error_result["can_continue"]:
                return {
                    "status": "completed_with_errors",
                    "findings": len(self.memory.findings),
                    "error": str(e),
                    "recovery": error_result["recovery"]
                }
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
        is_valid, reason = self.scope_validator.validate_target_resolved(self.target)
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
            self.logger.exception(f"Autonomous workflow failed: {e}")
            self._save_session()
            raise
        finally:
            self.is_running = False
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status"""
        return {
            "workflow_running": self.is_running,
            "current_step": self.current_step,
            "max_steps": self.max_steps,
            "component_health": self.enhanced_error_handler.get_component_health(),
            "memory_usage": {
                "findings": len(self.memory.findings),
                "tool_executions": len(self.memory.tool_executions)
            }
        }
    
    def stop(self):
        """Stop the workflow"""
        self.logger.info("Stopping workflow")
        self.is_running = False
    
    async def _execute_step(self, step: Dict[str, Any], workflow_name: Optional[str] = None):
        """Execute a workflow step"""
        step_type = step.get("type", "tool")
        
        # Check conditional steps
        if step.get("condition") == "burp_pro_available":
            burp_config = self.config.get("tools", {}).get("burp_pro", {})
            if not burp_config.get("run_additional_scan", True):
                self.logger.info(f"Skipping {step['name']}: Burp Pro additional scan disabled in config")
                return
            if "burp_pro" not in self.tool_agent.available_tools:
                self.logger.info(f"Skipping {step['name']}: Burp Pro not available")
                return
        
        if step.get("condition") == "zap_available":
            zap_config = self.config.get("tools", {}).get("zap", {})
            if not zap_config.get("run_additional_scan", True):
                self.logger.info(f"Skipping {step['name']}: ZAP additional scan disabled in config")
                return
            if "zap" not in self.tool_agent.available_tools:
                self.logger.info(f"Skipping {step['name']}: ZAP not available")
                return
        
        if step_type == "tool":
            # Use Tool Agent to select and execute tool
            tool_name = self._select_tool_for_step(step, workflow_name)
            if not tool_name:
                self.logger.warning("No available tool found for this step, skipping")
                return
            objective = step.get("objective", f"Execute {tool_name}")
            
            # Check if tool is available, skip if not
            if tool_name not in self.tool_agent.available_tools:
                self.logger.warning(f"Tool {tool_name} not available on this platform, skipping step")
                return
            
            self.logger.info(f"Tool Agent selecting tool: {tool_name}")
            
            # Tool Agent executes the tool
            tool_kwargs = step.get("parameters", {}) or {}

            # Allow steps to derive nmap ports from discovered open ports (speeds up vuln scripts).
            if tool_name == "nmap":
                if tool_kwargs.get("ports_from_context") and not tool_kwargs.get("ports"):
                    open_ports = self.memory.context.get("open_ports") or []
                    if isinstance(open_ports, list) and open_ports:
                        ports = []
                        for p in open_ports:
                            try:
                                ports.append(str(int(p)))
                            except Exception:
                                continue
                        if ports:
                            tool_kwargs = dict(tool_kwargs)
                            tool_kwargs["ports"] = ",".join(ports)
                    tool_kwargs = dict(tool_kwargs)
                    tool_kwargs.pop("ports_from_context", None)

            # If we have discovered URLs, run URL-first scanners using the URL list.
            # NOTE: only enable for tools that accept a `from_file` input in our wrappers.
            if tool_name in {"katana", "nuclei"}:
                urls = self._get_discovered_urls()
                if urls and "from_file" not in tool_kwargs:
                    url_file = self._write_urls_file(urls, name=f"{tool_name}_{self.memory.session_id}.txt")
                    tool_kwargs = dict(tool_kwargs)
                    tool_kwargs["from_file"] = str(url_file)

            if not self._scope_allows(self.target):
                self.logger.error(f"Target validation failed before tool execution: {self.target}")
                return

            result = await self.tool_agent.execute_tool(
                tool_name=tool_name,
                target=self.target,
                **tool_kwargs
            )

            self._log_tool_execution(tool=tool_name, args=tool_kwargs, result=result)
            
            if result.get("success"):
                parsed = result.get("parsed") if isinstance(result.get("parsed"), dict) else {}

                # Persist high-signal context from discovery tools.
                if tool_name in {"httpx", "katana"}:
                    urls = parsed.get("urls") or []
                    if isinstance(urls, list) and urls:
                        self.memory.update_context("urls", urls)
                        self.memory.update_context("discovered_assets", urls)

                if tool_name == "nmap":
                    open_ports = parsed.get("open_ports") or []
                    services = parsed.get("services") or []
                    if isinstance(open_ports, list) and open_ports:
                        self.memory.update_context("open_ports", open_ports)
                    if isinstance(services, list) and services:
                        self.memory.update_context("services", services)

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

    def _select_tool_for_step(self, step: Dict[str, Any], workflow_name: Optional[str]) -> Optional[str]:
        primary_tool = step.get("tool")
        preferred: list[str] = []

        step_pref = step.get("preferred_tool") or step.get("preferred_tools")
        if isinstance(step_pref, str):
            preferred.append(step_pref)
        elif isinstance(step_pref, list):
            preferred.extend([str(t) for t in step_pref if str(t).strip()])

        workflows_cfg = (self.config or {}).get("workflows", {}) or {}
        tool_prefs = workflows_cfg.get("tool_preferences", {}) or {}
        if workflow_name and isinstance(tool_prefs, dict):
            wf_prefs = tool_prefs.get(workflow_name, {}) or {}
            step_cfg = wf_prefs.get(step.get("name"), {})
            if isinstance(step_cfg, str):
                preferred.append(step_cfg)
            elif isinstance(step_cfg, list):
                preferred.extend([str(t) for t in step_cfg if str(t).strip()])
            elif isinstance(step_cfg, dict):
                cfg_primary = step_cfg.get("primary")
                if isinstance(cfg_primary, str) and cfg_primary.strip():
                    primary_tool = cfg_primary
                cfg_pref = step_cfg.get("preferred")
                if isinstance(cfg_pref, str):
                    preferred.append(cfg_pref)
                elif isinstance(cfg_pref, list):
                    preferred.extend([str(t) for t in cfg_pref if str(t).strip()])

        candidates = []
        for tool in preferred + ([primary_tool] if primary_tool else []):
            tool = str(tool).strip()
            if not tool or tool in candidates:
                continue
            candidates.append(tool)

        for tool in candidates:
            if tool in self.tool_agent.available_tools:
                if primary_tool and tool != primary_tool:
                    self.logger.info(f"Using preferred tool '{tool}' instead of primary '{primary_tool}'")
                return tool

        return None

    def _get_discovered_urls(self) -> List[str]:
        urls = self.memory.context.get("urls") or []
        if not isinstance(urls, list):
            return []
        # De-dupe and cap to keep downstream tools manageable.
        seen = set()
        out: list[str] = []
        for u in urls:
            if not isinstance(u, str):
                continue
            u = u.strip()
            if not u or u in seen:
                continue
            seen.add(u)
            out.append(u)
            if len(out) >= 2000:
                break
        return self._filter_urls_in_scope(out)

    def _filter_urls_in_scope(self, urls: List[str]) -> List[str]:
        filtered: list[str] = []
        for url in urls:
            if self._scope_allows(url):
                filtered.append(url)
        return filtered

    def _scope_allows(self, target: str) -> bool:
        cached = self._scope_cache.get(target)
        if cached is not None:
            return cached
        is_valid, _reason = self.scope_validator.validate_target_resolved(target)
        self._scope_cache[target] = bool(is_valid)
        return bool(is_valid)

    def _write_urls_file(self, urls: List[str], name: str) -> Path:
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / name
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(urls) + "\n")
        return path

    def _run_ip_enrichment(self, target_ip: str) -> None:
        """Perform lightweight enrichment for IP targets (PTR + TLS cert name harvesting)."""
        from urllib.parse import urlparse
        from utils.helpers import reverse_lookup_ip, fetch_tls_names
        from core.memory import ToolExecution

        hostname = reverse_lookup_ip(target_ip)
        if hostname:
            self.logger.info(f"Reverse DNS for {target_ip}: {hostname}")
            self.memory.update_context("discovered_assets", [hostname])
            self.memory.add_tool_execution(ToolExecution(
                tool="reverse_dns",
                command=f"PTR {target_ip}",
                target=target_ip,
                timestamp=datetime.now().isoformat(),
                exit_code=0,
                output=hostname,
                duration=0.0
            ))
        else:
            self.logger.info(f"Reverse DNS for {target_ip}: no PTR found")

        # Probe standard TLS port, plus an explicit port if the target URL included one.
        ports: list[int] = [443]
        try:
            parsed = urlparse(self.target if "://" in self.target else f"//{self.target}")
            if parsed.port and parsed.port not in ports:
                ports.append(int(parsed.port))
        except Exception:
            pass

        for port in ports:
            tls_names = fetch_tls_names(target_ip, port)
            if tls_names:
                self.logger.info(f"TLS names for {target_ip}:{port}: {', '.join(tls_names)}")
                self.memory.update_context("discovered_assets", tls_names)
                self.memory.add_tool_execution(ToolExecution(
                    tool="tls_cert_probe",
                    command=f"TLS SAN/CN from {target_ip}:{port}",
                    target=target_ip,
                    timestamp=datetime.now().isoformat(),
                    exit_code=0,
                    output=", ".join(tls_names),
                    duration=0.0
                ))
            else:
                self.logger.info(f"TLS names for {target_ip}:{port}: none or TLS unavailable")
    
    async def _execute_ai_decision(self, decision: Dict[str, Any]):
        """Execute an AI-decided action"""
        action = decision.get("next_action", "")
        
        self.logger.info(f"Executing AI decision: {action}")

        if not action or action == "unknown":
            self.logger.warning("Planner returned unknown/empty action; retrying once")
            retry = await self.planner.decide_next_action()
            action = retry.get("next_action", "")
            decision = retry
            if not action or action == "unknown":
                self.logger.warning("Planner still returned unknown; falling back to technology_detection")
                decision = {"next_action": "technology_detection", "parameters": "", "expected_outcome": ""}
                action = "technology_detection"
            self.logger.info(f"Recovered AI decision: {action}")

        # Handle internal (non-tool) actions without routing through ToolSelector.
        output_dir = Path(self.config.get("output", {}).get("save_path", "./reports"))
        output_dir.mkdir(parents=True, exist_ok=True)

        if action == "correlate_findings":
            analysis = await self.analyst.correlate_findings()
            self.memory.update_context("correlate_findings", analysis)
            self.logger.info("Correlation analysis complete")
            self.memory.mark_action_complete(action)
            return

        if action == "risk_assessment":
            assessment = await self.planner.analyze_results()
            content = assessment.get("response", "")
            if content:
                out_file = output_dir / f"risk_assessment_{self.memory.session_id}.md"
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(content)
                self.logger.info(f"Risk assessment saved to: {out_file}")
            self.memory.update_context("risk_assessment", assessment)
            self.memory.mark_action_complete(action)
            return

        if action == "executive_summary":
            summary = await self.reporter.generate_executive_summary()
            out_file = output_dir / f"executive_summary_{self.memory.session_id}.md"
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(summary)
            self.logger.info(f"Executive summary saved to: {out_file}")
            self.memory.update_context("executive_summary", summary)
            self.memory.mark_action_complete(action)
            return

        if action == "remediation_plan":
            plan = await self.reporter.generate_remediation_plan()
            out_file = output_dir / f"remediation_plan_{self.memory.session_id}.md"
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(plan)
            self.logger.info(f"Remediation plan saved to: {out_file}")
            self.memory.update_context("remediation_plan", plan)
            self.memory.mark_action_complete(action)
            return

        if action == "generate_report":
            for fmt, ext in (("markdown", "md"), ("html", "html")):
                self.logger.info(f"Generating {fmt} report...")
                report = await self.reporter.execute(format=fmt)
                report_file = output_dir / f"report_{self.memory.session_id}.{ext}"
                with open(report_file, "w", encoding="utf-8") as f:
                    f.write(report["content"])
                self.logger.info(f"Report saved to: {report_file}")
            self.memory.mark_action_complete(action)
            return

        if action == "ssl_analysis":
            # If the target is a plain-HTTP IP:port and TLS handshakes fail, skip running heavy TLS scanners.
            from urllib.parse import urlparse
            from utils.helpers import is_valid_ip, extract_domain_from_url, fetch_tls_names
            from core.memory import ToolExecution

            host = extract_domain_from_url(self.target) or self.target
            parsed = urlparse(self.target) if "://" in self.target else urlparse(f"//{self.target}")
            scheme = parsed.scheme.lower()
            port = parsed.port

            if is_valid_ip(host) and scheme == "http":
                ports_to_try = [p for p in [port, 443] if p]
                tls_names: list[str] = []
                for p in ports_to_try:
                    tls_names = fetch_tls_names(host, int(p))
                    if tls_names:
                        break
                if not tls_names:
                    self.logger.info(f"Skipping ssl_analysis: {host} does not appear to support TLS on {ports_to_try}")
                    self.memory.add_tool_execution(ToolExecution(
                        tool="tls_probe",
                        command=f"TLS handshake probe {host}:{ports_to_try}",
                        target=host,
                        timestamp=datetime.now().isoformat(),
                        exit_code=0,
                        output="no tls",
                        duration=0.0
                    ))
                    self.memory.mark_action_complete(action)
                    return

        # Skip domain-only actions on IP targets but attempt reverse DNS for recon value
        from utils.helpers import is_valid_ip, extract_domain_from_url
        target_host = extract_domain_from_url(self.target) or self.target
        if is_valid_ip(target_host) and action in {"subdomain_enumeration", "dns_enumeration", "ip_enrichment"}:
            self._run_ip_enrichment(target_host)
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

            # Normalize execution target for domain-only tools when the user provided a URL.
            # E.g. dnsrecon expects a bare domain, not "https://domain".
            exec_target = self.target
            domain_only_tools = {
                "subfinder",
                "dnsrecon",
                "dnsx",
                "shuffledns",
                "puredns",
                "altdns",
                "asnmap",
            }
            if tool_selection["tool"] in domain_only_tools:
                host = extract_domain_from_url(self.target) or self.target
                if host and host != self.target:
                    exec_target = host

            if not self._scope_allows(exec_target):
                self.logger.error(f"Target validation failed before tool execution: {exec_target}")
                self.memory.mark_action_complete(action)
                return

            result = await self.tool_agent.execute_tool(
                tool_name=tool_selection["tool"],
                target=exec_target,
                **tool_kwargs
            )

            self._log_tool_execution(tool=tool_selection["tool"], args=tool_kwargs, result=result)
            
            if result.get("success"):
                # Analyze with Analyst Agent
                analysis = await self.analyst.interpret_output(
                    tool=tool_selection["tool"],
                    target=exec_target,
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
        """Load workflow definition with OS-specific tool selection"""
        import platform
        is_macos = platform.system().lower() == "darwin"
        
        # Use alternative tools on macOS
        web_probing_tool = "gospider" if is_macos else "httpx"
        crawl_tool = "gospider" if is_macos else "katana"
        
        # Predefined workflows
        workflows = {
            "recon": [
                {"name": "subdomain_discovery", "type": "tool", "tool": "subfinder"},
                {"name": "port_scanning", "type": "tool", "tool": "nmap", "parameters": {"profile": "recon"}},
                {"name": "nmap_vuln_scan", "type": "tool", "tool": "nmap", "parameters": {"profile": "vuln", "ports_from_context": True, "tool_timeout": 900}},
                {"name": "web_probing", "type": "tool", "tool": web_probing_tool},
                {"name": "analysis", "type": "analysis"},
                {"name": "report", "type": "report"},
            ],
            "web": [
                {"name": "web_discovery", "type": "tool", "tool": web_probing_tool},
                {"name": "crawl", "type": "tool", "tool": crawl_tool},
                {"name": "vulnerability_scan", "type": "tool", "tool": "nuclei", "parameters": {"tool_timeout": 900}},
                {"name": "burp_pro_scan", "type": "tool", "tool": "burp_pro", "condition": "burp_pro_available"},
                {"name": "zap_scan", "type": "tool", "tool": "zap", "condition": "zap_available"},
                {"name": "analysis", "type": "analysis"},
                {"name": "report", "type": "report"},
            ],
            "network": [
                {"name": "port_scan", "type": "tool", "tool": "nmap", "parameters": {"profile": "recon"}},
                {"name": "nmap_vuln_scan", "type": "tool", "tool": "nmap", "parameters": {"profile": "vuln", "ports_from_context": True, "tool_timeout": 900}},
                {"name": "web_probing", "type": "tool", "tool": web_probing_tool},
                {"name": "crawl", "type": "tool", "tool": crawl_tool},
                {"name": "vulnerability_scan", "type": "tool", "tool": "nuclei", "parameters": {"tool_timeout": 900}},
                {"name": "analysis", "type": "analysis"},
                {"name": "report", "type": "report"},
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

    def _planner_config(self) -> tuple[bool, set[str]]:
        workflows_cfg = (self.config or {}).get("workflows", {}) or {}
        enabled = bool(workflows_cfg.get("use_planner", False))
        checkpoints = workflows_cfg.get("planner_checkpoints") or []
        if isinstance(checkpoints, str):
            checkpoints = [c.strip() for c in checkpoints.split(",") if c.strip()]
        checkpoints_set = {str(c).strip() for c in checkpoints if str(c).strip()}
        return enabled, checkpoints_set

    def _should_run_planner(self, step: Dict[str, Any]) -> bool:
        enabled, checkpoints = self._planner_config()
        if not enabled:
            return False
        if not checkpoints:
            return False
        if "all" in checkpoints:
            return True
        step_name = step.get("name")
        step_type = step.get("type")
        return step_name in checkpoints or step_type in checkpoints
    
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
