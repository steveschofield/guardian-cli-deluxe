"""
Tool Selector Agent
Selects appropriate pentesting tools and configures them
"""

import asyncio
from typing import Dict, Any, Optional
from core.agent import BaseAgent
from utils.error_handler import ToolExecutionError, with_error_handling
from ai.prompt_templates import (
    TOOL_SELECTOR_SYSTEM_PROMPT,
    TOOL_SELECTION_PROMPT,
    TOOL_PARAMETERS_PROMPT
)
from tools import (
    NmapTool,
    HttpxTool,
    SubfinderTool,
    NucleiTool,
)


class ToolAgent(BaseAgent):
    """Agent that selects and configures pentesting tools"""
    
    def __init__(self, config, llm_client, memory):
        super().__init__("ToolSelector", config, llm_client, memory)
        
        # Initialize available tools
        from tools import (
            NmapTool, HttpxTool, SubfinderTool, NucleiTool,
            WhatWebTool, Wafw00fTool, NiktoTool, TestSSLTool, GobusterTool,
            SQLMapTool, FFufTool, WPScanTool, SSLyzeTool, HeadersTool, MasscanTool, UdpProtoScannerTool,
            ArjunTool, XSStrikeTool, GitleaksTool, CMSeekTool, DnsReconTool,
            DnsxTool, ShufflednsTool, PurednsTool, AltdnsTool,
            HakrawlerTool, GospiderTool, RetireTool, NaabuTool, KatanaTool,
            AsnmapTool, WaybackurlsTool, SubjsTool, DirsearchTool,
            LinkfinderTool, XnlinkfinderTool, ParamspiderTool,
            SchemathesisTool, TrufflehogTool, MetasploitTool, ZapTool,
            DalfoxTool, CommixTool, FeroxbusterTool
        )

        import platform
        
        self.available_tools = {
            "nmap": NmapTool(config),
            "subfinder": SubfinderTool(config),
            "nuclei": NucleiTool(config),
            "whatweb": WhatWebTool(config),
            "wafw00f": Wafw00fTool(config),
            "nikto": NiktoTool(config),
            "testssl": TestSSLTool(config),
            "gobuster": GobusterTool(config),
            "sqlmap": SQLMapTool(config),
            "ffuf": FFufTool(config),
            "wpscan": WPScanTool(config),
            "sslyze": SSLyzeTool(config),
            "headers": HeadersTool(config),
            "masscan": MasscanTool(config),
            "udp-proto-scanner": UdpProtoScannerTool(config),
            "arjun": ArjunTool(config),
            "xsstrike": XSStrikeTool(config),
            "gitleaks": GitleaksTool(config),
            "cmseek": CMSeekTool(config),
            "dnsrecon": DnsReconTool(config),
            "dnsx": DnsxTool(config),
            "shuffledns": ShufflednsTool(config),
            "puredns": PurednsTool(config),
            "altdns": AltdnsTool(config),
            "hakrawler": HakrawlerTool(config),
            "gospider": GospiderTool(config),
            "retire": RetireTool(config),
            "naabu": NaabuTool(config),
            "asnmap": AsnmapTool(config),
            "waybackurls": WaybackurlsTool(config),
            "subjs": SubjsTool(config),
            "dirsearch": DirsearchTool(config),
            "linkfinder": LinkfinderTool(config),
            "xnlinkfinder": XnlinkfinderTool(config),
            "paramspider": ParamspiderTool(config),
            "schemathesis": SchemathesisTool(config),
            "trufflehog": TrufflehogTool(config),
            "metasploit": MetasploitTool(config),
            "zap": ZapTool(config),
            "dalfox": DalfoxTool(config),
            "commix": CommixTool(config),
            "feroxbuster": FeroxbusterTool(config),
        }
        
        # Add OS-specific tools
        if platform.system().lower() != "darwin":  # Not macOS
            self.available_tools["httpx"] = HttpxTool(config)
            self.available_tools["katana"] = KatanaTool(config)
        else:  # macOS only
            from tools.burp_pro import BurpProTool
            self.available_tools["burp_pro"] = BurpProTool(config)


    def log_tool_availability(self):
        """Log availability of all registered tools and basic install hints."""
        install_hints = {
            "nmap": "apt install nmap",
            "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "whatweb": "git clone https://github.com/urbanadventurer/WhatWeb",
            "wafw00f": "pip install wafw00f",
            "nikto": "apt install nikto",
            "testssl": "git clone https://github.com/drwetter/testssl.sh.git",
            "gobuster": "go install github.com/OJ/gobuster/v3@latest",
            "sqlmap": "pip install sqlmap",
            "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
            "wpscan": "gem install wpscan",
            "sslyze": "pip install sslyze",
            "headers": "apt install curl",
            "masscan": "apt install masscan",
            "udp-proto-scanner": "apt install udp-proto-scanner",
            "arjun": "pip install arjun",
            "xsstrike": "git clone https://github.com/s0md3v/XSStrike.git",
            "gitleaks": "go install github.com/zricethezav/gitleaks/v8@latest",
            "cmseek": "git clone https://github.com/Tuhinshubhra/CMSeeK.git",
            "dnsrecon": "pip install dnsrecon",
            "dnsx": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "shuffledns": "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
            "puredns": "go install github.com/d3mondev/puredns@latest",
            "altdns": "pip install altdns",
            "hakrawler": "go install github.com/hakluke/hakrawler@latest",
            "gospider": "go install github.com/jaeles-project/gospider@latest",
            "retire": "npm install -g retire",
            "naabu": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "asnmap": "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
            "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
            "subjs": "go install github.com/lc/subjs@latest",
            "dirsearch": "pip install dirsearch",
            "linkfinder": "pip install git+https://github.com/GerbenJavado/LinkFinder.git",
            "xnlinkfinder": "pip install xnlinkfinder",
            "paramspider": "pip install git+https://github.com/devanshbatham/ParamSpider.git",
            "schemathesis": "pip install schemathesis",
            "trufflehog": "pip install trufflehog",
            "metasploit": "install via https://www.metasploit.com/ (msfconsole on PATH)",
            "zap": "docker pull ghcr.io/zaproxy/zaproxy:stable (requires Docker)",
            "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
            "commix": "pip install commix",
            "feroxbuster": "cargo install feroxbuster",
            "burp_pro": "Install Burp Suite Professional (macOS only)",
        }

        missing = []
        for name, tool in self.available_tools.items():
            if tool.is_available:
                self.logger.info(f"Tool available: {name}")
            else:
                self.logger.warning(f"Tool missing: {name} ({install_hints.get(name, 'install manually')})")
                missing.append(name)
        if missing:
            self.logger.warning(f"Missing tools: {', '.join(missing)}. Some functionality will be limited.")

    
    async def execute(self, objective: str, target: str, **kwargs) -> Dict[str, Any]:
        """
        Select and configure the best tool for an objective
        
        Args:
            objective: What we're trying to accomplish
            target: Target to scan
            **kwargs: Additional context
        
        Returns:
            Dict with selected tool and configuration
        """
        # Determine target type and normalize for downstream tools
        target_type = self._detect_target_type(target)
        normalized_target = self._normalize_target_for_tooling(target, target_type)
        
        # Get context from memory
        context = self.memory.get_context_for_ai()
        
        # Ask AI to select tool
        prompt = TOOL_SELECTION_PROMPT.format(
            objective=objective,
            target=normalized_target,
            target_type=target_type,
            phase=self.memory.current_phase,
            context=context
        )
        
        result = await self.think(prompt, TOOL_SELECTOR_SYSTEM_PROMPT)
        
        # Parse tool selection
        tool_selection = self._parse_selection(result["response"])
        if not tool_selection.get("tool"):
            self.logger.warning("Tool parse failed; refusing to default to an arbitrary tool")
            return {
                "tool": "",
                "arguments": "",
                "reasoning": "Could not parse TOOL from ToolSelector response",
                "expected_output": ""
            }

        # Fail closed: if the model returns a tool name we don't have registered, do not attempt execution.
        if tool_selection["tool"] not in self.available_tools:
            self.logger.warning(
                f"Model selected unknown tool '{tool_selection['tool']}'; skipping selection"
            )
            return {
                "tool": "",
                "arguments": "",
                "reasoning": f"Unknown tool selected by model: {tool_selection['tool']}",
                "expected_output": ""
            }

        # Gate DNS/subdomain tools when target is IP-only
        dns_like = {"subfinder", "dnsrecon", "dnsx", "shuffledns", "puredns", "altdns", "asnmap"}
        if target_type == "ip" and tool_selection["tool"] in dns_like:
            self.logger.warning(f"Tool {tool_selection['tool']} not suitable for IP targets; skipping selection")
            return {
                "tool": "",
                "arguments": "",
                "reasoning": "Selected tool is DNS-only and target is an IP",
                "expected_output": ""
            }

        # De-duplicate httpx when no new context: if last tool was httpx with same target, skip
        if tool_selection["tool"] == "httpx":
            recent = self.memory.tool_executions[-1] if self.memory.tool_executions else None
            if recent and recent.tool == "httpx":
                recent_norm = self._normalize_target_for_tooling(recent.target, self._detect_target_type(recent.target))
                if recent_norm == normalized_target:
                    self.logger.info("Skipping redundant httpx run; recent httpx already executed for this target")
                    return {
                        "tool": "",
                        "arguments": "",
                        "reasoning": "Recent httpx already executed for this target",
                        "expected_output": ""
                    }
        
        self.log_action("ToolSelected", f"{tool_selection['tool']} for {objective}")
        
        return {
            "tool": tool_selection["tool"],
            "arguments": tool_selection.get("arguments", ""),
            "reasoning": result["reasoning"],
            "expected_output": tool_selection.get("expected_output", "")
        }
    
    async def configure_tool(self, tool_name: str, objective: str, target: str) -> Dict[str, Any]:
        """
        Generate optimal parameters for a specific tool
        
        Returns:
            Dict with tool parameters and justification
        """
        safe_mode = self.config.get("pentest", {}).get("safe_mode", True)
        timeout = (self.config.get("tools", {}).get(tool_name, {}) or {}).get("tool_timeout")
        if timeout is None:
            timeout = self.config.get("pentest", {}).get("tool_timeout", 300)
        
        prompt = TOOL_PARAMETERS_PROMPT.format(
            tool=tool_name,
            objective=objective,
            target=target,
            safe_mode=safe_mode,
            stealth=False,  # Could be configurable
            timeout=timeout
        )
        
        result = await self.think(prompt, TOOL_SELECTOR_SYSTEM_PROMPT)
        
        return {
            "parameters": result["response"],
            "justification": result["reasoning"]
        }
    
    async def execute_tool(self, tool_name: str, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute a selected tool with robust error handling
        
        Returns:
            Tool execution results
        """
        if tool_name not in self.available_tools:
            return self._record_tool_failure(
                tool_name=tool_name,
                target=target,
                error=f"Unknown tool: {tool_name}",
                exit_code=127,
                skipped=True,
            )
        
        tool = self.available_tools[tool_name]
        
        if not tool.is_available:
            # Re-check availability for tools that might have dynamic dependencies
            if hasattr(tool, '_check_installation'):
                if not tool._check_installation():
                    self.logger.warning(f"Tool {tool_name} not available (dependency check failed)")
                    return self._record_tool_failure(
                        tool_name=tool_name,
                        target=target,
                        error=f"Tool {tool_name} dependencies not available",
                        exit_code=127,
                        skipped=True,
                    )
            else:
                return self._record_tool_failure(
                    tool_name=tool_name,
                    target=target,
                    error=f"Tool {tool_name} not installed",
                    exit_code=127,
                    skipped=True,
                )
        
        try:
            # Execute tool with circuit breaker protection
            timeout = kwargs.pop('tool_timeout', self.config.get("pentest", {}).get("tool_timeout", 300))
            
            # Use enhanced error handler if available
            if hasattr(self, 'enhanced_error_handler'):
                result = await self.enhanced_error_handler.execute_with_protection(
                    "tool_execution",
                    lambda: asyncio.wait_for(tool.execute(target, **kwargs), timeout=timeout)
                )
                if not result["success"]:
                    return self._record_tool_failure(
                        tool_name=tool_name,
                        target=target,
                        error=result["error"],
                        exit_code=1,
                        skipped=False,
                    )
                result = result["result"]
            else:
                result = await asyncio.wait_for(tool.execute(target, **kwargs), timeout=timeout)

            # Record execution in memory (even on non-zero exit for audit/debug)
            from core.memory import ToolExecution
            raw_output = self._truncate_output(result.get("raw_output", "") or "")
            execution = ToolExecution(
                tool=tool_name,
                command=result["command"],
                target=target,
                timestamp=result.get("timestamp", ""),
                exit_code=result["exit_code"],
                output=raw_output,
                duration=result["duration"]
            )
            self.memory.add_tool_execution(execution)

            # Handle non-zero exit codes
            if result.get("exit_code", 0) != 0:
                error_msg = result.get("error") or "Tool exited with non-zero status"
                return {
                    "success": False,
                    "tool": tool_name,
                    "parsed": result["parsed"],
                    "raw_output": raw_output,
                    "duration": result["duration"],
                    "exit_code": result["exit_code"],
                    "error": error_msg,
                }
            
            return {
                "success": True,
                "tool": tool_name,
                "parsed": result["parsed"],
                "raw_output": raw_output,
                "duration": result["duration"],
                "exit_code": result["exit_code"],
            }
            
        except asyncio.TimeoutError:
            return self._record_tool_failure(
                tool_name=tool_name,
                target=target,
                error=f"Tool {tool_name} timed out after {timeout}s",
                exit_code=124,
                skipped=False,
            )
        except ValueError as e:
            self.logger.warning(f"Tool {tool_name} skipped: {e}")
            return self._record_tool_failure(
                tool_name=tool_name,
                target=target,
                error=str(e),
                exit_code=0,
                skipped=True,
            )
        except Exception as e:
            return self._record_tool_failure(
                tool_name=tool_name,
                target=target,
                error=f"Tool execution failed: {str(e)}",
                exit_code=1,
                skipped=False,
            )

    def _record_tool_failure(
        self,
        tool_name: str,
        target: str,
        error: str,
        exit_code: int,
        skipped: bool,
    ) -> Dict[str, Any]:
        """Record a failed or skipped tool execution and return a failure result."""
        from core.memory import ToolExecution
        timestamp = self._get_timestamp()
        output = f"skipped: {error}" if skipped else error
        execution = ToolExecution(
            tool=tool_name,
            command="",
            target=target,
            timestamp=timestamp,
            exit_code=exit_code,
            output=self._truncate_output(output),
            duration=0.0,
        )
        self.memory.add_tool_execution(execution)
        return {
            "success": False,
            "tool": tool_name,
            "error": error,
            "exit_code": exit_code,
            "skipped": skipped,
        }

    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _detect_target_type(self, target: str) -> str:
        """Detect if target is IP, domain, or URL"""
        from utils.helpers import is_valid_ip, is_valid_domain, is_valid_url, extract_domain_from_url
        # If it's a URL pointing to an IP, treat as IP
        if is_valid_url(target):
            host = extract_domain_from_url(target)
            if host and is_valid_ip(host):
                return "ip"
            return "url"
        if is_valid_ip(target):
            return "ip"
        if is_valid_domain(target):
            return "domain"
        return "unknown"

    def _normalize_target_for_tooling(self, target: str, target_type: str) -> str:
        """Strip schemes/ports for domain-only tools and gate non-domain actions."""
        from urllib.parse import urlparse

        if target_type == "url":
            parsed = urlparse(target)
            return parsed.netloc or target
        if target_type in ("ip", "domain"):
            return target
        return target

    def _truncate_output(self, output: str) -> str:
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        max_chars = ai_cfg.get("max_tool_output_chars", 20000)
        try:
            max_chars = int(max_chars)
        except Exception:
            max_chars = 20000
        if max_chars > 0 and len(output) > max_chars:
            return output[:max_chars] + "\n... (truncated)"
        return output
    
    def _parse_selection(self, response: str) -> Dict[str, str]:
        """Parse AI tool selection response.

        More tolerant of markdown/bold formatting (e.g., '**TOOL**: `nuclei`')
        and fails closed (returns empty tool) when parsing fails.
        """
        import re

        selection = {
            "tool": "",
            "arguments": "",
            "expected_output": ""
        }

        if not response:
            return selection

        # Match variants like "TOOL:", "**TOOL**:", "Tool:", with optional backticks
        tool_match = re.search(
            r"(?:^|\n)\s*(?:\d+[\.\)]\s*)?\**\s*tool\**\s*:\s*`?([a-zA-Z0-9_-]+)`?",
            response,
            re.IGNORECASE,
        )
        if tool_match:
            selection["tool"] = tool_match.group(1).lower()

        args_match = re.search(
            r"(?:^|\n)\s*(?:\d+[\.\)]\s*)?\**\s*arguments\**\s*:\s*(.+?)(?:\n\s*(?:\d+[\.\)]\s*)?\**\s*expected_output\**\s*:|$)",
            response,
            re.IGNORECASE | re.DOTALL,
        )
        if args_match:
            selection["arguments"] = args_match.group(1).strip()

        expected_match = re.search(
            r"(?:^|\n)\s*(?:\d+[\.\)]\s*)?\**\s*expected_output\**\s*:\s*(.+)$",
            response,
            re.IGNORECASE | re.DOTALL,
        )
        if expected_match:
            selection["expected_output"] = expected_match.group(1).strip()

        # Fallbacks: models often answer with markdown prose ("best tool would be **dnsrecon**").
        # Prefer selecting from the "primary" portion before any "Alternative Tools" section.
        primary = re.split(r"\n\s*#{1,6}\s*alternative|\nalternative tools?:", response, flags=re.IGNORECASE)[0]

        if not selection["tool"]:
            # Try to capture a bolded/backticked tool mention near the recommendation.
            rec_match = re.search(
                r"(?:best tool|recommend(?:ation)?|would be|use)\s+(?:the\s+)?\**`?([a-zA-Z0-9_-]+)`?\**",
                primary[:600],
                re.IGNORECASE,
            )
            if rec_match:
                candidate = rec_match.group(1).lower()
                if candidate in self.available_tools:
                    selection["tool"] = candidate

        if not selection["tool"]:
            # Last-resort: pick the first known tool name mentioned in the primary section.
            for name in self.available_tools.keys():
                if re.search(rf"\b{re.escape(name)}\b", primary, re.IGNORECASE):
                    selection["tool"] = name
                    break

        # If arguments are inside a fenced code block, extract the first command-like line.
        # This is useful when models output:
        # ### ARGUMENTS:
        # ```\n dnsrecon -d example.com \n```
        if not selection["arguments"] or "```" in selection["arguments"]:
            fence_match = re.search(r"```(?:bash|sh|shell)?\s*\n([\s\S]*?)```", response, re.IGNORECASE)
            if fence_match:
                block = fence_match.group(1)
                first_line = ""
                for line in block.splitlines():
                    line = line.strip()
                    if line:
                        first_line = line
                        break
                if first_line:
                    selection["arguments"] = first_line

        # Normalize "arguments" to be args-only when it starts with the tool name.
        if selection["tool"] and selection["arguments"]:
            parts = selection["arguments"].strip().split()
            if parts and parts[0].lower() == selection["tool"]:
                selection["arguments"] = " ".join(parts[1:]).strip()

        return selection
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get status of all tools"""
        return {
            name: tool.is_available
            for name, tool in self.available_tools.items()
        }
