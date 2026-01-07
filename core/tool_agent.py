"""
Tool Selector Agent
Selects appropriate pentesting tools and configures them
"""

from typing import Dict, Any, Optional
from core.agent import BaseAgent
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
            SQLMapTool, FFufTool, AmassTool, WPScanTool, SSLyzeTool, MasscanTool,
            ArjunTool, XSStrikeTool, GitleaksTool, CMSeekTool, DnsReconTool,
            DnsxTool, ShufflednsTool, PurednsTool, AltdnsTool,
            HakrawlerTool, GospiderTool, RetireTool, NaabuTool, KatanaTool,
            AsnmapTool, WaybackurlsTool, SubjsTool, DirsearchTool,
            LinkfinderTool, XnlinkfinderTool, ParamspiderTool,
            SchemathesisTool, TrufflehogTool, MetasploitTool, ZapTool
        )

        self.available_tools = {
            "nmap": NmapTool(config),
            "httpx": HttpxTool(config),
            "subfinder": SubfinderTool(config),
            "nuclei": NucleiTool(config),
            "whatweb": WhatWebTool(config),
            "wafw00f": Wafw00fTool(config),
            "nikto": NiktoTool(config),
            "testssl": TestSSLTool(config),
            "gobuster": GobusterTool(config),
            "sqlmap": SQLMapTool(config),
            "ffuf": FFufTool(config),
            "amass": AmassTool(config),
            "wpscan": WPScanTool(config),
            "sslyze": SSLyzeTool(config),
            "masscan": MasscanTool(config),
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
            "katana": KatanaTool(config),
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
        }

    def log_tool_availability(self):
        """Log availability of all registered tools and basic install hints."""
        install_hints = {
            "nmap": "apt install nmap",
            "masscan": "apt install masscan (or build from source)",
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
            "amass": "go install github.com/owasp-amass/amass/v4/...@master",
            "wpscan": "gem install wpscan",
            "sslyze": "pip install sslyze",
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
        dns_like = {"subfinder", "amass", "dnsrecon", "dnsx", "shuffledns", "puredns", "altdns", "asnmap"}
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
        Execute a selected tool
        
        Returns:
            Tool execution results
        """
        if tool_name not in self.available_tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        tool = self.available_tools[tool_name]
        
        if not tool.is_available:
            self.logger.warning(f"Tool {tool_name} is not installed")
            return {
                "success": False,
                "error": f"Tool {tool_name} not available",
                "tool": tool_name
            }
        
        try:
            # Execute tool
            result = await tool.execute(target, **kwargs)

            # Record execution in memory (even on non-zero exit for audit/debug)
            from core.memory import ToolExecution
            execution = ToolExecution(
                tool=tool_name,
                command=result["command"],
                target=target,
                timestamp=result.get("timestamp", ""),
                exit_code=result["exit_code"],
                output=result.get("raw_output", ""),
                duration=result["duration"]
            )
            self.memory.add_tool_execution(execution)

            # Treat non-zero exit as failure (still returning captured output/error)
            if result.get("exit_code", 0) != 0:
                err = result.get("error") or "Tool exited with non-zero status"
                self.logger.warning(f"Tool {tool_name} exited non-zero ({result.get('exit_code')}): {err}")
                return {
                    "success": False,
                    "error": err,
                    "tool": tool_name,
                    "raw_output": result.get("raw_output", ""),
                    "exit_code": result.get("exit_code"),
                }
            
            return {
                "success": True,
                "tool": tool_name,
                "parsed": result["parsed"],
                "raw_output": result["raw_output"],
                "duration": result["duration"],
                "exit_code": result["exit_code"],
            }
            
        except ValueError as e:
            self.logger.warning(f"Tool {tool_name} skipped: {e}")
            return {
                "success": False,
                "error": str(e),
                "tool": tool_name,
                "skipped": True
            }
        except Exception as e:
            self.logger.error(f"Tool execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "tool": tool_name
            }
    
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

        return selection
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get status of all tools"""
        return {
            name: tool.is_available
            for name, tool in self.available_tools.items()
        }
