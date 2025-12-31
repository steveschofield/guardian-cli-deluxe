"""
Metasploit wrapper for scripted module execution
"""

import shutil
from typing import Dict, Any, List
from tools.base_tool import BaseTool
from utils.logger import get_logger


class MetasploitTool(BaseTool):
    """metasploit wrapper (msfconsole scripted run)"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger(config)
        self.tool_name = "msfconsole"
        self.is_available = self._check_installation()
        if not self.is_available:
            self.logger.warning(f"Tool {self.tool_name} is not installed or not in PATH")

    def get_command(self, target: str, **kwargs) -> List[str]:
        if kwargs.get("msf_commands"):
            command_string = kwargs["msf_commands"]
        elif kwargs.get("module"):
            module = kwargs["module"]
            rhosts = kwargs.get("rhosts", target)
            extra = kwargs.get("extra_commands", "")
            command_string = f"use {module}; set RHOSTS {rhosts}; {extra}; run; exit"
        else:
            # Fast sanity check
            command_string = "version; exit"

        return ["msfconsole", "-q", "-x", command_string]

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw_output": output}
