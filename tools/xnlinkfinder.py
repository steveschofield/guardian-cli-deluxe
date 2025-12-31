"""
xnLinkFinder wrapper for advanced JS endpoint extraction
"""

import re
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class XnlinkfinderTool(BaseTool):
    """xnlinkfinder wrapper"""

    def __init__(self, config):
        super().__init__(config)
        # Binary installs as 'xnLinkFinder'
        self.tool_name = "xnLinkFinder"
        self.is_available = self._check_installation()
        if not self.is_available:
            self.logger.warning(f"Tool {self.tool_name} is not installed or not in PATH")

    def get_command(self, target: str, **kwargs) -> List[str]:
        command = [self.tool_name, "-i", target]
        if kwargs.get("domain"):
            command.extend(["-d", kwargs["domain"]])
        if kwargs.get("output"):
            command.extend(["-o", kwargs["output"]])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = []
        for line in output.splitlines():
            for match in re.findall(r"https?://[^\s\"'<>]+", line):
                urls.append(match)
        return {"urls": urls}
