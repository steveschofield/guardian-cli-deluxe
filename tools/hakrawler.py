"""
hakrawler wrapper for URL discovery
"""

from typing import Dict, Any, List
from tools.base_tool import BaseTool


class HakrawlerTool(BaseTool):
    """hakrawler wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["hakrawler", "-url", target]
        depth = kwargs.get("depth")
        if depth:
            command.extend(["-depth", str(depth)])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        return {"urls": urls}
