"""
gospider wrapper for web crawling
"""

from typing import Dict, Any, List
from tools.base_tool import BaseTool


class GospiderTool(BaseTool):
    """gospider wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["gospider", "-s", target, "-d", str(kwargs.get("depth", 1))]
        if kwargs.get("js"):
            command.append("-js")
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        return {"urls": urls}
