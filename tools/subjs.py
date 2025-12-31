"""
subjs wrapper for JavaScript URL extraction
"""

from typing import Dict, Any, List
from tools.base_tool import BaseTool


class SubjsTool(BaseTool):
    """subjs wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["subjs"]
        if kwargs.get("from_file"):
            command.extend(["-iL", kwargs["from_file"]])
        else:
            command.extend(["-i", target])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        return {"urls": urls}
