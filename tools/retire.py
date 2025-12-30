"""
Retire.js wrapper for JavaScript library vulnerability scanning
"""

from typing import Dict, Any, List
from tools.base_tool import BaseTool


class RetireTool(BaseTool):
    """Retire.js wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        # Supports scanning a URL or local path
        command = ["retire", "--outputformat", "json"]
        # Retire expects --path for local, --url for remote
        if target.startswith("http://") or target.startswith("https://"):
            command.extend(["--url", target])
        else:
            command.extend(["--path", target])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
