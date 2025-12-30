"""
shuffledns wrapper for permutation-based DNS enumeration
"""

from typing import Dict, Any, List
from tools.base_tool import BaseTool


class ShufflednsTool(BaseTool):
    """shuffledns wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["shuffledns", "-d", target]

        if "wordlist" in kwargs:
            command.extend(["-w", kwargs["wordlist"]])
        if "resolvers" in kwargs:
            command.extend(["-r", kwargs["resolvers"]])
        if "massdns" in kwargs:
            command.extend(["-m", kwargs["massdns"]])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return {"subdomains": lines}
