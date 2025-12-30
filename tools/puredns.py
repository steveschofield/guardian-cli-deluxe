"""
puredns wrapper for DNS resolution
"""

from typing import Dict, Any, List
from tools.base_tool import BaseTool


class PurednsTool(BaseTool):
    """puredns wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        # Usually used as resolver for shuffledns; here simple resolve mode
        command = ["puredns", "resolve", target]

        if "resolvers" in kwargs:
            command.extend(["-r", kwargs["resolvers"]])
        if "wordlist" in kwargs:
            command.extend(["-w", kwargs["wordlist"]])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return {"resolved": lines}
