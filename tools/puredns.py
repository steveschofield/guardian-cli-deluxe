"""
puredns wrapper for DNS resolution
"""

import os
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class PurednsTool(BaseTool):
    """puredns wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        # Usually used as resolver for shuffledns; here simple resolve mode
        command = ["puredns", "resolve", target]

        if "resolvers" in kwargs:
            resolvers = os.path.expandvars(os.path.expanduser(kwargs["resolvers"]))
            command.extend(["-r", resolvers])
        if "wordlist" in kwargs:
            wordlist = os.path.expandvars(os.path.expanduser(kwargs["wordlist"]))
            command.extend(["-w", wordlist])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return {"resolved": lines}
