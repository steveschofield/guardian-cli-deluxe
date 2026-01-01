"""
shuffledns wrapper for permutation-based DNS enumeration
"""

import os
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class ShufflednsTool(BaseTool):
    """shuffledns wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["shuffledns", "-d", target]

        if "wordlist" in kwargs:
            wordlist = os.path.expandvars(os.path.expanduser(kwargs["wordlist"]))
            command.extend(["-w", wordlist])
        if "resolvers" in kwargs:
            resolvers = os.path.expandvars(os.path.expanduser(kwargs["resolvers"]))
            command.extend(["-r", resolvers])
        if "massdns" in kwargs:
            massdns = os.path.expandvars(os.path.expanduser(kwargs["massdns"]))
            command.extend(["-m", massdns])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return {"subdomains": lines}
