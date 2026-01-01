"""
dirsearch wrapper for content discovery
"""

import os
import re
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class DirsearchTool(BaseTool):
    """dirsearch wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        config = self.config.get("tools", {}).get("dirsearch", {})
        command = ["dirsearch", "-u", target]

        wordlist = kwargs.get("wordlist") or config.get("wordlist")
        if wordlist:
            wordlist = os.path.expandvars(os.path.expanduser(wordlist))
            command.extend(["-w", wordlist])

        extensions = kwargs.get("extensions") or config.get("extensions")
        if extensions:
            command.extend(["-e", extensions])

        threads = kwargs.get("threads") or config.get("threads")
        if threads:
            command.extend(["-t", str(threads)])

        if kwargs.get("recursive") or config.get("recursive"):
            command.append("-r")

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        results = []
        for line in output.splitlines():
            status = None
            status_match = re.search(r"\[(\d{3})\]", line)
            if status_match:
                status = int(status_match.group(1))

            url_match = re.search(r"(https?://[^\s]+)", line)
            if url_match:
                results.append({"url": url_match.group(1), "status": status})

        return {"results": results}
