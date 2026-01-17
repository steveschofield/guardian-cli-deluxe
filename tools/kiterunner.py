"""
Kiterunner wrapper for schema-less API route discovery
"""

import os
import re
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class KiterunnerTool(BaseTool):
    """Kiterunner wrapper"""

    def __init__(self, config):
        self._binary = None
        super().__init__(config)
        self.tool_name = "kiterunner"

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("kiterunner", {}) or {}
        binary = cfg.get("binary")
        if binary and os.path.isfile(str(binary)):
            self._binary = str(binary)
            return True
        for candidate in ("kr", "kiterunner"):
            found = shutil.which(candidate)
            if found:
                self._binary = found
                return True
        for candidate in self._local_candidates():
            if os.path.isfile(candidate):
                self._binary = candidate
                return True
        return False

    def _local_candidates(self) -> List[str]:
        here = os.path.abspath(os.path.dirname(__file__))
        repo_root = os.path.abspath(os.path.join(here, os.pardir))
        guardian_home = os.getenv("GUARDIAN_HOME")
        candidates = [
            os.path.join(repo_root, "tools", ".bin", "kr"),
            os.path.join(repo_root, "tools", ".bin", "kiterunner"),
        ]
        if guardian_home:
            candidates.append(os.path.join(guardian_home, "tools", ".bin", "kr"))
            candidates.append(os.path.join(guardian_home, "tools", ".bin", "kiterunner"))
        return candidates

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("kiterunner", {}) or {}
        binary = self._binary or cfg.get("binary") or "kr"
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")

        if args:
            args = str(args).replace("{target}", target)
            return [binary] + args.split()

        wordlist = kwargs.get("wordlist") if "wordlist" in kwargs else cfg.get("wordlist")
        if wordlist:
            wordlist = os.path.expandvars(os.path.expanduser(str(wordlist)))
        else:
            raise ValueError("kiterunner requires args or a wordlist")

        command = [binary, "scan", target, "-w", wordlist]
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = []
        paths = []
        lines = [line.strip() for line in output.splitlines() if line.strip()]

        for line in lines:
            line_urls = re.findall(r"https?://[^\s\"'<>]+", line)
            if line_urls:
                urls.extend(line_urls)
                continue
            match = re.search(r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(/\S+)", line, re.IGNORECASE)
            if match:
                paths.append(match.group(2))

        return {"raw": output, "urls": urls, "paths": paths, "lines": lines}
