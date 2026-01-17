"""
JSParser wrapper for JavaScript endpoint extraction
"""

import os
import re
import shutil
import sys
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class JsparserTool(BaseTool):
    """JSParser wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "jsparser"
        self._script_path = None
        self._binary_path = None

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("jsparser", {}) or {}
        script = cfg.get("script")
        binary = cfg.get("binary")

        if script and os.path.isfile(str(script)):
            self._script_path = str(script)
            return True

        if binary and os.path.isfile(str(binary)):
            self._binary_path = str(binary)
            return True

        local_script = self._local_script()
        if local_script and os.path.isfile(local_script):
            self._script_path = local_script
            return True

        found = shutil.which("jsparser")
        if found:
            self._binary_path = found
            return True

        return False

    def _local_script(self) -> str | None:
        here = os.path.abspath(os.path.dirname(__file__))
        repo_root = os.path.abspath(os.path.join(here, os.pardir))
        candidates = [
            os.path.join(repo_root, "tools", "vendor", "guardian_tools", "jsparser.py"),
            os.path.join(repo_root, "tools", "vendor", "JSParser", "JSParser.py"),
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("jsparser", {}) or {}
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")
        script = kwargs.get("script") or cfg.get("script") or self._script_path
        binary = kwargs.get("binary") or cfg.get("binary") or self._binary_path or "jsparser"

        if not args:
            args = "-u {target}"

        args = str(args).replace("{target}", target)

        if script:
            script = os.path.expandvars(os.path.expanduser(str(script)))
            return [sys.executable, script] + args.split()

        return [binary] + args.split()

    def parse_output(self, output: str) -> Dict[str, Any]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        urls = []
        for line in lines:
            for match in re.findall(r"https?://[^\s\"'<>]+", line):
                urls.append(match)
        return {"raw": output, "urls": urls, "lines": lines}
