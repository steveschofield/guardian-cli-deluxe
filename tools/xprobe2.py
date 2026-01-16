"""
xprobe2 tool wrapper for OS fingerprinting
"""

import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class Xprobe2Tool(BaseTool):
    """xprobe2 OS fingerprinting wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "xprobe2"

    def _check_installation(self) -> bool:
        return shutil.which("xprobe2") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("xprobe2", {}) or {}
        args = kwargs.get("args") or cfg.get("args") or "-v"
        command = ["xprobe2"]
        if args:
            command.extend(str(args).split())
        command.append(target)
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        guess = ""
        for line in (output or "").splitlines():
            if "Primary guess" in line:
                guess = line.split(":", 1)[-1].strip()
                break
        return {"os_guess": guess}
