"""
tplmap tool wrapper for template injection testing
"""

import os
import shutil
import sys
from pathlib import Path
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class TplmapTool(BaseTool):
    """tplmap wrapper"""

    def __init__(self, config):
        self._script = None
        super().__init__(config)
        self.tool_name = "tplmap"

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("tplmap", {}) or {}
        binary = cfg.get("binary")
        script = cfg.get("script")

        if script and os.path.isfile(str(script)):
            self._script = str(script)
            return True

        repo_root = Path(__file__).resolve().parent.parent
        vendored = repo_root / "tools" / "vendor" / "tplmap" / "tplmap.py"
        if vendored.is_file():
            self._script = str(vendored)
            return True

        return bool((binary and os.path.isfile(str(binary))) or shutil.which("tplmap"))

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("tplmap", {}) or {}
        binary = cfg.get("binary") or "tplmap"
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")
        script = kwargs.get("script") or cfg.get("script") or self._script

        if args:
            args = str(args).replace("{target}", target)
            if script:
                return [sys.executable, script] + args.split()
            return [binary] + args.split()

        raise ValueError("tplmap requires args in config (e.g., -u https://target/?q=FUZZ)")

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
