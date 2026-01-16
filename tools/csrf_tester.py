"""
csrf tester tool wrapper
"""

import os
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class CsrfTesterTool(BaseTool):
    """CSRF tester wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "csrf-tester"
        self._binary = None

    def _resolve_binary(self) -> str | None:
        cfg = (self.config or {}).get("tools", {}).get("csrf_tester", {}) or {}
        binary = cfg.get("binary")
        if binary and os.path.isfile(str(binary)):
            return str(binary)
        for name in ("csrf-tester", "csrftester"):
            found = shutil.which(name)
            if found:
                return found
        return None

    def _check_installation(self) -> bool:
        self._binary = self._resolve_binary()
        return self._binary is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("csrf_tester", {}) or {}
        binary = self._binary or cfg.get("binary") or "csrf-tester"
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")

        if args:
            args = str(args).replace("{target}", target)
            return [binary] + args.split()

        raise ValueError("csrf tester requires args in config")

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
