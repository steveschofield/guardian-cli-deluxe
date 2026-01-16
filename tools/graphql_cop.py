"""
graphql-cop tool wrapper for GraphQL testing
"""

import os
import shutil
import sys
from typing import Dict, Any, List
from pathlib import Path

from tools.base_tool import BaseTool


class GraphqlCopTool(BaseTool):
    """graphql-cop wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "graphql-cop"
        self._script = None

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("graphql_cop", {}) or {}
        binary = cfg.get("binary")
        script = cfg.get("script")

        if script and os.path.isfile(str(script)):
            self._script = str(script)
            return True

        repo_root = Path(__file__).resolve().parent.parent
        vendored = repo_root / "tools" / "vendor" / "graphql-cop" / "graphql-cop.py"
        if vendored.is_file():
            self._script = str(vendored)
            return True

        if binary and os.path.isfile(str(binary)):
            return True

        if shutil.which("graphql-cop"):
            return True

        return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("graphql_cop", {}) or {}
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")

        if args:
            args = str(args).replace("{target}", target)
            if self._script:
                return [sys.executable, self._script] + args.split()
            binary = cfg.get("binary") or "graphql-cop"
            return [binary] + args.split()

        raise ValueError("graphql-cop requires args in config (e.g., -t https://host/graphql)")

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
