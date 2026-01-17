"""
upload-scanner tool wrapper for file upload testing
"""

import os
import shutil
import sys
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class UploadScannerTool(BaseTool):
    """upload-scanner wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "upload-scanner"
        self._script_path = None

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("upload_scanner", {}) or {}
        binary = cfg.get("binary")
        script = cfg.get("script")
        if script and os.path.isfile(str(script)):
            self._script_path = str(script)
            return True
        if binary and os.path.isfile(str(binary)):
            return True
        local_script = self._local_script()
        if local_script:
            self._script_path = local_script
            return True
        return bool(shutil.which("upload-scanner"))

    def _local_script(self) -> str | None:
        here = os.path.abspath(os.path.dirname(__file__))
        repo_root = os.path.abspath(os.path.join(here, os.pardir))
        candidate = os.path.join(repo_root, "tools", "vendor", "guardian_tools", "upload_scanner.py")
        return candidate if os.path.isfile(candidate) else None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("upload_scanner", {}) or {}
        binary = cfg.get("binary") or "upload-scanner"
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")
        script = kwargs.get("script") or cfg.get("script") or self._script_path

        if args:
            args = str(args).replace("{target}", target)
            if script:
                script = os.path.expandvars(os.path.expanduser(str(script)))
                return [sys.executable, script] + args.split()
            return [binary] + args.split()

        raise ValueError("upload-scanner requires args in config")

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
