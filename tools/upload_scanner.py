"""
upload-scanner tool wrapper for file upload testing
"""

import os
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class UploadScannerTool(BaseTool):
    """upload-scanner wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "upload-scanner"

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("upload_scanner", {}) or {}
        binary = cfg.get("binary")
        return bool((binary and os.path.isfile(str(binary))) or shutil.which("upload-scanner"))

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("upload_scanner", {}) or {}
        binary = cfg.get("binary") or "upload-scanner"
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")

        if args:
            args = str(args).replace("{target}", target)
            return [binary] + args.split()

        raise ValueError("upload-scanner requires args in config")

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
