"""
wappalyzer tool wrapper for web technology detection
"""

import json
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class WappalyzerTool(BaseTool):
    """wappalyzer CLI wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "wappalyzer"

    def _check_installation(self) -> bool:
        return shutil.which("wappalyzer") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("wappalyzer", {}) or {}
        args = kwargs.get("args") or cfg.get("args") or ""
        command = ["wappalyzer"]
        if args:
            command.extend(str(args).split())
        command.append(target)
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {"technologies": [], "raw": output}
        text = (output or "").strip()
        if not text:
            return results
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                tech = data.get("technologies") or data.get("apps") or []
                if isinstance(tech, list):
                    results["technologies"] = [t.get("name") for t in tech if isinstance(t, dict) and t.get("name")]
        except Exception:
            pass
        return results
