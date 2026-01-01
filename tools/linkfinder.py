"""
LinkFinder wrapper for extracting endpoints from JS
"""

import re
from typing import Dict, Any, List
from importlib.util import find_spec
from tools.base_tool import BaseTool
from utils.logger import get_logger


class LinkfinderTool(BaseTool):
    """linkfinder wrapper"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger(config)
        self.tool_name = "linkfinder"
        self.is_available = find_spec("linkfinder") is not None
        if not self.is_available:
            self.logger.warning("Tool linkfinder is not installed or importable")

    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["python", "-m", "linkfinder", "-i", target, "-o", "cli"]
        if kwargs.get("custom_regex"):
            command.extend(["-r", kwargs["custom_regex"]])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = []
        for line in output.splitlines():
            for match in re.findall(r"https?://[^\s\"'<>]+", line):
                urls.append(match)
        return {"urls": urls}
