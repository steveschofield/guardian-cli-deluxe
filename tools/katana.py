"""
katana tool wrapper for web crawling
"""

import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class KatanaTool(BaseTool):
    """katana crawler wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "katana"

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build katana command"""
        config = self.config.get("tools", {}).get("katana", {})

        command = ["katana", "-silent", "-json"]

        # Crawl depth
        depth = config.get("depth")
        if depth:
            command.extend(["-d", str(depth)])

        # Concurrency
        concurrency = config.get("concurrency")
        if concurrency:
            command.extend(["-c", str(concurrency)])

        # Input target(s)
        if kwargs.get("from_file"):
            command.extend(["-list", kwargs["from_file"]])
        else:
            command.extend(["-u", target])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse katana JSONL output"""
        results = {
            "urls": []
        }

        for line in output.strip().splitlines():
            if not line:
                continue

            try:
                data = json.loads(line)
                url = data.get("url") or data.get("request") or data.get("path")
            except json.JSONDecodeError:
                url = line.strip()

            if url and url not in results["urls"]:
                results["urls"].append(url)

        return results
