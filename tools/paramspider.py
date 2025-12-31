"""
ParamSpider wrapper for parameter discovery
"""

import re
from urllib.parse import urlparse
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class ParamspiderTool(BaseTool):
    """paramspider wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        parsed = urlparse(target)
        domain = parsed.netloc or target

        command = ["paramspider", "-d", domain]

        if kwargs.get("exclude"):
            command.extend(["-e", kwargs["exclude"]])
        if kwargs.get("threads"):
            command.extend(["-t", str(kwargs["threads"])])
        if kwargs.get("level"):
            command.extend(["-l", str(kwargs["level"])])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        params = []
        for line in output.splitlines():
            for match in re.findall(r"https?://[^\s\"'<>]+", line):
                params.append(match)
        return {"urls": params}
