"""
dnsx tool wrapper for DNS resolution/enumeration
"""

from typing import Dict, Any, List

from tools.base_tool import BaseTool


class DnsxTool(BaseTool):
    """dnsx wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        # dnsx expects domains from stdin or -d
        command = ["dnsx", "-d", target]

        # threads if provided
        threads = kwargs.get("threads")
        if threads:
            command.extend(["-t", str(threads)])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        # Each line is a resolved domain/IP
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return {"resolved": lines}
