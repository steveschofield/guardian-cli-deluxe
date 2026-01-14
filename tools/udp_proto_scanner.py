"""
udp-proto-scanner wrapper for fast UDP service probing
"""

import re
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class UdpProtoScannerTool(BaseTool):
    """udp-proto-scanner wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "udp-proto-scanner"

    def _check_installation(self) -> bool:
        return shutil.which("udp-proto-scanner.pl") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["udp-proto-scanner.pl"]
        if kwargs.get("from_file"):
            command.extend(["-iL", kwargs["from_file"]])
        else:
            command.append(target)
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        results = {"open_ports": []}
        for line in (output or "").splitlines():
            # Example formats vary; try to capture "IP:port" or "port <n> on <ip>"
            ip_port = re.search(r"(\\d+\\.\\d+\\.\\d+\\.\\d+)[:\\s]+(\\d{1,5})", line)
            if ip_port:
                ip = ip_port.group(1)
                port = int(ip_port.group(2))
                results["open_ports"].append({"host": ip, "port": port, "protocol": "udp"})
                continue
            alt = re.search(r"port\\s+(\\d{1,5}).*?on\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)", line, re.IGNORECASE)
            if alt:
                port = int(alt.group(1))
                ip = alt.group(2)
                results["open_ports"].append({"host": ip, "port": port, "protocol": "udp"})
        return results
