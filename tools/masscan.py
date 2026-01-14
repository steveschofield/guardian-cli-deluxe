"""
masscan tool wrapper for fast port discovery
"""

import json
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class MasscanTool(BaseTool):
    """masscan port scanner wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "masscan"

    def _check_installation(self) -> bool:
        return shutil.which("masscan") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build masscan command"""
        config = self.config.get("tools", {}).get("masscan", {})

        ports = kwargs.get("ports") or config.get("ports") or "80,443"
        rate = kwargs.get("rate") or config.get("rate") or 10000

        command = ["masscan", "-p", str(ports), "--rate", str(rate), "-oJ", "-"]

        if kwargs.get("exclude"):
            command.extend(["--exclude", str(kwargs["exclude"])])

        # Input target(s)
        if kwargs.get("from_file"):
            command.extend(["-iL", kwargs["from_file"]])
        else:
            command.append(target)

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse masscan JSON output"""
        results = {"hosts": {}, "open_ports": []}
        text = (output or "").strip()
        if not text:
            return results

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = []
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if not line or not line.startswith("{"):
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if isinstance(data, dict):
            data = [data]

        for entry in data:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip")
            ports = entry.get("ports") or []
            if not ip or not isinstance(ports, list):
                continue
            for p in ports:
                port = p.get("port") if isinstance(p, dict) else None
                proto = p.get("proto") if isinstance(p, dict) else None
                if port is None:
                    continue
                results["open_ports"].append({"host": ip, "port": port, "protocol": proto})
                host_ports = results["hosts"].setdefault(ip, [])
                host_ports.append(port)

        return results
