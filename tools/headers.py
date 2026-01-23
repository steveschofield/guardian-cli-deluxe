"""
HTTP security headers check (curl-based).
"""

from __future__ import annotations

import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class HeadersTool(BaseTool):
    """HTTP security headers checker."""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "headers"

    def _check_installation(self) -> bool:
        return shutil.which("curl") is not None

    def is_success_exit_code(self, exit_code: int) -> bool:
        """
        curl exit codes:
        0 = Success
        60 = SSL certificate verification failure (handle gracefully)
        """
        return exit_code in (0, 60)

    def get_command(self, target: str, **kwargs) -> List[str]:
        timeout = int(kwargs.get("timeout", 10))
        follow = bool(kwargs.get("follow_redirects", True))
        user_agent = kwargs.get("user_agent", "Guardian-Header-Check/1.0")
        # Default to insecure mode for pentest tools to avoid SSL cert failures
        insecure = bool(kwargs.get("insecure", True))

        command = [
            "curl",
            "-sS",
            "-D",
            "-",
            "-o",
            "/dev/null",
            "--max-time",
            str(timeout),
            "--connect-timeout",
            str(min(5, timeout)),
            "-A",
            user_agent,
        ]
        if follow:
            command.append("-L")
        if insecure:
            command.append("-k")
        command.append(target)
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        blocks = []
        if output:
            normalized = output.replace("\r\n", "\n")
            blocks = [b.strip() for b in normalized.split("\n\n") if b.strip()]

        last_block = blocks[-1] if blocks else ""
        status_line = ""
        headers: Dict[str, str] = {}
        raw_lines: List[str] = []

        for i, line in enumerate(last_block.splitlines()):
            raw_lines.append(line)
            if i == 0 and line.upper().startswith("HTTP/"):
                status_line = line.strip()
                continue
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "cross-origin-embedder-policy",
            "cross-origin-resource-policy",
        ]
        deprecated_headers = ["x-xss-protection"]

        present = [h for h in security_headers if h in headers]
        missing = [h for h in security_headers if h not in headers]
        deprecated_present = [h for h in deprecated_headers if h in headers]

        return {
            "status_line": status_line,
            "headers": headers,
            "security_headers_present": present,
            "security_headers_missing": missing,
            "deprecated_headers_present": deprecated_present,
            "raw_headers": raw_lines,
        }
