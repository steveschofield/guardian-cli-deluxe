"""
Schemathesis wrapper for API schema fuzzing
"""

import re
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class SchemathesisTool(BaseTool):
    """schemathesis wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("schemathesis", {}) or {}
        schema = kwargs.get("schema") or kwargs.get("openapi")
        base_url = kwargs.get("base_url") or kwargs.get("url") or target

        if not schema:
            raise ValueError("Schemathesis requires a schema/openapi URL; none provided")

        command = ["schemathesis", "run", schema, "--url", base_url]

        tls_verify = kwargs.get("tls_verify") if "tls_verify" in kwargs else cfg.get("tls_verify")
        if tls_verify is False or str(tls_verify).lower() in {"false", "0", "no"}:
            command.append("--tls-verify=false")

        if kwargs.get("workers"):
            command.extend(["--workers", str(kwargs["workers"])])
        if kwargs.get("checks"):
            command.extend(["--checks", kwargs["checks"]])
        if kwargs.get("max_examples"):
            command.extend(["--max-examples", str(kwargs["max_examples"])])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        summary = {"passed": 0, "failed": 0, "errors": 0, "raw_output": output}

        passed = re.search(r"(?i)passed[:\s]+(\d+)", output)
        failed = re.search(r"(?i)failed[:\s]+(\d+)", output)
        errored = re.search(r"(?i)errored[:\s]+(\d+)", output)

        if passed:
            summary["passed"] = int(passed.group(1))
        if failed:
            summary["failed"] = int(failed.group(1))
        if errored:
            summary["errors"] = int(errored.group(1))

        return summary
