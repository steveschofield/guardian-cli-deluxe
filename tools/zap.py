"""
OWASP ZAP tool wrapper (headless) for Guardian.

Default execution uses the official Docker image (`ghcr.io/zaproxy/zaproxy:stable`) and runs:
- zap-baseline.py (passive scan, safer)

Active scans are intentionally gated behind safe_mode=false and an explicit config choice.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.base_tool import BaseTool


class ZapTool(BaseTool):
    """OWASP ZAP wrapper (Docker-first)."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.tool_name = "zap"

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("zap", {}) or {}
        mode = (cfg.get("mode") or "docker").lower()

        if mode == "docker":
            return shutil.which("docker") is not None

        if mode in {"daemon", "remote"}:
            # Daemon mode uses the ZAP API (local or remote) via our helper script.
            return True

        # "local" mode expects a zap script in PATH (user-managed)
        # Common entrypoints are "zap.sh" (Linux) or "zap.bat" (Windows).
        zap_bin = cfg.get("binary") or os.environ.get("GUARDIAN_ZAP_BIN")
        if zap_bin:
            return os.path.isfile(str(zap_bin)) and os.access(str(zap_bin), os.X_OK)

        return (shutil.which("zap.sh") is not None) or (shutil.which("zap-baseline.py") is not None)

    def _reports_dir(self) -> Path:
        base = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        base.mkdir(parents=True, exist_ok=True)
        return base

    def _build_daemon_command(self, target: str, scan: str, timeout_min: int) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("zap", {}) or {}
        api_url = (cfg.get("api_url") or cfg.get("daemon_url") or os.environ.get("GUARDIAN_ZAP_API_URL") or "").strip()
        if not api_url:
            api_url = "http://127.0.0.1:8080"
        api_key = (cfg.get("api_key") or os.environ.get("GUARDIAN_ZAP_API_KEY") or "").strip()
        export_har = bool(cfg.get("export_har", False))

        # baseline: spider + passive; full: spider + active + passive
        spider = bool(cfg.get("spider", True))

        safe_mode = (self.config or {}).get("pentest", {}).get("safe_mode", True)
        active = (scan == "full") and (not safe_mode)

        out_dir = self._reports_dir() / "zap"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        har_name = f"zap_{scan}_{ts}.har"

        script = Path(__file__).resolve().parent.parent / "scripts" / "zap_daemon_scan.py"
        args = [
            "python3",
            str(script),
            "--api-url",
            api_url,
            "--target",
            target,
            "--max-minutes",
            str(int(timeout_min)),
        ]
        if api_key:
            args.extend(["--api-key", api_key])
        if spider:
            args.append("--spider")
        if active:
            args.append("--active")
        if export_har:
            args.extend(["--har-out", str(out_dir / har_name)])
        return args

    def _build_docker_command(self, target: str, scan: str, timeout_min: int) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("zap", {}) or {}
        image = cfg.get("docker_image") or "ghcr.io/zaproxy/zaproxy:stable"

        out_dir = self._reports_dir() / "zap"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            out_dir.chmod(0o777)
        except Exception:
            pass
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_name = f"zap_{scan}_{ts}.json"
        html_name = f"zap_{scan}_{ts}.html"
        md_name = f"zap_{scan}_{ts}.md"

        # Host path mount for reports.
        host_out = str(out_dir.resolve())

        # ZAP scripts live inside the container image.
        if scan == "full":
            script = "/zap/zap-full-scan.py"
            # -a is "active scan"; full scan is inherently active.
            scan_flags = "-a"
        else:
            script = "/zap/zap-baseline.py"
            scan_flags = ""

        # Use bash so we can always emit the JSON report content to stdout for parsing.
        # Keep it simple and rely on file artifacts for humans.
        container_cmd = (
            "set -euo pipefail; "
            f"{script} -t {shlex.quote(target)} "
            f"-J /zap/wrk/{shlex.quote(json_name)} "
            f"-r /zap/wrk/{shlex.quote(html_name)} "
            f"-w /zap/wrk/{shlex.quote(md_name)} "
            f"-m {int(timeout_min)} "
            f"{scan_flags} "
            "|| true; "
            f"cat /zap/wrk/{shlex.quote(json_name)} 2>/dev/null || true"
        )

        return [
            "bash",
            "-lc",
            " ".join(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull=missing",
                    "-v",
                    f"{shlex.quote(host_out)}:/zap/wrk",
                    image,
                    "bash",
                    "-lc",
                    shlex.quote(container_cmd),
                ]
            ),
        ]

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("zap", {}) or {}

        scan = (cfg.get("scan") or "baseline").lower()
        if scan not in {"baseline", "full"}:
            scan = "baseline"

        # Gate active scans behind safe_mode=false.
        safe_mode = (self.config or {}).get("pentest", {}).get("safe_mode", True)
        if safe_mode and scan == "full":
            scan = "baseline"

        # Default time budget (minutes) for the ZAP scripts.
        timeout_min = int(cfg.get("max_minutes", 10))

        mode = (cfg.get("mode") or "docker").lower()
        if mode == "docker":
            return self._build_docker_command(target=target, scan=scan, timeout_min=timeout_min)

        if mode in {"daemon", "remote"}:
            return self._build_daemon_command(target=target, scan=scan, timeout_min=timeout_min)

        # Local mode not fully standardized across OSes; keep a minimal hook.
        # Expect user to supply a command like "zap-baseline.py" in PATH.
        local_cmd = cfg.get("local_command")
        if not local_cmd:
            raise RuntimeError(
                "ZAP local mode requires tools.zap.local_command (e.g., 'zap-baseline.py'). "
                "Prefer tools.zap.mode=docker."
            )
        return [local_cmd, "-t", target]

    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse ZAP JSON report (when available). If not JSON, return raw text summary.
        """
        output = (output or "").strip()

        # Try to parse JSON (zap-baseline.py -J output).
        try:
            data = json.loads(output) if output else {}
        except Exception:
            return {"alerts": [], "count": 0, "raw": output[:2000]}

        # ZAP report JSON can be either:
        # - baseline/full scan report format: {"site": [{"alerts":[...]}]}
        # - daemon helper format: {"alerts":[...], "count": n, ...}
        alerts: list[dict[str, Any]] = []
        if isinstance(data.get("alerts"), list):
            for alert in (data.get("alerts") or []):
                alerts.append(
                    {
                        "name": alert.get("name") or alert.get("alert"),
                        "risk": alert.get("risk") or alert.get("riskdesc"),
                        "confidence": alert.get("confidence"),
                        "desc": alert.get("desc") or alert.get("description"),
                        "solution": alert.get("solution"),
                        "reference": alert.get("reference"),
                        "instances": alert.get("instances") or [],
                        "url": alert.get("url"),
                        "param": alert.get("param"),
                        "attack": alert.get("attack"),
                        "evidence": alert.get("evidence"),
                    }
                )
        else:
            for site in (data.get("site") or []):
                for alert in (site.get("alerts") or []):
                    alerts.append(
                        {
                            "name": alert.get("name"),
                            "risk": alert.get("risk"),
                            "confidence": alert.get("confidence"),
                            "desc": alert.get("desc"),
                            "solution": alert.get("solution"),
                            "reference": alert.get("reference"),
                            "instances": alert.get("instances") or [],
                        }
                    )

        return {
            "alerts": alerts,
            "count": len(alerts),
            "summary": {
                "sites": len(data.get("site") or []),
            },
        }
