"""
katana tool wrapper for web crawling
"""

import os
import shutil
import subprocess
from pathlib import Path
import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class KatanaTool(BaseTool):
    """katana crawler wrapper"""

    def __init__(self, config):
        self._executable: str | None = None
        super().__init__(config)
        self.tool_name = "katana"

    def _repo_bin_candidates(self) -> List[str]:
        repo_root = Path(__file__).resolve().parent.parent
        return [
            str(repo_root / "tools" / ".bin" / "katana"),
            str(repo_root / "tools" / ".bin" / "katana_pd"),
            str(repo_root / "tools" / ".bin" / "katana-projectdiscovery"),
        ]

    def _is_projectdiscovery_katana(self, executable: str) -> bool:
        # Katana prints "projectdiscovery.io" in help/version output.
        for args in ([executable, "-version"], [executable, "-h"]):
            try:
                proc = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
            except Exception:
                continue
            out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).lower()
            if "katana" in out and ("projectdiscovery" in out or "projectdiscovery.io" in out or "-jsonl" in out):
                return True
        return False

    def _find_projectdiscovery_katana(self) -> str | None:
        cfg = (self.config or {}).get("tools", {}).get("katana", {})
        override = cfg.get("binary") or os.environ.get("GUARDIAN_KATANA_BIN")

        candidates: List[str] = []
        if override:
            candidates.append(str(override))

        candidates.extend(self._repo_bin_candidates())

        found = shutil.which("katana")
        if found:
            candidates.append(found)

        try:
            which_all = subprocess.run(
                ["which", "-a", "katana"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if which_all.returncode == 0:
                for line in which_all.stdout.splitlines():
                    line = line.strip()
                    if line:
                        candidates.append(line)
        except Exception:
            pass

        seen = set()
        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK) and self._is_projectdiscovery_katana(candidate):
                return candidate

        return None

    def _check_installation(self) -> bool:
        self.tool_name = "katana"
        self._executable = self._find_projectdiscovery_katana()
        if not self._executable:
            return False
        return True

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build katana command"""
        if not self._executable:
            raise RuntimeError("ProjectDiscovery katana executable not resolved")
        config = self.config.get("tools", {}).get("katana", {})

        command = [self._executable, "-silent", "-jsonl"]

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
