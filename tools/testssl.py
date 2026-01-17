"""
TestSSL tool wrapper for SSL/TLS testing
"""

import asyncio
import shutil
import re
import tempfile
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse
from pathlib import Path

from tools.base_tool import BaseTool


class TestSSLTool(BaseTool):
    """TestSSL.sh SSL/TLS testing wrapper"""
    
    def __init__(self, config):
        super().__init__(config)

    def _vendor_executable_path(self) -> Path:
        return Path(__file__).resolve().parent / "vendor" / "testssl.sh" / "testssl.sh"

    def _resolve_executable(self) -> str | None:
        # Prefer PATH, fall back to vendored copy if present.
        return (
            shutil.which("testssl.sh")
            or shutil.which("testssl")
            or (str(self._vendor_executable_path()) if self._vendor_executable_path().exists() else None)
        )

    def _check_installation(self) -> bool:
        return self._resolve_executable() is not None

    def _normalize_target(self, target: str) -> str:
        # testssl.sh expects host[:port] (URLs with scheme can confuse it).
        if "://" in target:
            parsed = urlparse(target)
            return parsed.netloc or target
        return target

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build testssl command"""
        executable = self._resolve_executable()
        if not executable:
            raise RuntimeError("testssl executable not found (expected testssl/testssl.sh or vendored copy)")

        command = [executable]

        cfg = (self.config or {}).get("tools", {}).get("testssl", {}) or {}
        
        # Machine-readable output
        jsonfile_path = kwargs.get("jsonfile_path")
        if not jsonfile_path:
            raise ValueError("TestSSLTool requires jsonfile_path")
        command.append(f"--jsonfile={jsonfile_path}")
        
        # Severity level
        severity = kwargs.get("severity", "HIGH")
        command.extend(["--severity", severity])
        
        # Fast mode
        if kwargs.get("fast", False):
            command.append("--fast")

        # Quiet mode
        command.append("--quiet")

        ip_mode = kwargs.get("ip") if "ip" in kwargs else cfg.get("ip")
        if ip_mode:
            command.extend(["--ip", str(ip_mode)])

        nodns = kwargs.get("nodns") if "nodns" in kwargs else cfg.get("nodns")
        if nodns:
            command.extend(["--nodns", str(nodns)])
        
        # Target (host:port or URL)
        command.append(self._normalize_target(target))
        
        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute testssl.sh and parse JSON output from its jsonfile.

        testssl.sh treats `--jsonfile=-` as a literal filename and refuses to overwrite it;
        always use a temp file and read it back.
        """
        if not self.is_available:
            raise RuntimeError("Tool testssl is not available")

        timeout = self.config.get("pentest", {}).get("tool_timeout", 300)
        started = datetime.now()

        with tempfile.TemporaryDirectory(prefix="guardian-testssl-") as tmpdir:
            json_path = Path(tmpdir) / "testssl.json"
            command = self.get_command(target, jsonfile_path=str(json_path), **kwargs)

            self.logger.info(f"Executing: {' '.join(command)}")

            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                try:
                    process.kill()
                    await process.communicate()
                except Exception:
                    pass
                duration = (datetime.now() - started).total_seconds()
                self.logger.error(f"Tool {self.tool_name} timed out after {timeout}s (elapsed {duration:.2f}s)")
                raise

            duration = (datetime.now() - started).total_seconds()
            out_text = (stdout or b"").decode("utf-8", errors="replace")
            err_text = (stderr or b"").decode("utf-8", errors="replace")

            file_text = ""
            try:
                if json_path.exists():
                    file_text = json_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                file_text = ""

            raw = (file_text.strip() or out_text).strip()
            if err_text and (not raw or process.returncode != 0):
                raw = (raw + "\n" + err_text).strip()

            parsed = self.parse_output(file_text.strip() or out_text)

            self.logger.info(
                f"Tool {self.tool_name} completed in {duration:.2f}s (exit {process.returncode})"
            )

            return {
                "tool": self.tool_name,
                "target": target,
                "command": " ".join(command),
                "timestamp": started.isoformat(),
                "exit_code": process.returncode,
                "duration": duration,
                "raw_output": raw,
                "error": err_text if err_text else None,
                "parsed": parsed,
            }
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse testssl JSON output"""
        results = {
            "ssl_enabled": False,
            "tls_versions": [],
            "cipher_suites": [],
            "vulnerabilities": [],
            "certificate_info": {},
            "grade": None,
            "issues_count": 0
        }
        
        try:
            import json

            text = (output or "").strip()
            if not text:
                return results

            items: list[dict] = []
            if text.startswith("[") or text.startswith("{"):
                try:
                    loaded = json.loads(text)
                    if isinstance(loaded, dict):
                        items = [loaded]
                    elif isinstance(loaded, list):
                        items = [i for i in loaded if isinstance(i, dict)]
                except json.JSONDecodeError:
                    items = []

            # Fallback: JSON lines (some builds emit one object per line)
            if not items:
                for line in text.splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict):
                            items.append(data)
                    except json.JSONDecodeError:
                        continue

            for data in items:
                # Extract certificate info
                if data.get("id") == "cert_commonName":
                    results["certificate_info"]["common_name"] = data.get("finding")

                elif data.get("id") == "cert_notAfter":
                    results["certificate_info"]["expiry"] = data.get("finding")

                # Extract protocols
                elif "SSLv" in data.get("id", "") or "TLS" in data.get("id", ""):
                    if str(data.get("finding", "")).lower() == "offered":
                        protocol = str(data.get("id", "")).replace("_", " ")
                        results["tls_versions"].append(protocol)

                # Extract vulnerabilities
                elif data.get("severity") in ["HIGH", "CRITICAL", "MEDIUM"]:
                    vuln = {
                        "name": data.get("id"),
                        "severity": str(data.get("severity", "")).lower(),
                        "finding": data.get("finding"),
                        "cve": data.get("cve", "")
                    }
                    results["vulnerabilities"].append(vuln)
                    results["issues_count"] += 1
            
            results["ssl_enabled"] = len(results["tls_versions"]) > 0
            
        except Exception as e:
            # Fallback to text parsing if JSON fails
            if "ssl" in output.lower() or "tls" in output.lower():
                results["ssl_enabled"] = True
        
        return results
