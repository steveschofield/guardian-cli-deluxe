"""
TestSSL tool wrapper for SSL/TLS testing
"""

import shutil
import re
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
        
        # Machine-readable output
        command.append("--jsonfile=-")
        
        # Severity level
        severity = kwargs.get("severity", "HIGH")
        command.extend(["--severity", severity])
        
        # Fast mode
        if kwargs.get("fast", False):
            command.append("--fast")
        
        # Quiet mode
        command.append("--quiet")
        
        # Target (host:port or URL)
        command.append(self._normalize_target(target))
        
        return command
    
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
            
            # TestSSL outputs JSON lines
            for line in output.strip().split('\n'):
                if not line or not line.startswith('{'):
                    continue
                
                try:
                    data = json.loads(line)
                    
                    # Extract certificate info
                    if data.get("id") == "cert_commonName":
                        results["certificate_info"]["common_name"] = data.get("finding")
                    
                    elif data.get("id") == "cert_notAfter":
                        results["certificate_info"]["expiry"] = data.get("finding")
                    
                    # Extract protocols
                    elif "SSLv" in data.get("id", "") or "TLS" in data.get("id", ""):
                        if data.get("finding") == "offered":
                            protocol = data.get("id").replace("_", " ")
                            results["tls_versions"].append(protocol)
                    
                    # Extract vulnerabilities
                    elif data.get("severity") in ["HIGH", "CRITICAL", "MEDIUM"]:
                        vuln = {
                            "name": data.get("id"),
                            "severity": data.get("severity").lower(),
                            "finding": data.get("finding"),
                            "cve": data.get("cve", "")
                        }
                        results["vulnerabilities"].append(vuln)
                        results["issues_count"] += 1
                    
                except json.JSONDecodeError:
                    continue
            
            results["ssl_enabled"] = len(results["tls_versions"]) > 0
            
        except Exception as e:
            # Fallback to text parsing if JSON fails
            if "ssl" in output.lower() or "tls" in output.lower():
                results["ssl_enabled"] = True
        
        return results
