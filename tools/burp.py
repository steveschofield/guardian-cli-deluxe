"""
Burp Suite Professional tool wrapper
Automated web application security testing
"""

import asyncio
import subprocess
import json
from typing import Dict, Any, List
from datetime import datetime
from tools.base_tool import BaseTool


class BurpTool(BaseTool):
    """Burp Suite Professional wrapper for automated scanning"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "burp"
    
    def _check_installation(self) -> bool:
        """Check if Burp Suite Professional is available"""
        # Check for burp_suite command or java -jar burpsuite_pro.jar
        return (
            subprocess.run(["which", "burp_suite"], capture_output=True).returncode == 0 or
            subprocess.run(["java", "-version"], capture_output=True).returncode == 0
        )
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build Burp Suite command"""
        burp_jar = kwargs.get("burp_jar", "/opt/burpsuite_pro/burpsuite_pro.jar")
        
        command = [
            "java", "-jar", burp_jar,
            "--headless",
            "--target", target,
            "--scan-type", kwargs.get("scan_type", "crawl-and-audit"),
            "--output-format", "json"
        ]
        
        # Add authentication if provided
        if kwargs.get("auth_username") and kwargs.get("auth_password"):
            command.extend([
                "--auth-username", kwargs["auth_username"],
                "--auth-password", kwargs["auth_password"]
            ])
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse Burp Suite JSON output"""
        try:
            data = json.loads(output)
            
            vulnerabilities = []
            for issue in data.get("issues", []):
                vuln = {
                    "name": issue.get("name", "Unknown"),
                    "severity": issue.get("severity", "info").lower(),
                    "confidence": issue.get("confidence", "tentative"),
                    "url": issue.get("url", ""),
                    "description": issue.get("description", ""),
                    "remediation": issue.get("remediation", ""),
                    "references": issue.get("references", [])
                }
                vulnerabilities.append(vuln)
            
            return {
                "vulnerabilities": vulnerabilities,
                "count": len(vulnerabilities),
                "by_severity": self._count_by_severity(vulnerabilities)
            }
        except json.JSONDecodeError:
            return {"vulnerabilities": [], "count": 0, "by_severity": {}}
    
    def _count_by_severity(self, vulns: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulns:
            severity = vuln.get("severity", "info")
            if severity in counts:
                counts[severity] += 1
        return counts