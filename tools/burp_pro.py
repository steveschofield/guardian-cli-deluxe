"""
Burp Suite Professional tool wrapper (macOS only)
"""

import json
import platform
import subprocess
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class BurpProTool(BaseTool):
    """Burp Suite Professional scanner wrapper"""
    
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "burp_pro"
    
    def _check_installation(self) -> bool:
        """Check if Burp Pro is available (macOS only)"""
        if platform.system().lower() != "darwin":
            return False
        
        # Check if Java is available
        try:
            subprocess.run(["java", "-version"], capture_output=True, check=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            self.logger.warning("Java not found - required for Burp Pro")
            return False
        
        # Check for Burp Pro jar file in common locations
        import os
        burp_paths = [
            "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar",
            "/Applications/Burp Suite Professional.app/Contents/java/app/burpsuite_pro.jar",
            "/opt/burp/burpsuite_pro.jar",
            "~/Applications/burpsuite_pro.jar"
        ]
        
        for path in burp_paths:
            if os.path.exists(os.path.expanduser(path)):
                return True
        
        return False
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build Burp Pro headless scanner command"""
        # Default Burp Pro location on macOS
        burp_jar = kwargs.get("burp_jar", "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar")
        
        command = [
            "java", "-jar", burp_jar,
            "--headless",
            "--target", target,
            "--scan-type", kwargs.get("scan_type", "crawl-and-audit"),
            "--output-format", "json"
        ]
        
        # Add scan scope
        if kwargs.get("scope"):
            command.extend(["--scope", kwargs["scope"]])
        
        # Add authentication
        if kwargs.get("auth_username") and kwargs.get("auth_password"):
            command.extend([
                "--auth-username", kwargs["auth_username"],
                "--auth-password", kwargs["auth_password"]
            ])
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse Burp Pro JSON output"""
        try:
            data = json.loads(output)
            
            vulnerabilities = []
            for issue in data.get("issues", []):
                vuln = {
                    "name": issue.get("name", "Unknown"),
                    "severity": self._map_severity(issue.get("severity", "Information")),
                    "confidence": issue.get("confidence", "Tentative"),
                    "url": issue.get("url", ""),
                    "parameter": issue.get("parameter", ""),
                    "description": issue.get("description", ""),
                    "remediation": issue.get("remediation", ""),
                    "evidence": issue.get("evidence", ""),
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
    
    def _map_severity(self, burp_severity: str) -> str:
        """Map Burp severity to standard levels"""
        mapping = {
            "High": "high",
            "Medium": "medium", 
            "Low": "low",
            "Information": "info"
        }
        return mapping.get(burp_severity, "info")
    
    def _count_by_severity(self, vulns: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulns:
            severity = vuln.get("severity", "info")
            if severity in counts:
                counts[severity] += 1
        return counts