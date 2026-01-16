"""
Nmap tool wrapper for port scanning and service detection
"""

import re
import json
from typing import Dict, Any, List
from urllib.parse import urlparse

from tools.base_tool import BaseTool


class NmapTool(BaseTool):
    """Nmap port scanner wrapper"""
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build nmap command"""
        config = self.config.get("tools", {}).get("nmap", {})

        # Normalize target: strip scheme, capture port if present
        parsed = urlparse(target)
        target_host = target
        target_port = None
        if parsed.scheme and parsed.hostname:
            target_host = parsed.hostname
            target_port = parsed.port
        elif parsed.scheme and not parsed.hostname:
            raise ValueError(f"Invalid target for nmap: {target}")
        
        # Base command
        command = ["nmap"]
        
        # Arguments profile (recon vs vuln scripts)
        profile = (kwargs.get("profile") or "recon").strip().lower()
        recon_args = config.get("default_args", "-sV -sC")
        vuln_args = config.get("vuln_args", "-sV --script vuln")
        args = vuln_args if profile in {"vuln", "vulnerability"} else recon_args
        override_args = kwargs.get("args") or kwargs.get("override_args")
        if override_args:
            args = override_args
        if args:
            command.extend(str(args).split())
        
        # Timing template
        timing = kwargs.get("timing") or config.get("timing", "T4")
        command.append(f"-{timing}")
        
        # XML output for parsing
        command.extend(["-oX", "-"])
        
        # Custom args from kwargs
        if "ports" in kwargs and kwargs["ports"]:
            command.extend(["-p", kwargs["ports"]])
        elif target_port:
            command.extend(["-p", str(target_port)])

        if "scan_type" in kwargs:
            command.append(kwargs["scan_type"])

        extra_args = kwargs.get("extra_args")
        if extra_args:
            if isinstance(extra_args, list):
                command.extend([str(a) for a in extra_args if str(a).strip()])
            else:
                command.extend(str(extra_args).split())
        
        # Target
        command.append(target_host)
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap XML output"""
        results = {
            "open_ports": [],
            "services": [],
            "os_detection": None,
            "vulnerabilities": [],
            "hosts_up": []
        }
        
        # Simple regex parsing (in production, use proper XML parser)
        # Extract open ports
        port_pattern = r'portid="(\d+)".*?service name="([^"]*)".*?product="([^"]*)"'
        for match in re.finditer(port_pattern, output, re.DOTALL):
            port = match.group(1)
            service = match.group(2)
            product = match.group(3) if match.group(3) else "unknown"
            
            results["open_ports"].append(int(port))
            results["services"].append({
                "port": int(port),
                "service": service,
                "product": product
            })
        
        # Extract OS if available
        os_match = re.search(r'osclass type="([^"]*)".*?osfamily="([^"]*)"', output)
        if os_match:
            results["os_detection"] = {
                "type": os_match.group(1),
                "family": os_match.group(2)
            }

        # Extract hosts up (ping scan or host discovery)
        for host_block in re.findall(r"<host[^>]*>.*?</host>", output, re.DOTALL):
            if 'state="up"' not in host_block:
                continue
            addr_match = re.search(r'address addr="([^"]+)"', host_block)
            if addr_match:
                addr = addr_match.group(1)
                if addr and addr not in results["hosts_up"]:
                    results["hosts_up"].append(addr)
        
        return results
