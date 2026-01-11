"""
Fallback tool implementations for missing ProjectDiscovery tools
Uses alternative tools when httpx/katana are not available
"""

import subprocess
import json
import asyncio
from typing import Dict, Any, List
from urllib.parse import urlparse


class HttpxFallback:
    """Fallback for httpx using curl"""
    
    def __init__(self, config):
        self.config = config
    
    async def probe_url(self, url: str) -> Dict[str, Any]:
        """Probe single URL using curl"""
        try:
            cmd = [
                "curl", "-s", "-I", "-L", "--max-time", "10",
                "--user-agent", "Guardian-Scanner/1.0",
                url
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                headers = stdout.decode('utf-8', errors='ignore')
                status_code = self._extract_status_code(headers)
                server = self._extract_header(headers, 'Server')
                
                return {
                    "url": url,
                    "status_code": status_code,
                    "server": server,
                    "method": "GET",
                    "success": True
                }
            else:
                return {"url": url, "success": False, "error": stderr.decode()}
                
        except Exception as e:
            return {"url": url, "success": False, "error": str(e)}
    
    def _extract_status_code(self, headers: str) -> int:
        """Extract HTTP status code from headers"""
        lines = headers.split('\n')
        for line in lines:
            if line.startswith('HTTP/'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return int(parts[1])
                    except ValueError:
                        pass
        return 0
    
    def _extract_header(self, headers: str, header_name: str) -> str:
        """Extract specific header value"""
        lines = headers.split('\n')
        for line in lines:
            if line.lower().startswith(header_name.lower() + ':'):
                return line.split(':', 1)[1].strip()
        return ""


class KatanaFallback:
    """Fallback for katana using gospider or hakrawler"""
    
    def __init__(self, config):
        self.config = config
        self.available_crawlers = self._check_available_crawlers()
    
    def _check_available_crawlers(self) -> List[str]:
        """Check which alternative crawlers are available"""
        crawlers = []
        for tool in ['gospider', 'hakrawler']:
            try:
                subprocess.run([tool, '--help'], capture_output=True, timeout=5)
                crawlers.append(tool)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        return crawlers
    
    async def crawl_url(self, url: str, depth: int = 2) -> Dict[str, Any]:
        """Crawl URL using available alternative"""
        if 'gospider' in self.available_crawlers:
            return await self._crawl_with_gospider(url, depth)
        elif 'hakrawler' in self.available_crawlers:
            return await self._crawl_with_hakrawler(url, depth)
        else:
            return await self._crawl_with_wget(url, depth)
    
    async def _crawl_with_gospider(self, url: str, depth: int) -> Dict[str, Any]:
        """Crawl using gospider"""
        try:
            cmd = [
                "gospider", "-s", url, "-d", str(depth),
                "-c", "10", "-t", "10", "--json"
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                urls = []
                for line in stdout.decode().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if data.get('output'):
                                urls.append(data['output'])
                        except json.JSONDecodeError:
                            continue
                
                return {
                    "urls": list(set(urls)),
                    "crawler": "gospider",
                    "success": True
                }
            else:
                return {"success": False, "error": stderr.decode()}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _crawl_with_hakrawler(self, url: str, depth: int) -> Dict[str, Any]:
        """Crawl using hakrawler"""
        try:
            cmd = [
                "hakrawler", "-url", url, "-depth", str(depth),
                "-plain"
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                urls = [line.strip() for line in stdout.decode().split('\n') if line.strip()]
                return {
                    "urls": list(set(urls)),
                    "crawler": "hakrawler", 
                    "success": True
                }
            else:
                return {"success": False, "error": stderr.decode()}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _crawl_with_wget(self, url: str, depth: int) -> Dict[str, Any]:
        """Basic crawling using wget as last resort"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            cmd = [
                "wget", "--spider", "--recursive", f"--level={depth}",
                "--no-parent", "--domains", domain,
                "--user-agent=Guardian-Scanner/1.0",
                "--timeout=10", "--tries=1", "-O", "/dev/null",
                url
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            # Extract URLs from wget output
            urls = []
            for line in stderr.decode().split('\n'):
                if '--' in line and 'http' in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith('http'):
                            urls.append(part.rstrip('...'))
            
            return {
                "urls": list(set(urls)),
                "crawler": "wget",
                "success": True
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}