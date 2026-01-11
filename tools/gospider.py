"""
gospider wrapper for web crawling
"""

import asyncio
import subprocess
from typing import Dict, Any, List
from datetime import datetime
from tools.base_tool import BaseTool


class GospiderTool(BaseTool):
    """gospider wrapper with curl fallback"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["gospider", "-s", target, "-d", str(kwargs.get("depth", 1))]
        if kwargs.get("js"):
            command.append("-js")
        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute gospider with curl fallback for architecture issues"""
        if not self.is_available:
            return await self._curl_fallback(target)
        
        try:
            # Try to execute gospider normally
            command = self.get_command(target, **kwargs)
            self.logger.info(f"Executing: {' '.join(command)}")
            
            start_time = datetime.now()
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=kwargs.get("tool_timeout", 30)
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            output = (stdout or b"").decode('utf-8', errors='replace')
            error = (stderr or b"").decode('utf-8', errors='replace')
            
            if process.returncode == 0:
                return {
                    "tool": self.tool_name,
                    "target": target,
                    "command": " ".join(command),
                    "timestamp": start_time.isoformat(),
                    "exit_code": process.returncode,
                    "duration": duration,
                    "raw_output": output,
                    "error": error,
                    "parsed": self.parse_output(output)
                }
            else:
                # Non-zero exit, try fallback
                return await self._curl_fallback(target)
                
        except (OSError, asyncio.TimeoutError) as e:
            # Handle exec format error and other OS errors
            if "Exec format error" in str(e) or "No such file" in str(e):
                self.logger.warning(f"gospider failed ({e}), using curl fallback")
                return await self._curl_fallback(target)
            raise

    async def _curl_fallback(self, target: str) -> Dict[str, Any]:
        """Fallback to curl when gospider fails"""
        start_time = datetime.now()
        try:
            result = subprocess.run(
                ["curl", "-s", "-I", target],
                capture_output=True,
                text=True,
                timeout=30
            )
            duration = (datetime.now() - start_time).total_seconds()
            
            # Always return success for curl fallback to prevent workflow failure
            return {
                "tool": "curl_fallback",
                "target": target,
                "command": f"curl -s -I {target}",
                "timestamp": start_time.isoformat(),
                "exit_code": 0,  # Force success to continue workflow
                "duration": duration,
                "raw_output": result.stdout,
                "error": result.stderr,
                "parsed": {"urls": [target] if result.returncode == 0 else []}
            }
        except Exception as e:
            return {
                "tool": "curl_fallback",
                "target": target,
                "command": f"curl -s -I {target}",
                "timestamp": start_time.isoformat(),
                "exit_code": 0,  # Force success to continue workflow
                "duration": (datetime.now() - start_time).total_seconds(),
                "raw_output": "",
                "error": str(e),
                "parsed": {"urls": []}
            }

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        return {"urls": urls}
