"""
Base class for all pentest tool wrappers
"""

import asyncio
import subprocess
import shutil
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
from abc import ABC, abstractmethod

from utils.logger import get_logger


class BaseTool(ABC):
    """Base class for external penetration testing tools"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)
        self.tool_name = self.__class__.__name__.replace("Tool", "").lower()
        
        # Check if tool is installed
        self.is_available = self._check_installation()
        if not self.is_available:
            self.logger.warning(f"Tool {self.tool_name} is not installed or not in PATH")
    
    @abstractmethod
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build command line for the tool"""
        pass
    
    @abstractmethod
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse tool output into structured data"""
        pass
    
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute the tool against a target
        
        Returns:
            Dict with parsed results, raw output, and metadata
        """
        if not self.is_available:
            raise RuntimeError(f"Tool {self.tool_name} is not available")
        
        # Build command
        command = self.get_command(target, **kwargs)
        
        self.logger.info(f"Executing: {' '.join(command)}")
        
        # Get execution timeout from config (per-tool overrides supported)
        timeout_override = kwargs.get("tool_timeout")
        timeout = (
            (self.config.get("tools", {}).get(self.tool_name, {}) or {}).get("tool_timeout")
            if isinstance(self.config, dict)
            else None
        )
        if timeout_override is not None:
            timeout = timeout_override
        if timeout is None:
            timeout = self.config.get("pentest", {}).get("tool_timeout", 300)
        try:
            timeout = int(timeout)
        except Exception:
            timeout = 300
        
        start_time = datetime.now()
        status = "unknown"
        exit_code: Optional[int] = None
        stdout_len = 0
        stderr_len = 0
        process: Optional[asyncio.subprocess.Process] = None
        
        try:
            # Execute tool
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait with timeout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            exit_code = process.returncode
            
            # Decode output
            stdout_len = len(stdout or b"")
            stderr_len = len(stderr or b"")
            output = (stdout or b"").decode('utf-8', errors='replace')
            error = (stderr or b"").decode('utf-8', errors='replace')
            
            # Parse results (prefer stdout; keep stderr for diagnostics)
            parsed = self.parse_output(output)

            # Combine stderr into raw output when stdout is empty or the tool failed.
            combined_output = output
            if error and (not output.strip() or process.returncode != 0):
                combined_output = (output + "\n" + error).strip()
            
            result = {
                "tool": self.tool_name,
                "target": target,
                "command": " ".join(command),
                "timestamp": start_time.isoformat(),
                "exit_code": process.returncode,
                "duration": duration,
                "raw_output": combined_output,
                "error": error if error else None,
                "parsed": parsed
            }

            status = "completed" if process.returncode == 0 else "failed"
            return result
            
        except asyncio.TimeoutError:
            status = "timed_out"
            self.logger.error(f"Tool {self.tool_name} timed out after {timeout}s")
            try:
                if process and process.returncode is None:
                    process.kill()
                    await process.communicate()
            except Exception:
                pass
            raise
        except Exception as e:
            status = "exception"
            self.logger.error(f"Tool {self.tool_name} failed: {e}")
            raise
        finally:
            duration = (datetime.now() - start_time).total_seconds()
            exit_str = f"{exit_code}" if exit_code is not None else "n/a"
            self.logger.info(
                f"Tool {self.tool_name} finished in {duration:.2f}s (status={status}, exit={exit_str}, stdout={stdout_len}B, stderr={stderr_len}B)"
            )
    
    def _check_installation(self) -> bool:
        """Check if tool is installed and in PATH"""
        return shutil.which(self.tool_name) is not None
    
    def get_version(self) -> Optional[str]:
        """Get tool version if available"""
        try:
            result = subprocess.run(
                [self.tool_name, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() or result.stderr.strip()
        except:
            return None
