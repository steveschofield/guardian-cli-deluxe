"""
Base agent class for all Guardian AI agents
"""

import asyncio
import time
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

from core.memory import PentestMemory
from utils.logger import get_logger


class BaseAgent(ABC):
    """Base class for all AI agents in Guardian"""
    
    def __init__(
        self,
        name: str,
        config: Dict[str, Any],
        llm_client: Any,
        memory: PentestMemory
    ):
        self.name = name
        self.config = config
        self.llm = llm_client
        self.memory = memory
        self.logger = get_logger(config)
    
    @abstractmethod
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the agent's primary function"""
        pass
    
    async def think(self, prompt: str, system_prompt: str) -> Dict[str, str]:
        """
        Use AI to think through a problem with reasoning
        
        Returns:
            Dict with 'reasoning' and 'response' keys
        """
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        pentest_cfg = (self.config or {}).get("pentest", {}) or {}

        # Backwards compatible: config/guardian.yaml uses ai.timeout, while newer configs use ai.llm_timeout_seconds.
        llm_timeout = (
            ai_cfg.get("llm_timeout_seconds")
            or ai_cfg.get("timeout")
            or pentest_cfg.get("llm_timeout_seconds")
            or pentest_cfg.get("timeout")
            or 120
        )
        try:
            llm_timeout = float(llm_timeout)
        except Exception:
            llm_timeout = 120.0

        started = time.time()
        try:
            result = await asyncio.wait_for(
                self.llm.generate_with_reasoning(
                    prompt=prompt,
                    system_prompt=system_prompt
                ),
                timeout=llm_timeout
            )
            
            # Log AI decision
            self.logger.log_ai_decision(
                agent=self.name,
                decision=result["response"],
                reasoning=result["reasoning"],
                context={"prompt": prompt[:200]}
            )
            self.logger.debug(
                f"[{self.name}] LLM call completed in {time.time() - started:.2f}s"
            )
            
            # Store in memory
            self.memory.add_ai_decision(
                agent=self.name,
                decision=result["response"],
                reasoning=result["reasoning"]
            )
            
            return result
            
        except asyncio.TimeoutError:
            elapsed = time.time() - started
            self.logger.error(f"Agent {self.name} LLM call timed out after {elapsed:.2f}s")
            raise
        except Exception as e:
            self.logger.error(f"Agent {self.name} thinking error: {e}")
            raise
    
    def log_action(self, action: str, details: str):
        """Log an agent action"""
        self.logger.info(f"[{self.name}] {action}: {details}")
