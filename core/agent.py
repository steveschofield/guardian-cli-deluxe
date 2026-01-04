"""
Base agent class for all Guardian AI agents
"""

import asyncio
import json
import os
import time
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from uuid import uuid4

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
        call_id = uuid4().hex
        try:
            self._maybe_log_llm_request(call_id=call_id, prompt=prompt, system_prompt=system_prompt)

            result = await asyncio.wait_for(
                self.llm.generate_with_reasoning(
                    prompt=prompt,
                    system_prompt=system_prompt
                ),
                timeout=llm_timeout
            )

            usage = getattr(self.llm, "last_usage", None)
            request_id = getattr(self.llm, "last_request_id", None)
            model = getattr(self.llm, "last_model", None)
            bits: list[str] = []
            if isinstance(usage, dict):
                prompt_tokens = usage.get("prompt_tokens")
                completion_tokens = usage.get("completion_tokens")
                total_tokens = usage.get("total_tokens")
                if model:
                    bits.append(f"model={model}")
                if request_id:
                    bits.append(f"request_id={request_id}")
                tok = []
                if prompt_tokens is not None:
                    tok.append(f"prompt={prompt_tokens}")
                if completion_tokens is not None:
                    tok.append(f"completion={completion_tokens}")
                if total_tokens is not None:
                    tok.append(f"total={total_tokens}")
                if tok:
                    bits.append("tokens(" + ", ".join(tok) + ")")
            if bits:
                self.logger.info(f"[{self.name}] LLM usage: " + " ".join(bits))

            self._maybe_log_llm_response(
                call_id=call_id,
                prompt=prompt,
                system_prompt=system_prompt,
                response=result.get("response", ""),
                reasoning=result.get("reasoning", ""),
                usage=usage if isinstance(usage, dict) else None,
                request_id=request_id if isinstance(request_id, str) else None,
                model=model if isinstance(model, str) else None,
            )

            # Log AI decision
            context = {"prompt": prompt[:200]}
            if isinstance(usage, dict):
                context["llm_usage"] = usage
            if request_id:
                context["llm_request_id"] = request_id
            if model:
                context["llm_model"] = model
            self.logger.log_ai_decision(
                agent=self.name,
                decision=result["response"],
                reasoning=result["reasoning"],
                context=context
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
            self._maybe_log_llm_error(
                call_id=call_id,
                prompt=prompt,
                system_prompt=system_prompt,
                error=f"timeout after {elapsed:.2f}s",
            )
            raise
        except Exception as e:
            self.logger.error(f"Agent {self.name} thinking error: {e}")
            self._maybe_log_llm_error(
                call_id=call_id,
                prompt=prompt,
                system_prompt=system_prompt,
                error=str(e),
            )
            raise

    def _llm_io_enabled(self) -> bool:
        """
        Enable full request/response logging when:
        - env LSG_LOG_LLM_REQUESTS=1, OR
        - config.ai.log_llm_requests/log_llm_responses/log_llm_io_file is true
        """
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        env_on = os.getenv("LSG_LOG_LLM_REQUESTS", "").strip() in {"1", "true", "TRUE", "yes", "YES"}
        cfg_on = bool(
            ai_cfg.get("log_llm_requests")
            or ai_cfg.get("log_llm_responses")
            or ai_cfg.get("log_llm_io_file")
            or ai_cfg.get("log_llm_full_io")
        )
        return env_on or cfg_on

    def _llm_io_path(self, out_dir: Path) -> Path:
        session_id = getattr(self.memory, "session_id", None) or "unknown"

        path = getattr(self.memory, "llm_io_log_path", None)
        if not isinstance(path, (str, Path)) or not str(path):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = out_dir / f"llm_io_{session_id}_{ts}.jsonl"
            try:
                setattr(self.memory, "llm_io_log_path", str(path))
            except Exception:
                pass
        return Path(str(path))

    def _maybe_log_llm_request(self, call_id: str, prompt: str, system_prompt: str) -> None:
        if not self._llm_io_enabled():
            return

        # Keep console readable: full prompts go to file; console shows only a short marker unless debug is on.
        self.logger.info(f"[{self.name}] LLM request: system_prompt={len(system_prompt)} chars, prompt={len(prompt)} chars")

        ai_cfg = (self.config or {}).get("ai", {}) or {}
        save_file = bool(
            ai_cfg.get("log_llm_io_file")
            or ai_cfg.get("log_llm_full_io")
            or os.getenv("LSG_DEBUG_SAVE_OUTPUT", "").strip() in {"1", "true", "TRUE", "yes", "YES"}
        )
        if not save_file:
            return

        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)

        record = {
            "timestamp": datetime.now().isoformat(),
            "event": "request",
            "call_id": call_id,
            "agent": self.name,
            "provider": ((self.config or {}).get("ai", {}) or {}).get("provider"),
            "model": ((self.config or {}).get("ai", {}) or {}).get("model"),
            "system_prompt": system_prompt,
            "prompt": prompt,
        }

        path = self._llm_io_path(out_dir)
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.warning(f"[{self.name}] Failed to write LLM request log: {e}")

    def _maybe_log_llm_response(
        self,
        call_id: str,
        prompt: str,
        system_prompt: str,
        response: str,
        reasoning: str,
        usage: Optional[Dict[str, Any]],
        request_id: Optional[str],
        model: Optional[str],
    ) -> None:
        if not self._llm_io_enabled():
            return

        ai_cfg = (self.config or {}).get("ai", {}) or {}
        save_file = bool(
            ai_cfg.get("log_llm_io_file")
            or ai_cfg.get("log_llm_full_io")
            or os.getenv("LSG_DEBUG_SAVE_OUTPUT", "").strip() in {"1", "true", "TRUE", "yes", "YES"}
        )

        self.logger.info(f"[{self.name}] LLM response: {len(response or '')} chars")

        if not save_file:
            return

        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)

        record = {
            "timestamp": datetime.now().isoformat(),
            "event": "response",
            "call_id": call_id,
            "agent": self.name,
            "provider": ((self.config or {}).get("ai", {}) or {}).get("provider"),
            "model": model or ((self.config or {}).get("ai", {}) or {}).get("model"),
            "request_id": request_id,
            "response": response,
            "reasoning": reasoning,
            "usage": usage,
        }

        path = self._llm_io_path(out_dir)
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.warning(f"[{self.name}] Failed to write LLM IO log: {e}")

    def _maybe_log_llm_error(self, call_id: str, prompt: str, system_prompt: str, error: str) -> None:
        if not self._llm_io_enabled():
            return

        ai_cfg = (self.config or {}).get("ai", {}) or {}
        save_file = bool(
            ai_cfg.get("log_llm_io_file")
            or ai_cfg.get("log_llm_full_io")
            or os.getenv("LSG_DEBUG_SAVE_OUTPUT", "").strip() in {"1", "true", "TRUE", "yes", "YES"}
        )
        if not save_file:
            return

        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)

        record = {
            "timestamp": datetime.now().isoformat(),
            "event": "error",
            "call_id": call_id,
            "agent": self.name,
            "provider": ((self.config or {}).get("ai", {}) or {}).get("provider"),
            "model": ((self.config or {}).get("ai", {}) or {}).get("model"),
            "error": error,
        }

        path = self._llm_io_path(out_dir)
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.warning(f"[{self.name}] Failed to write LLM error log: {e}")
    
    def log_action(self, action: str, details: str):
        """Log an agent action"""
        self.logger.info(f"[{self.name}] {action}: {details}")
