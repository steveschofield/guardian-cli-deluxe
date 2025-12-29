"""
Factory for selecting the LLM backend based on configuration.
"""

from typing import Any, Dict

from ai.gemini_client import GeminiClient
from ai.ollama_client import OllamaClient


def get_llm_client(config: Dict[str, Any]) -> Any:
    """
    Return the appropriate LLM client based on config["ai"]["provider"].
    Supported providers: gemini, ollama.
    """
    provider = config.get("ai", {}).get("provider", "gemini").lower()

    if provider == "gemini":
        return GeminiClient(config)
    if provider == "ollama":
        return OllamaClient(config)

    raise ValueError(f"Unsupported AI provider: {provider}")
