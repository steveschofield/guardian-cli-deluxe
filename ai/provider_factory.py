"""
Factory for selecting the LLM backend based on configuration.
"""

from typing import Any, Dict


def get_llm_client(config: Dict[str, Any]) -> Any:
    """
    Return the appropriate LLM client based on config["ai"]["provider"].
    Supported providers: gemini, ollama, openrouter, huggingface.
    """
    provider = config.get("ai", {}).get("provider", "gemini").lower()

    if provider == "gemini":
        from ai.gemini_client import GeminiClient
        return GeminiClient(config)
    if provider == "ollama":
        from ai.ollama_client import OllamaClient
        return OllamaClient(config)
    if provider == "openrouter":
        from ai.openrouter_client import OpenRouterClient
        return OpenRouterClient(config)
    if provider in {"huggingface", "hf"}:
        from ai.huggingface_client import HuggingFaceClient
        return HuggingFaceClient(config)

    raise ValueError(f"Unsupported AI provider: {provider}")
