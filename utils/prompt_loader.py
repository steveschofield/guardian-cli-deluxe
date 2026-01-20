"""
Dynamic prompt loader utility

Loads appropriate prompts based on configuration
"""

import importlib
from typing import Dict, Any


class PromptLoader:
    """Manages dynamic loading of prompt templates based on LLM configuration"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._prompts_cache = None
        self._current_prompt_set = None

    def get_prompt_set(self) -> str:
        """
        Determine which prompt set to use based on configuration.

        Priority:
        1. Explicit config.ai.prompt_set
        2. Auto-detect from model name
        3. Default to "default"
        """
        ai_config = self.config.get("ai", {})

        # Explicit prompt_set in config
        prompt_set = ai_config.get("prompt_set")
        if prompt_set:
            return prompt_set

        # Auto-detect from model name
        model_name = ai_config.get("model", "").lower()

        # Map model patterns to prompt sets
        if any(pattern in model_name for pattern in ["llama3.2:3b", "llama3.2-3b", "llama-3.2-3b"]):
            return "llama3_2_3b"

        if any(pattern in model_name for pattern in ["llama3.1:8b", "llama3.1-8b", "llama-3.1-8b"]):
            return "llama3_1_8b"

        if any(pattern in model_name for pattern in ["deepseek-r1:8b", "deepseek-r1-8b", "deepseek_r1"]):
            return "deepseek_r1_8b"

        if any(pattern in model_name for pattern in ["deephat", "deep-hat", "deephat-v1"]):
            return "deephat_v1_7b"

        # Default prompts
        return "default"

    def load_prompts(self) -> Dict[str, str]:
        """
        Load prompt templates based on configuration.

        Returns:
            dict: All prompt constants as a dictionary
        """
        prompt_set = self.get_prompt_set()

        # Return cached prompts if same set
        if self._prompts_cache and self._current_prompt_set == prompt_set:
            return self._prompts_cache

        # Load appropriate prompt module based on prompt set
        if prompt_set == "llama3_2_3b":
            # Import llama3_2_3b optimized prompts
            from ai.prompt_templates import llama3_2_3b as prompt_module

            # Collect all prompts
            prompts = {}
            for attr in dir(prompt_module):
                if attr.isupper() and "PROMPT" in attr:
                    prompts[attr] = getattr(prompt_module, attr)
        elif prompt_set == "llama3_1_8b":
            # Import llama3_1_8b optimized prompts
            from ai.prompt_templates import llama3_1_8b as prompt_module

            # Collect all prompts
            prompts = {}
            for attr in dir(prompt_module):
                if attr.isupper() and "PROMPT" in attr:
                    prompts[attr] = getattr(prompt_module, attr)
        elif prompt_set == "deepseek_r1_8b":
            # Import deepseek_r1_8b reasoning-focused prompts
            from ai.prompt_templates import deepseek_r1_8b as prompt_module

            # Collect all prompts
            prompts = {}
            for attr in dir(prompt_module):
                if attr.isupper() and "PROMPT" in attr:
                    prompts[attr] = getattr(prompt_module, attr)
        elif prompt_set == "deephat_v1_7b":
            # Import deephat_v1_7b red team optimized prompts
            from ai.prompt_templates import deephat_v1_7b as prompt_module

            # Collect all prompts
            prompts = {}
            for attr in dir(prompt_module):
                if attr.isupper() and "PROMPT" in attr:
                    prompts[attr] = getattr(prompt_module, attr)
        else:
            # Default prompts - import from main package
            from ai import prompt_templates as prompt_module

            # Extract all prompt constants
            prompts = {}
            for attr in dir(prompt_module):
                if attr.isupper() and "PROMPT" in attr:
                    prompts[attr] = getattr(prompt_module, attr)

        # Cache the results
        self._prompts_cache = prompts
        self._current_prompt_set = prompt_set

        return prompts

    def get_prompt(self, prompt_name: str) -> str:
        """
        Get a specific prompt by name.

        Args:
            prompt_name: Name of the prompt constant (e.g., "ANALYST_SYSTEM_PROMPT")

        Returns:
            str: The prompt text

        Raises:
            KeyError: If prompt name not found
        """
        prompts = self.load_prompts()
        return prompts[prompt_name]


def get_prompts(config: Dict[str, Any]) -> Dict[str, str]:
    """
    Convenience function to load prompts from config.

    Args:
        config: Guardian configuration dictionary

    Returns:
        dict: All prompt constants
    """
    loader = PromptLoader(config)
    return loader.load_prompts()
