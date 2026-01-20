#!/usr/bin/env python3
"""
Test script to validate all prompt sets load correctly
"""

import sys
import importlib.util

# Load prompt_loader directly to avoid rich dependency
spec = importlib.util.spec_from_file_location('prompt_loader', 'utils/prompt_loader.py')
prompt_loader_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prompt_loader_module)

PromptLoader = prompt_loader_module.PromptLoader


def test_prompt_set(model_name, expected_prompt_set):
    """Test that a model name correctly resolves to expected prompt set"""
    config = {"ai": {"model": model_name}}
    loader = PromptLoader(config)

    detected_set = loader.get_prompt_set()
    print(f"✓ Model '{model_name}' → Prompt set '{detected_set}'", end="")

    if detected_set != expected_prompt_set:
        print(f" ✗ FAILED (expected '{expected_prompt_set}')")
        return False

    # Try to load prompts
    try:
        prompts = loader.load_prompts()
        required_prompts = [
            "ANALYST_SYSTEM_PROMPT",
            "ANALYST_INTERPRET_PROMPT",
            "PLANNER_SYSTEM_PROMPT",
            "PLANNER_DECISION_PROMPT",
            "REPORTER_SYSTEM_PROMPT",
            "REPORTER_EXECUTIVE_SUMMARY_PROMPT",
        ]

        missing = [p for p in required_prompts if p not in prompts]
        if missing:
            print(f" ✗ FAILED (missing prompts: {missing})")
            return False

        print(f" ✓ ({len(prompts)} prompts loaded)")
        return True
    except Exception as e:
        print(f" ✗ FAILED (load error: {e})")
        return False


def main():
    """Run all prompt validation tests"""
    print("=" * 60)
    print("Prompt Set Validation Tests")
    print("=" * 60)

    tests = [
        # Llama 3.2 3B variants
        ("llama3.2:3b", "llama3_2_3b"),
        ("llama3.2-3b", "llama3_2_3b"),
        ("llama-3.2-3b", "llama3_2_3b"),

        # Llama 3.1 8B variants
        ("llama3.1:8b", "llama3_1_8b"),
        ("llama3.1-8b", "llama3_1_8b"),
        ("llama-3.1-8b", "llama3_1_8b"),

        # DeepSeek-R1 8B variants
        ("deepseek-r1:8b", "deepseek_r1_8b"),
        ("deepseek-r1-8b", "deepseek_r1_8b"),
        ("deepseek_r1", "deepseek_r1_8b"),

        # DeepHat variants
        ("DeepHat/DeepHat-V1-7B:latest", "deephat_v1_7b"),
        ("deephat", "deephat_v1_7b"),
        ("deep-hat", "deephat_v1_7b"),
        ("deephat-v1", "deephat_v1_7b"),

        # Default fallback
        ("gpt-4", "default"),
        ("claude-3-opus", "default"),
        ("unknown-model", "default"),
    ]

    passed = 0
    failed = 0

    for model_name, expected_set in tests:
        if test_prompt_set(model_name, expected_set):
            passed += 1
        else:
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed > 0:
        sys.exit(1)

    print("\n✓ All prompt sets validated successfully!")


if __name__ == "__main__":
    main()
