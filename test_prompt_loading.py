#!/usr/bin/env python3
"""
Test script to verify prompt loading functionality
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.prompt_loader import PromptLoader


def test_default_prompts():
    """Test loading default prompts"""
    print("=" * 80)
    print("Testing DEFAULT prompts...")
    print("=" * 80)

    config = {
        "ai": {
            "provider": "ollama",
            "model": "llama3.1:8b",
            "prompt_set": "default"
        }
    }

    loader = PromptLoader(config)
    prompts = loader.load_prompts()

    print(f"\nLoaded {len(prompts)} prompts")
    print(f"Prompt set: {loader.get_prompt_set()}")

    # Show a sample prompt
    if "ANALYST_SYSTEM_PROMPT" in prompts:
        sample = prompts["ANALYST_SYSTEM_PROMPT"]
        print(f"\nANALYST_SYSTEM_PROMPT (first 200 chars):")
        print(f"{sample[:200]}...")
        print(f"Total length: {len(sample)} characters")


def test_llama3_2_3b_prompts():
    """Test loading Llama 3.2 3B optimized prompts"""
    print("\n" + "=" * 80)
    print("Testing LLAMA3-2-3B optimized prompts...")
    print("=" * 80)

    config = {
        "ai": {
            "provider": "ollama",
            "model": "llama3.2:3b",
            "prompt_set": "llama3-2-3b"
        }
    }

    loader = PromptLoader(config)
    prompts = loader.load_prompts()

    print(f"\nLoaded {len(prompts)} prompts")
    print(f"Prompt set: {loader.get_prompt_set()}")

    # Show a sample prompt
    if "ANALYST_SYSTEM_PROMPT" in prompts:
        sample = prompts["ANALYST_SYSTEM_PROMPT"]
        print(f"\nANALYST_SYSTEM_PROMPT (first 200 chars):")
        print(f"{sample[:200]}...")
        print(f"Total length: {len(sample)} characters")


def test_auto_detection():
    """Test auto-detection of prompt set from model name"""
    print("\n" + "=" * 80)
    print("Testing AUTO-DETECTION...")
    print("=" * 80)

    test_cases = [
        ("llama3.2:3b", "llama3-2-3b"),
        ("llama3.1:8b", "default"),
        ("deepseek-r1:8b", "default"),
        ("mistral:7b", "default"),
    ]

    for model, expected in test_cases:
        config = {"ai": {"model": model}}
        loader = PromptLoader(config)
        detected = loader.get_prompt_set()
        status = "✓" if detected == expected else "✗"
        print(f"{status} Model: {model:20} → {detected:15} (expected: {expected})")


def compare_prompts():
    """Compare default vs optimized prompts"""
    print("\n" + "=" * 80)
    print("COMPARISON: Default vs Optimized")
    print("=" * 80)

    # Load both sets
    default_loader = PromptLoader({"ai": {"prompt_set": "default"}})
    llama_loader = PromptLoader({"ai": {"prompt_set": "llama3-2-3b"}})

    default_prompts = default_loader.load_prompts()
    llama_prompts = llama_loader.load_prompts()

    # Compare key prompts
    comparison_prompts = [
        "ANALYST_SYSTEM_PROMPT",
        "ANALYST_INTERPRET_PROMPT",
        "PLANNER_DECISION_PROMPT",
        "REPORTER_SYSTEM_PROMPT",
    ]

    print(f"\n{'Prompt':<30} {'Default':<15} {'Optimized':<15} {'Reduction':<15}")
    print("-" * 80)

    for prompt_name in comparison_prompts:
        if prompt_name in default_prompts and prompt_name in llama_prompts:
            default_len = len(default_prompts[prompt_name])
            llama_len = len(llama_prompts[prompt_name])
            reduction = ((default_len - llama_len) / default_len * 100) if default_len > 0 else 0
            print(f"{prompt_name:<30} {default_len:<15} {llama_len:<15} {reduction:>6.1f}%")


def main():
    """Run all tests"""
    try:
        test_default_prompts()
        test_llama3_2_3b_prompts()
        test_auto_detection()
        compare_prompts()

        print("\n" + "=" * 80)
        print("✓ All tests completed successfully!")
        print("=" * 80)

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
