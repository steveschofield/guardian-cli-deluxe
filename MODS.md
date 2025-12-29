# Guardian Modding Guide

Quick pointers for extending Guardian with new tools, workflows, or AI backends.

## Adding a New Tool
- Implement a tool class in `tools/` following existing patterns (e.g., `NmapTool`, `HttpxTool`).
- Wire it into `tools/__init__.py` and register it in `core/tool_agent.py` `available_tools`.
- Provide sensible defaults and guardrails (timeouts, safe args) in the tool config block in `config/guardian.yaml`.
- If the tool needs external binaries, update the Dockerfile and/or docs.

## Adding a Workflow
- Define a workflow YAML in `workflows/` or extend `_load_workflow` logic if using code-driven steps.
- Keep step names descriptive; ensure each step maps to a tool/action the agents understand.
- Update docs/README if the workflow should be user-facing.

## Changing AI Providers
- Guardian now supports Gemini and local LLMs via Ollama/OpenAI-compatible endpoints.
- Configure in `config/guardian.yaml` (or `~/.guardian/guardian.yaml`):
  ```yaml
  ai:
    provider: ollama   # or gemini
    model: "llama3.1:8b"
    base_url: "http://127.0.0.1:11434"
  ```
- To add a new provider, implement a client in `ai/`, extend `ai/provider_factory.py`, and ensure it exposes `generate`, `generate_sync`, and `generate_with_reasoning`.
- Add any needed pip deps to `pyproject.toml` and Dockerfile.

## Scope/Safety
- Default scope blacklist lives in `config/guardian.yaml` (`scope.blacklist`). Adjust for lab/production needs.
- `safe_mode` and `require_confirmation` live under `pentest` config. Keep destructive actions gated.

## Testing Changes
- Run a local workflow: `python -m cli.main workflow run --name autonomous --target http://target`.
- For CLI help: `python -m cli.main --help`.
- Consider adding lightweight unit tests under `tests/` for new parsers/logic.

## Docs
- Update `README.md` when adding user-facing features or new requirements.
