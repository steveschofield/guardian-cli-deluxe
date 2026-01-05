# Guardian Quick Start Guide

## Installation (Windows)

1. **Navigate to project directory**:
   ```cmd
   cd C:\path\to\guardian-cli
   ```

2. **Create virtual environment**:
   ```cmd
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Install Guardian**:
   ```cmd
   pip install -e .
   ```

4. **Initialize configuration**:
   ```cmd
   python -m cli.main init
   ```
   Or use the batch launcher:
   ```cmd
   .\guardian.bat init
   ```

## Common Commands

### List Available Workflows
```cmd
python -m cli.main workflow list
```

### Dry Run Reconnaissance
```cmd
python -m cli.main recon --domain example.com --dry-run
```

### Run Port Scan (requires nmap)
```cmd
python -m cli.main scan --target scanme.nmap.org
```

### Run Full Workflow
```cmd
python -m cli.main workflow run --name recon --target example.com
```

## Configuration

Edit `config/guardian.yaml` (when running from this repo) or `~/.guardian/guardian.yaml` (when using `guardian init`) to customize:
- AI model and settings
- Tool configurations
- Security guardrails
- Output formats

If you’re using `~/.guardian/guardian.yaml`, pass it explicitly:
```cmd
python -m cli.main recon --domain example.com --config %USERPROFILE%\\.guardian\\guardian.yaml
```

## Getting Help

```cmd
python -m cli.main --help
python -m cli.main <command> --help
```

## Important Notes

- **Windows**: Use `python -m cli.main` or `.\guardian.bat` instead of `guardian`
- **API Key**: Required for hosted LLMs (Gemini: https://makersuite.google.com/app/apikey, OpenRouter: https://openrouter.ai/keys). Not required for local Ollama.
- **External Tools**: Optional but recommended (nmap, httpx, subfinder, nuclei, **nikto**)
- **Authorization**: Only scan systems you have explicit permission to test
- **Workflow steps**: Recon/web/full_vuln workflows will run Nikto if present; install via `apt install nikto` (or equivalent) to enable that step.

## Troubleshooting

### Command not found
- Make sure you're in the project directory
- Activate the virtual environment
- Use `python -m cli.main` instead of `guardian`

### Import errors
- Reinstall dependencies: `pip install -e .`
- Check Python version: `python --version` (requires 3.11+)

### API errors
- Verify your Gemini API key in `.env` (project root) or `~/.guardian/.env`
- If using OpenRouter, verify `OPENROUTER_API_KEY` in `.env` (project root) or `~/.guardian/.env`
- If using Gemini Vertex/ADC, ensure `gcloud auth application-default login` has been run and `ai.project` is set in your config
- Check internet connectivity

## Next Steps

1. Install external pentest tools for full functionality
2. Review `config/guardian.yaml` and customize settings
3. Run `--dry-run` mode to see what would be executed
4. Start with safe targets like `scanme.nmap.org`
5. Review logs in `logs/guardian.log`
