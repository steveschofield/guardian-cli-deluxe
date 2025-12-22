# Guardian Quick Start Guide

## Installation (Windows)

1. **Navigate to project directory**:
   ```cmd
   cd c:\Users\MyBook Hype AMD\workarea\guardian-cli
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

Edit `config/guardian.yaml` or `~/.guardian/guardian.yaml` to customize:
- AI model and settings
- Tool configurations
- Security guardrails
- Output formats

## Getting Help

```cmd
python -m cli.main --help
python -m cli.main <command> --help
```

## Important Notes

- **Windows**: Use `python -m cli.main` or `.\guardian.bat` instead of `guardian`
- **API Key**: Required for AI features (get from https://makersuite.google.com/app/apikey)
- **External Tools**: Optional but recommended (nmap, httpx, subfinder, nuclei)
- **Authorization**: Only scan systems you have explicit permission to test

## Troubleshooting

### Command not found
- Make sure you're in the project directory
- Activate the virtual environment
- Use `python -m cli.main` instead of `guardian`

### Import errors
- Reinstall dependencies: `pip install -e .`
- Check Python version: `python --version` (requires 3.11+)

### API errors
- Verify your Gemini API key in `.env` or `.guardian/.env`
- Check internet connectivity

## Next Steps

1. Install external pentest tools for full functionality
2. Review `config/guardian.yaml` and customize settings
3. Run `--dry-run` mode to see what would be executed
4. Start with safe targets like `scanme.nmap.org`
5. Review logs in `logs/guardian.log`
