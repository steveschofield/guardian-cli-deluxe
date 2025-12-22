# 🔐 Guardian - AI-Powered Penetration Testing CLI Tool

**Guardian** is a production-ready AI-powered penetration testing automation CLI tool that leverages **Google Gemini** and **LangChain** to orchestrate intelligent, step-by-step penetration testing workflows while maintaining ethical hacking standards.

## ✨ Features

- **🤖 AI-Driven Decision Making**: Uses Google Gemini to strategically decide next testing steps
- **🔄 Multi-Agent System**: Specialized AI agents for planning, tool selection, analysis, and reporting
- **🛠️ Tool Integration**: Seamlessly integrates with industry-standard pentest tools (nmap, httpx, subfinder, nuclei)
- **📊 Intelligent Analysis**: AI-powered result interpretation and false positive filtering
- **🔒 Security First**: Built-in safety guardrails, scope validation, and human-in-the-loop controls
- **📝 Professional Reports**: Auto-generated reports in Markdown, HTML, and JSON formats
- **⚡ Async Execution**: Fast parallel tool execution
- **🎯 Workflow Automation**: Predefined workflows for recon, web, and network pentesting

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Google Gemini API Key ([Get one here](https://makersuite.google.com/app/apikey))
- Optional external tools: `nmap`, `httpx`, `subfinder`, `nuclei`

### Installation

```bash
# Clone the repository
cd c:\Users\MyBook Hype AMD\workarea\guardian-cli

# Create and activate virtual environment (recommended)
python -m venv venv
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -e .
```

### Initial Setup

```bash
# Initialize Guardian (creates config files and prompts for API key)
python -m cli.main init

# Or use the Windows batch launcher
.\guardian.bat init
```

During initialization, you'll be prompted for your Gemini API key.

> **Windows Note**: On Windows, use `python -m cli.main` or `.\guardian.bat` instead of just `guardian`.

### Basic Usage

```bash
# Run reconnaissance on a domain
python -m cli.main recon --domain example.com

# Dry run to see what would be executed
python -m cli.main recon --domain example.com --dry-run

# Quick port scan
python -m cli.main scan --target 192.168.1.1 --ports "80,443,8080"

# Run a full workflow
python -m cli.main workflow run --name recon --target example.com

# Run autonomous AI-driven pentest
python -m cli.main workflow run --name autonomous --target example.com

# List available workflows
python -m cli.main workflow list

# Generate a report
python -m cli.main report --session <session-id> --format html
```

## 📖 Documentation

### Commands

#### `guardian init`
Initialize configuration and set up API keys.

```bash
guardian init
guardian init --config-dir ~/.guardian --force
```

#### `guardian scan`
Quick port scanning with nmap.

```bash
guardian scan --target example.com
guardian scan --target 192.168.1.0/24 --ports "1-1000"
```

#### `guardian recon`
Run full reconnaissance workflow.

```bash
guardian recon --domain example.com
guardian recon --domain example.com --dry-run  # Show plan without executing
```

#### `guardian workflow`
Run predefined or autonomous workflows.

```bash
# List workflows
guardian workflow list

# Run reconnaissance workflow
guardian workflow run --name recon --target example.com

# Run web application pentest
guardian workflow run --name web --target https://example.com

# Run autonomous AI-driven testing
guardian workflow run --name autonomous --target example.com
```

#### `guardian analyze`
Analyze scan results with AI.

```bash
guardian analyze --input scan_results.json
```

#### `guardian report`
Generate professional pentesting reports.

```bash
guardian report --session 20241222_120000 --format markdown
guardian report --session 20241222_120000 --format html --output report.html
```

## 🏗️ Architecture

Guardian uses a multi-agent architecture:

```
┌─────────────┐
│   Planner   │  → Decides next steps strategically
│    Agent    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Tool Agent  │  → Selects and configures tools
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Analyst    │  → Interprets results, finds vulns
│    Agent    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Reporter   │  → Generates professional reports
│    Agent    │
└─────────────┘
```

### Key Components

- **AI Layer**: Gemini client with LangChain orchestration
- **Core**: Agents, workflow engine, memory management
- **Tools**: Wrappers for pentesting tools (nmap, httpx, subfinder, nuclei)
- **CLI**: Typer-based command interface with rich output
- **Utils**: Logging, scope validation, configuration

## ⚙️ Configuration

Edit `~/.guardian/guardian.yaml` or `config/guardian.yaml`:

```yaml
ai:
  provider: gemini
  model: gemini-1.5-pro
  temperature: 0.2

pentest:
  safe_mode: true
  require_confirmation: true
  max_parallel_tools: 3
  tool_timeout: 300

output:
  format: markdown
  save_path: ./reports
  include_reasoning: true
  verbosity: normal

scope:
  blacklist:
    - 127.0.0.0/8
    - 10.0.0.0/8
  require_scope_file: false
```

## 🔒 Security & Ethics

Guardian is designed with security and ethics as core principles:

- **Scope Validation**: Automatic blacklisting of private IP ranges
- **Confirmation Prompts**: Required approval before executing tools
- **Audit Logging**: All AI decisions and actions are logged
- **Safe Mode**: Prevents destructive actions by default
- **Human-in-the-Loop**: User control over workflow execution

> ⚠️ **Warning**: Guardian must only be used for authorized penetration testing. Unauthorized scanning is illegal. Always obtain proper authorization before testing any system.

## 📊 Workflows

### Reconnaissance Workflow
1. Subdomain enumeration (subfinder)
2. Port scanning (nmap)
3. HTTP probing (httpx)
4. AI analysis and correlation

### Web Application Workflow
1. HTTP service discovery
2. Technology detection
3. Vulnerability scanning (nuclei)
4. AI-powered analysis

### Network Workflow
1. Port scanning
2. Service detection
3. OS fingerprinting
4. Vulnerability assessment

### Autonomous Workflow
AI-driven adaptive testing where the Planner Agent decides each step dynamically based on findings.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## 📄 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- Google Gemini for AI capabilities
- LangChain for orchestration framework
- The offensive security community for tools and knowledge

## 📞 Support

For issues and questions, please open a GitHub issue.

---

**Guardian** - Intelligent, Ethical, Automated Penetration Testing
