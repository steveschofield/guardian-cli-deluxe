<div align="center">

<img src="docs/logo.svg" alt="Guardian Logo" width="200" />

# 🔐 Guardian

### AI-Powered Penetration Testing Automation Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Guardian** is an enterprise-grade AI-powered penetration testing automation framework that combines the strategic reasoning of Google Gemini with battle-tested security tools to deliver intelligent, adaptive security assessments.

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## ⚠️ Legal Disclaimer

**Guardian is designed exclusively for authorized security testing and educational purposes.**

- ✅ **Legal Use**: Authorized penetration testing, security research, educational environments
- ❌ **Illegal Use**: Unauthorized access, malicious activities, any form of cyber attack

**You are fully responsible for ensuring you have explicit written permission before testing any system.** Unauthorized access to computer systems is illegal under laws including the Computer Fraud and Abuse Act (CFAA), GDPR, and equivalent international legislation.

**By using Guardian, you agree to use it only on systems you own or have explicit authorization to test.**

---

## ✨ Features

### 🤖 AI-Powered Intelligence

- **Multi-Agent Architecture**: Specialized AI agents (Planner, Tool Selector, Analyst, Reporter) collaborate for comprehensive security assessments
- **Strategic Decision Making**: Google Gemini analyzes findings and determines optimal next steps
- **Adaptive Testing**: AI adjusts tactics based on discovered vulnerabilities and system responses
- **False Positive Filtering**: Intelligent analysis reduces noise and focuses on real vulnerabilities

### 🛠️ Extensive Tool Arsenal

**15 Integrated Security Tools:**
- **Network**: Nmap (comprehensive port scanning), Masscan (ultra-fast scanning)
- **Web Reconnaissance**: httpx (HTTP probing), WhatWeb (technology fingerprinting), Wafw00f (WAF detection)
- **Subdomain Discovery**: Subfinder (passive enumeration), Amass (active/passive mapping)
- **Vulnerability Scanning**: Nuclei (template-based), Nikto (web vulnerabilities), SQLMap (SQL injection), WPScan (WordPress)
- **SSL/TLS Testing**: TestSSL (cipher analysis), SSLyze (advanced configuration analysis)
- **Content Discovery**: Gobuster (directory brute forcing), FFuf (advanced web fuzzing)

### 🔒 Security & Compliance

- **Scope Validation**: Automatic blacklisting of private networks and unauthorized targets
- **Audit Logging**: Complete transparency with detailed logs of all AI decisions and actions
- **Human-in-the-Loop**: Configurable confirmation prompts for sensitive operations
- **Safe Mode**: Prevents destructive actions by default

### 📊 Professional Reporting

- **Multiple Formats**: Markdown, HTML, and JSON reports
- **Executive Summaries**: Non-technical overviews for stakeholders
- **Technical Deep-Dives**: Detailed findings with evidence and remediation steps
- **AI Decision Traces**: Full transparency into AI reasoning process

### ⚡ Performance & Efficiency

- **Asynchronous Execution**: Parallel tool execution for faster assessments
- **Workflow Automation**: Predefined workflows (Recon, Web, Network, Autonomous)
- **Customizable**: Create custom tools and workflows via simple YAML/Python

---

## 📋 Prerequisites

### Required

- **Python 3.11 or higher** ([Download](https://www.python.org/downloads/))
- **Google Gemini API Key** ([Get Free API Key](https://makersuite.google.com/app/apikey))
- **Git** (for cloning repository)

### Optional Tools (for full functionality)

Guardian can intelligently use these tools if installed:

| Tool | Purpose | Installation |
|------|---------|--------------|
| **nmap** | Port scanning | `apt install nmap` / `choco install nmap` |
| **masscan** | Ultra-fast scan | `apt install masscan` / Build from source |
| **httpx** | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **subfinder** | Subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **amass** | Network mapping | `go install github.com/owasp-amass/amass/v4/...@master` |
| **nuclei** | Vuln scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **whatweb** | Tech fingerprint | `gem install whatweb` / `apt install whatweb` |
| **wafw00f** | WAF detection | `pip install wafw00f` |
| **nikto** | Web vuln scan | `apt install nikto` |
| **sqlmap** | SQL injection | `pip install sqlmap` / `apt install sqlmap` |
| **wpscan** | WordPress scan | `gem install wpscan` |
| **testssl** | SSL/TLS testing | Download from [testssl.sh](https://testssl.sh/) |
| **sslyze** | SSL/TLS analysis | `pip install sslyze` |
| **gobuster** | Directory brute | `go install github.com/OJ/gobuster/v3@latest` |
| **ffuf** | Web fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| **arjun** | Parameter discovery | `pip install arjun` |
| **xsstrike** | Advanced XSS | `git clone ...` |
| **gitleaks** | Secret scanning | `go install github.com/zricethezav/gitleaks/v8@latest` |
| **cmseek** | CMS detection | `pip install cmseek` |
| **dnsrecon** | DNS enumeration | `pip install dnsrecon` |

> **Note**: Guardian works without external tools but with limited scanning capabilities. The AI will adapt based on available tools.

---

## 🚀 Installation

### Option 1: Docker (Recommended - All Tools Included) 🐳

**Easiest and fastest way to get started with all 15 security tools pre-installed!**

```bash
# Clone repository
git clone https://github.com/zakirkun/guardian-cli.git
cd guardian-cli

# Create .env file with your API key
echo "GOOGLE_API_KEY=your_api_key_here" > .env

# Build Docker image (one-time, ~5 minutes)
docker-compose build

# Run Guardian
docker-compose run --rm guardian recon --domain example.com
```

**Benefits:**
- ✅ All 15 tools pre-installed (nmap, httpx, nuclei, sqlmap, etc.)
- ✅ No manual tool installation required
- ✅ Consistent environment across all systems
- ✅ Isolated and secure

**See [Docker Guide](docs/DOCKER.md) for advanced usage.**

---

### Option 2: Local Installation (Customizable)

#### Step 1: Clone Repository

```bash
git clone https://github.com/zakirkun/guardian-cli.git
cd guardian-cli
```

#### Step 2: Set Up Python Environment

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -e .
```

#### Step 3: Initialize Configuration

```bash
# Linux/macOS
python -m cli.main init

# Windows
python -m cli.main init
# or use the batch launcher
.\guardian.bat init
```

During initialization, you'll be prompted for your Gemini API key. Alternatively, create a `.env` file:

```bash
echo "GOOGLE_API_KEY=your_api_key_here" > .env
```

---

## 🎯 Quick Start

### Basic Commands

```bash
# List available workflows
python -m cli.main workflow list

# Dry run (see execution plan without running)
python -m cli.main recon --domain example.com --dry-run
```

### Example Usage Scenarios

#### 1. Quick Web Application Scan
```bash
# Fast security check of a web application
python -m cli.main workflow run --name web --target https://example.com
```

#### 2. Comprehensive Network Assessment
```bash
# Full network penetration test
python -m cli.main workflow run --name network --target 192.168.1.0/24
```

#### 3. Subdomain Reconnaissance
```bash
# Discover and analyze subdomains
python -m cli.main recon --domain example.com
```

#### 4. Autonomous AI-Driven Test
```bash
# Let AI decide each step dynamically
python -m cli.main workflow run --name autonomous --target example.com
```

#### 5. Generate Professional Report
```bash
# Create HTML report from previous scan
python -m cli.main report --session 20251222_120000 --format html
```

#### 6. Explain AI Decisions
```bash
# View AI decision-making process
python -m cli.main ai --last
```

> **Windows Users**: Use `python -m cli.main` or `.\guardian.bat` instead of `guardian`

---

## 📖 Documentation

### User Guides
- **[Quick Start Guide](QUICKSTART.md)** - Get up and running in 5 minutes
- **[Docker Deployment Guide](docs/DOCKER.md)** - Run Guardian with Docker (recommended)
- **[Command Reference](docs/)** - Detailed documentation for all commands
- **[Configuration Guide](config/guardian.yaml)** - Customize Guardian's behavior

### Developer Guides
- **[Creating Custom Tools](docs/TOOLS_DEVELOPMENT_GUIDE.md)** - Build your own tool integrations
- **[Workflow Development](docs/WORKFLOW_GUIDE.md)** - Create custom testing workflows
- **[Available Tools](tools/README.md)** - Overview of integrated tools

### Architecture
- **Multi-Agent System**: Planner → Tool Selector → Analyst → Reporter
- **AI-Driven**: Google Gemini for strategic decision-making
- **Modular**: Easy to extend with new tools and workflows

---

## 🏗️ Project Structure

```
guardian-cli/
├── ai/                    # AI integration (Gemini client, prompts)
├── cli/                   # Command-line interface
│   └── commands/         # CLI commands (init, scan, recon, etc.)
├── core/                  # Core agent system
│   ├── agent.py          # Base agent
│   ├── planner.py        # Planner agent
│   ├── tool_agent.py     # Tool selection agent
│   ├── analyst_agent.py  # Analysis agent
│   ├── reporter_agent.py # Reporting agent
│   ├── memory.py         # State management
│   └── workflow.py       # Workflow orchestration
├── tools/                 # Pentesting tool wrappers
│   ├── nmap.py           # Nmap integration
│   ├── masscan.py        # Masscan integration
│   ├── httpx.py          # httpx integration
│   ├── subfinder.py      # Subfinder integration
│   ├── amass.py          # Amass integration
│   ├── nuclei.py         # Nuclei integration
│   ├── sqlmap.py         # SQLMap integration
│   ├── wpscan.py         # WPScan integration
│   ├── whatweb.py        # WhatWeb integration
│   ├── wafw00f.py        # Wafw00f integration
│   ├── nikto.py          # Nikto integration
│   ├── testssl.py        # TestSSL integration
│   ├── sslyze.py         # SSLyze integration
│   ├── gobuster.py       # Gobuster integration
│   ├── ffuf.py           # FFuf integration
│   └── ...               # 15 tools total
├── workflows/             # Workflow definitions (YAML)
├── utils/                 # Utilities (logging, validation)
├── config/                # Configuration files
├── docs/                  # Documentation
└── reports/               # Generated reports
```

---

## 🔧 Configuration

Edit `config/guardian.yaml` to customize:

```yaml
ai:
  provider: gemini
  model: gemini-1.5-pro
  temperature: 0.2

pentest:
  safe_mode: true              # Prevent destructive actions
  require_confirmation: true   # Confirm before each step
  max_parallel_tools: 3        # Concurrent tool execution

scope:
  blacklist:                   # Never scan these
    - 127.0.0.0/8
    - 10.0.0.0/8
```

---

## 🤝 Contributing

We welcome contributions! Here's how:

### Setting Up Development Environment

```bash
# Fork and clone
git clone https://github.com/zakirkun/guardian-cli.git
cd guardian-cli

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Format code
black .
```

### Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Areas for Contribution

- 🛠️ **New Tool Integrations** - Add more security tools
- 🔄 **Custom Workflows** - Share your workflow templates
- 🐛 **Bug Fixes** - Report and fix issues
- 📚 **Documentation** - Improve guides and examples
- 🧪 **Testing** - Expand test coverage

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 📊 Roadmap

- [ ] Web Dashboard for visualization
- [ ] PostgreSQL backend for multi-session tracking
- [ ] MITRE ATT&CK mapping for findings
- [ ] Plugin system for custom modules
- [ ] Integration with CI/CD pipelines
- [ ] Additional AI models support (Claude, GPT-4)
- [ ] Mobile app for on-the-go assessments

---

## 🐛 Troubleshooting

### Common Issues

**Import Errors**
```bash
# Reinstall dependencies
pip install -e . --force-reinstall
```

**API Rate Limits**
- Free tier: 2 requests/minute
- Switch to paid tier or implement request throttling
- Configure in `config/guardian.yaml`: `ai.rate_limit: 60`

**Tool Not Found**
```bash
# Check tool availability
which nmap
which httpx

# Install missing tools (see Prerequisites)
```

**Windows Command Not Found**
```powershell
# Use full command
python -m cli.main --help

# Or use batch launcher
.\guardian.bat --help
```

For more help, [open an issue](https://github.com/zakirkun/guardian-cli/issues).

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Guardian Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 🙏 Acknowledgments

- **Google Gemini** - AI capabilities
- **LangChain** - AI orchestration framework
- **ProjectDiscovery** - Open-source security tools (httpx, subfinder, nuclei)
- **Nmap** - Network exploration and security auditing
- **The Security Community** - Tool developers and researchers

---

## 📞 Support & Contact

- **GitHub Issues**: [Report bugs or request features](https://github.com/zakirkun/guardian-cli/issues)
- **Discussions**: [Join community discussions](https://github.com/zakirkun/guardian-cli/discussions)
- **Documentation**: [Read the docs](docs/)
- **Security**: Report vulnerabilities privately to security@example.com

---

## ⭐ Star History

If you find Guardian useful, please consider giving it a star! ⭐

---

<div align="center">

**Guardian** - Intelligent, Ethical, Automated Penetration Testing

Made with ❤️ by the Security Community

[⬆ Back to Top](#-guardian)

</div>
