# 🔐 Guardian Enterprise

### AI-Powered Penetration Testing Automation Platform

**Guardian Enterprise** is an AI-powered penetration testing automation framework designed for internal security teams. It combines modern LLM providers with industry-standard security tools to deliver intelligent, automated security assessments.

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites

- **Kali Linux** (preferred) or **macOS** (secondary support)
- **Python 3.11+**
- **Git**
- **Container Runtime**: Docker (Kali Linux) or Podman (macOS) for ZAP scans

### Installation# 1. Clone and setup

```bash
git clone <internal-repo-url>
cd guardian-cli-deluxe
python3 -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate
pip install -e .

# 1. Install security tools (Debian based and MacOS)
./setup.sh 2>&1 | tee setup.log

# 3. Add java on MacOS for burp
brew install java (MacOS)
sudo apt install default-jre

Add java path to .zshrc, .bashrc or .profile (i.e /opt/homebrew/opt/openjdk/bin)

# 4. Initialize Guardian
python -m cli.main init

# 5. Test installation
source venv/bin/activate (always need this before)
python -m cli.main workflow run --name recon --target <approved-test-target>
```

---

## 🔧 Enterprise Configuration

### AI Provider Setup

Configure an AI provider in your `config/guardian.yaml`:

```yaml
# config/guardian.yaml
ai:
  provider: ollama
  model: "llama3.1:8b"
  base_url: "http://127.0.0.1:11434"
```

### Security & Compliance

- **Audit Logging**: All AI decisions and tool executions logged
- **Scope Validation**: Automatic blacklisting prevents unauthorized scanning
- **Safe Mode**: Destructive actions disabled by default
- **Session Tracking**: Complete audit trail for compliance

### Tool Installation

Run the automated setup script:

```bash
./setup.sh 2>&1 | tee setup-tools.log
```

Missing tools will be logged with installation commands.

---

## 📊 Usage Workflows

### Network Assessment

```bash
python -m cli.main workflow run --name network --target <target-ip-or-range>
```

### Web Application Testing

```bash
python -m cli.main workflow run --name web --target https://<target-domain>
```

### Reconnaissance Only

```bash
python -m cli.main workflow run --name recon --target <target>
```

### AI-Driven Autonomous Testing

```bash
python -m cli.main workflow run --name autonomous --target <target>
```

---

## 📋 Reports & Outputs

Each scan generates:

- **HTML Report**: `reports/report_<session>.html`
- **Markdown Report**: `reports/report_<session>.md`
- **Tool Commands**: `reports/payloads_<session>.txt` (for manual verification)
- **Discovered URLs**: `reports/urls_<session>.txt` (for Burp/ZAP import)
- **Session Data**: `reports/session_<session>.json` (full audit trail)

---

## 🛠️ Tool Arsenal

**Core Tools (Always Available):**

- **[nmap](https://nmap.org/)** - Port scanning and service detection
- **[nuclei](https://github.com/projectdiscovery/nuclei)** - Vulnerability scanning (15min timeout)
- **[subfinder](https://github.com/projectdiscovery/subfinder)** - Subdomain enumeration
- **[gospider](https://github.com/jaeles-project/gospider)** - Web crawling (macOS compatible with curl fallback)
- **[gobuster](https://github.com/OJ/gobuster)** / **[ffuf](https://github.com/ffuf/ffuf)** - Directory/file brute forcing
- **[testssl](https://github.com/drwetter/testssl.sh)** - SSL/TLS analysis
- **[gitleaks](https://github.com/zricethezav/gitleaks)** - Secret detection
- **[arjun](https://github.com/s0md3v/Arjun)** - Parameter discovery
- **[xsstrike](https://github.com/s0md3v/XSStrike)** - XSS testing
- **[dnsrecon](https://github.com/darkoperator/dnsrecon)** - DNS enumeration

**Additional Tools** (installed via setup.sh):

- **[httpx](https://github.com/projectdiscovery/httpx)** - HTTP probing (Linux only, gospider fallback on macOS)
- **[katana](https://github.com/projectdiscovery/katana)** - Advanced web crawling (Linux only)
- **[nikto](https://github.com/sullo/nikto)** - Web vulnerability scanner
- **[sqlmap](https://github.com/sqlmapproject/sqlmap)** - SQL injection testing
- **[wpscan](https://github.com/wpscanteam/wpscan)** - WordPress security scanner
- **[sslyze](https://github.com/nabla-c0d3/sslyze)** - SSL/TLS configuration analysis
- **[dnsx](https://github.com/projectdiscovery/dnsx)** - Fast DNS toolkit
- **[hakrawler](https://github.com/hakluke/hakrawler)** - Web crawler
- **[wafw00f](https://github.com/EnableSecurity/wafw00f)** - WAF detection
- **[whatweb](https://github.com/urbanadventurer/WhatWeb)** - Web technology identification
- **[metasploit](https://github.com/rapid7/metasploit-framework)** - Exploitation framework
- **[zap](https://github.com/zaproxy/zaproxy)** - OWASP ZAP (Docker-based)

**Application Security Tools:**

- **[dalfox](https://github.com/hahwul/dalfox)** - Advanced XSS scanner and parameter analysis
- **[commix](https://github.com/commixproject/commix)** - Command injection testing framework
- **[feroxbuster](https://github.com/epi052/feroxbuster)** - Fast API endpoint and content discovery
- **[burp_pro](https://portswigger.net/burp/pro)** - Burp Suite Professional scanner (macOS only)

**Platform Notes:**

- **Kali Linux**: All tools supported
- **macOS**: httpx/katana automatically replaced with gospider + curl fallback, Burp Pro available for professional web app scanning

---

## 🔍 Troubleshooting

### Common Issues

**"Unable to locate credentials"**

Ensure your chosen provider credentials are set in the environment (see `docs/CONFIGURATION.md`).

**Enterprise Authentication**

- **SSO Users**: Authenticate via your identity provider before running Guardian
- **Helper Script**: Use `./scripts/auth-check.sh` to verify authentication status

**Missing Tools**

```bash
# Check what's available
python -m cli.main workflow list
# Install missing tools
./setup.sh
```

**macOS Compatibility**

- httpx/katana automatically skipped on macOS
- gospider with curl fallback used instead

---

## 📞 Internal Support

- **Issues**: Create ticket in internal issue tracker
- **Documentation**: See `docs/` directory
- **Tool Development**: See `docs/TOOLS_DEVELOPMENT_GUIDE.md`

---

## 🔒 Security Notes

- **Authorized Use Only**: Ensure proper authorization before scanning
- **Network Policies**: Verify firewall/proxy compatibility
- **Data Handling**: All scan data stored locally in `reports/`
- **Audit Trail**: Complete logging enabled by default

---

**Guardian Enterprise** - Intelligent Security Assessment for Internal Teams
