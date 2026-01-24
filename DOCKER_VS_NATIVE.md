# Docker vs Native - Quick Reference

## TL;DR

✅ **Use Native Kali + setup.sh** (Recommended)
✅ **Use Docker** for CI/CD, non-Kali systems, or isolated testing

Both have **100% feature parity** as of v3.0.

---

## Quick Comparison Table

| Aspect | Native Kali + setup.sh | Docker Container |
|--------|------------------------|------------------|
| **Tool Coverage** | 100% (55+ tools) | 100% (55+ tools) ✅ PARITY |
| **Installation Time** | 10-20 minutes | 30-60 minutes |
| **Disk Space** | ~7 GB | ~15 GB |
| **Performance** | Native speed | ~5% overhead |
| **Network Access** | Direct | Requires `--net=host` for raw packets |
| **GPU Access** | Direct | Complex passthrough |
| **Updates** | Re-run `./setup.sh` (30s) | Rebuild image (30-60 min) |
| **Idempotency** | ✅ Yes | ⚠️ Requires rebuild |
| **Portability** | Kali only | Any OS with Docker |
| **Isolation** | Shared system | Isolated container |
| **CI/CD Integration** | Manual | Native support |
| **Customization** | Easy (edit setup.sh) | Medium (edit Dockerfile) |

---

## Tool Inventory (Both Have These)

### ✅ SAST/Whitebox Analysis (4 tools)
- Semgrep - Code vulnerability scanner
- Trivy - Dependency CVE + IaC scanner
- TruffleHog - Advanced secret detection
- Gitleaks - Secret scanning

### ✅ ProjectDiscovery Suite (9 tools)
- httpx, nuclei, subfinder
- dnsx, katana, naabu
- shuffledns, asnmap, interactsh-client

### ✅ Go Tools (8 tools)
- ffuf, waybackurls, gau
- dalfox, gitleaks, puredns
- subjs, webanalyze, god-eye

### ✅ Rust Tools (1 tool)
- feroxbuster

### ✅ Python Security Tools (10+ tools)
- arjun, dirsearch, schemathesis
- wafw00f, sqlmap, sslyze
- dnsrecon, xnlinkfinder, dnsgen
- sstimap, paramspider

### ✅ Git-Cloned Tools (10+ tools)
- XSStrike, CMSeeK, testssl.sh
- commix, graphql-cop, jwt_tool
- SSTImap, CORScanner
- LinkFinder, ParamSpider

### ✅ System Tools (10+ tools)
- nmap, masscan, amass
- nikto, wpscan, hydra
- enum4linux-ng, metasploit
- sqlmap, nuclei

### ✅ npm Tools (1 tool)
- retire.js

### ✅ Wordlists (2 collections)
- SecLists
- Kiterunner API routes

### ✅ Smart Wrappers (2 tools)
- guardian-portscan (masscan → nmap)
- guardian-zap (Docker/native detection)

### ✅ LangChain Ecosystem
- langchain, langchain-core
- langchain-community, langchain-ollama
- langsmith

---

## When to Use Native Kali

### ✅ Best For:
1. **Primary pentest workstation**
2. **Active penetration testing**
3. **Frequent tool updates**
4. **Hardware-dependent attacks** (GPU cracking, wireless)
5. **Raw network access** (SYN scans, masscan)
6. **Limited disk space**
7. **Performance-critical operations**

### Installation:
```bash
git clone https://github.com/yourusername/guardian-cli-deluxe.git
cd guardian-cli-deluxe
python3.12 -m venv venv
source venv/bin/activate
./setup.sh
```

---

## When to Use Docker

### ✅ Best For:
1. **CI/CD pipelines** (GitHub Actions, GitLab CI, Jenkins)
2. **Non-Kali systems** (Ubuntu, macOS, Windows)
3. **Isolated testing environments**
4. **Multi-tenant setups**
5. **Reproducible builds**
6. **Quick demos/training**
7. **Temporary engagement containers**

### Installation:
```bash
git clone https://github.com/yourusername/guardian-cli-deluxe.git
cd guardian-cli-deluxe
docker build -f Dockerfile.kali -t guardian-cli-deluxe:latest .
docker run -it --rm -e ANTHROPIC_API_KEY="sk-ant-..." guardian-cli-deluxe:latest
```

---

## Command Equivalents

### Native Kali
```bash
# Activate environment
source venv/bin/activate

# Run workflow
python -m cli.main workflow run --name web --target https://example.com

# SAST + DAST
python -m cli.main workflow run \
  --name web \
  --target https://example.com \
  --source /path/to/code

# Update tools
./setup.sh  # Idempotent, takes 30 seconds
```

### Docker
```bash
# Run workflow
docker run -it --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v $(pwd)/reports:/guardian/reports \
  guardian-cli-deluxe:latest \
  python -m cli.main workflow run --name web --target https://example.com

# SAST + DAST
docker run -it --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v $(pwd)/reports:/guardian/reports \
  -v $(pwd)/source:/guardian/source \
  guardian-cli-deluxe:latest \
  python -m cli.main workflow run \
    --name web \
    --target https://example.com \
    --source /guardian/source

# Update tools
docker build --no-cache -f Dockerfile.kali -t guardian-cli-deluxe:latest .  # 30-60 min
```

---

## Resource Usage

### Native Kali
- **Disk:** ~7 GB
- **RAM:** ~2 GB (during scans)
- **CPU:** Depends on workflow
- **Install Time:** 10-20 minutes

### Docker
- **Disk:** ~15 GB (image + layers)
- **RAM:** ~2.5 GB (container + overhead)
- **CPU:** Depends on workflow
- **Build Time:** 30-60 minutes

---

## Network Scanning Differences

### Native Kali
```bash
# Full access to raw sockets
sudo nmap -sS -sV 192.168.1.0/24

# Masscan works directly
sudo masscan 192.168.1.0/24 -p1-65535 --rate=10000
```

### Docker
```bash
# Requires host network mode for raw packets
docker run -it --rm --net=host guardian-cli-deluxe:latest \
  nmap -sS -sV 192.168.1.0/24

# Masscan needs capabilities
docker run -it --rm \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  guardian-cli-deluxe:latest \
  masscan 192.168.1.0/24 -p1-65535 --rate=10000
```

---

## Update Strategy

### Native Kali (Easy)
```bash
# Update tools in 30 seconds
source venv/bin/activate
./setup.sh  # Idempotent - only updates missing/outdated tools

# Update individual tool
source venv/bin/activate
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Docker (Slower)
```bash
# Full rebuild required (30-60 minutes)
docker build --no-cache -f Dockerfile.kali -t guardian-cli-deluxe:latest .

# Can't easily update individual tools
# (Would need to docker exec into running container, but changes are lost on restart)
```

---

## CI/CD Examples

### GitHub Actions (Docker)
```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: docker build -f Dockerfile.kali -t guardian .
      - run: |
          docker run --rm \
            -e ANTHROPIC_API_KEY=${{ secrets.ANTHROPIC_API_KEY }} \
            -v $PWD/reports:/guardian/reports \
            guardian python -m cli.main workflow run --name web --target $TARGET
```

### GitLab CI (Docker)
```yaml
security-scan:
  image: guardian-cli-deluxe:latest
  script:
    - python -m cli.main workflow run --name web --target $TARGET
  artifacts:
    paths:
      - reports/
```

### Native (Jenkins)
```groovy
stage('Security Scan') {
    steps {
        sh '''
            source venv/bin/activate
            python -m cli.main workflow run --name web --target ${TARGET}
        '''
    }
}
```

---

## Pros & Cons Summary

### Native Kali

**Pros:**
- ✅ Faster installation (10-20 min)
- ✅ Easier updates (30 seconds)
- ✅ Better performance (no container overhead)
- ✅ Direct hardware access
- ✅ Full network capabilities
- ✅ Less disk space (~7 GB)
- ✅ Python venv isolation

**Cons:**
- ❌ Kali Linux only
- ❌ Modifies host system
- ❌ Less portable
- ❌ Manual setup in CI/CD

### Docker

**Pros:**
- ✅ Runs on any OS
- ✅ Isolated environment
- ✅ Reproducible builds
- ✅ Native CI/CD support
- ✅ Easy multi-tenant
- ✅ Quick teardown

**Cons:**
- ❌ Slower build (30-60 min)
- ❌ Harder to update (rebuild required)
- ❌ More disk space (~15 GB)
- ❌ Network limitations (needs `--net=host`)
- ❌ No venv isolation (system-wide pip)
- ❌ ~5% performance overhead

---

## Recommendation Flow Chart

```
Are you on Kali Linux?
├─ Yes → Use Native setup.sh ✅
└─ No → Do you need maximum performance?
    ├─ Yes → Install Kali VM, then use Native setup.sh
    └─ No → Is this for CI/CD?
        ├─ Yes → Use Docker ✅
        └─ No → Is this for active pentesting?
            ├─ Yes → Install Kali, use Native setup.sh
            └─ No → Use Docker ✅
```

---

## Final Recommendation

### 🏆 Primary Pentest Workstation
**Use Native Kali + setup.sh**

### 🤖 CI/CD Automation
**Use Docker**

### 💻 Non-Kali Systems (Ubuntu/macOS/Windows)
**Use Docker**

### 🎓 Training/Demos
**Use Docker**

### 🔥 Active Engagement
**Use Native Kali + setup.sh**

---

## Both Have 100% Parity

No matter which you choose, you get:
- ✅ All 55+ security tools
- ✅ SAST capabilities (Semgrep, Trivy)
- ✅ DAST capabilities (Nuclei, SQLMap, etc.)
- ✅ SAST+DAST correlation
- ✅ LangChain + AI agents
- ✅ Fixed dependencies
- ✅ Wordlists (SecLists, Kiterunner)
- ✅ Smart wrappers

**Choose based on your environment, not on features!**
