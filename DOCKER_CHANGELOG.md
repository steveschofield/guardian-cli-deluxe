# Docker Container Update - Changelog

## Summary

Updated `Dockerfile.kali` from v2.0 → **v3.0** to achieve **100% parity** with `setup.sh`.

---

## Changes Made

### 🎯 Added SAST/Whitebox Analysis Tools (CRITICAL)

**Previously Missing:**
- ❌ Semgrep (code vulnerability scanner)
- ❌ Trivy (dependency CVE + IaC scanner)
- ❌ TruffleHog (advanced secret scanner - v3 binary)

**Now Included:**
- ✅ Semgrep installed via pip with version verification
- ✅ Trivy installed via official apt repository
- ✅ TruffleHog installed via official installer script
- ✅ Gitleaks installed via go install (was already in Go tools)

---

### 🔧 Added Missing Go Tools

**Previously Missing:**
- ❌ waybackurls, gau, subjs
- ❌ gitleaks, puredns
- ❌ webanalyze (replaced deprecated wappalyzer)
- ❌ god-eye (comprehensive recon)
- ❌ ProjectDiscovery tools: httpx, dnsx, katana, naabu, shuffledns, asnmap, interactsh-client

**Now Included:**
- ✅ All ProjectDiscovery tools via `go install`
- ✅ All Go security tools (ffuf, dalfox, waybackurls, gau, etc.)
- ✅ god-eye compiled from source
- ✅ Nuclei templates updated

---

### 🐍 Added Missing Python Tools

**Previously Missing:**
- ❌ arjun, dirsearch, schemathesis
- ❌ wafw00f, dnsgen, xnlinkfinder
- ❌ sstimap (tplmap replacement)

**Now Included:**
- ✅ All Python security tools via pip
- ✅ arjun, dirsearch, schemathesis, wafw00f
- ✅ dnsgen (replaces py-altdns)
- ✅ sstimap (pip + git clone for latest)
- ✅ xnlinkfinder, paramspider

---

### 📦 Added Missing Git-Cloned Tools

**Previously Missing:**
- ❌ testssl.sh (latest version)
- ❌ cmseek, graphql-cop, jwt_tool
- ❌ sstimap, corscanner, linkfinder
- ❌ paramspider

**Now Included:**
- ✅ testssl.sh cloned (in addition to apt version)
- ✅ XSStrike, CMSeeK, commix
- ✅ graphql-cop (with simplejson, skipping broken requirements.txt)
- ✅ jwt_tool, SSTImap
- ✅ CORScanner, LinkFinder
- ✅ ParamSpider

---

### 🦀 Added Rust Tools

**Previously Missing:**
- ❌ feroxbuster (fast directory brute-forcer)

**Now Included:**
- ✅ feroxbuster compiled via cargo
- ✅ Installed to /usr/local/bin with version verification

---

### 📚 Added Wordlists

**Previously Missing:**
- ❌ SecLists (comprehensive wordlist collection)
- ❌ Kiterunner API routes wordlist

**Now Included:**
- ✅ SecLists cloned to /opt/wordlists/SecLists
- ✅ Kiterunner routes-small.json downloaded

---

### 🔗 Fixed Python Dependencies (CRITICAL)

**Previously:**
- ❌ Generic pip installs without version pinning
- ❌ Missing LangChain ecosystem packages
- ❌ Potential dependency conflicts

**Now Fixed:**
- ✅ Uninstall old incompatible packages before installing
- ✅ Install exact versions: requests>=2.32.0, urllib3>=2.0.0
- ✅ Install LangChain ecosystem: langchain-ollama, langsmith
- ✅ Force-reinstall correct versions after Guardian install

---

### 🚀 Added Smart Wrappers & Enhancements

**Previously Missing:**
- ❌ ZAP hybrid mode detection
- ❌ Smart port scanner wrapper
- ❌ Guardian-specific utilities

**Now Included:**
- ✅ `guardian-zap` - Detects Docker/native ZAP availability
- ✅ `zap-docker` - Wrapper for ZAP Docker container
- ✅ `guardian-portscan` - Smart masscan → nmap pipeline

---

### ✅ Added Comprehensive Verification

**Previously:**
- ❌ Basic tool verification (nmap, nuclei, sqlmap)
- ❌ No SAST tool verification
- ❌ No Python package version checks

**Now Included:**
- ✅ Verify SAST tools (semgrep, trivy, trufflehog, gitleaks)
- ✅ Verify ProjectDiscovery tools (httpx, nuclei, subfinder, etc.)
- ✅ Verify Go tools (ffuf, dalfox, waybackurls, gau, etc.)
- ✅ Verify Rust tools (feroxbuster)
- ✅ Verify Python tools (arjun, dirsearch, wafw00f, etc.)
- ✅ Verify git-cloned tools (xsstrike, cmseek, jwt_tool, etc.)
- ✅ Verify npm tools (retire)
- ✅ Verify Guardian wrappers (guardian-portscan, guardian-zap)
- ✅ Verify Python packages (langchain_ollama, langsmith, requests>=2.32.0)
- ✅ **Build fails if any critical tool is missing**

---

### 🎨 Updated Entrypoint Banner

**Previously:**
```
Guardian CLI Deluxe - Kali Linux Container
AI-Powered Penetration Testing Framework
```

**Now:**
```
Guardian CLI Deluxe - Kali Linux Container v3.0
AI-Powered Penetration Testing Framework
Full Parity with Native setup.sh
```

**Added:**
- ✅ Tool categories in welcome message
- ✅ Whitebox analysis usage example
- ✅ Quick start examples

---

### 📋 Updated Build Messages

**Added:**
- ✅ Comprehensive build completion summary
- ✅ Tool category breakdown
- ✅ Parity confirmation message

```
╔════════════════════════════════════════════════════════════════╗
║  Guardian CLI Deluxe v3.0 Docker Image Build Complete         ║
║                                                                ║
║  ✓ SAST Tools (Semgrep, Trivy, TruffleHog, Gitleaks)         ║
║  ✓ ProjectDiscovery Suite (httpx, nuclei, subfinder, etc.)   ║
║  ✓ Go Tools (ffuf, dalfox, gau, waybackurls, etc.)           ║
║  ✓ Rust Tools (feroxbuster)                                  ║
║  ✓ Python Tools (arjun, dirsearch, sqlmap, etc.)             ║
║  ✓ Git-cloned Tools (xsstrike, cmseek, jwt_tool, etc.)       ║
║  ✓ Wordlists (SecLists, Kiterunner)                          ║
║  ✓ LangChain Ecosystem (langchain-ollama, langsmith)         ║
║  ✓ Fixed Dependencies (requests>=2.32.0, urllib3>=2.0.0)     ║
║  ✓ Smart Wrappers (guardian-portscan, guardian-zap)          ║
║                                                                ║
║  Full parity with native Kali setup.sh achieved!              ║
╚════════════════════════════════════════════════════════════════╝
```

---

## File Changes

### Modified Files
1. **Dockerfile.kali** - Complete rewrite from 354 lines → 652 lines
   - Added 16 stages (was 8 stages)
   - Added SAST tools stage
   - Added comprehensive verification stage
   - Added dependency fixing stage

### New Files
2. **DOCKER.md** - Comprehensive Docker usage guide
   - Quick start instructions
   - Native vs Docker comparison
   - Tool coverage comparison
   - CI/CD integration examples
   - Troubleshooting guide

3. **DOCKER_CHANGELOG.md** - This file

---

## Testing Recommendations

### Build the Image
```bash
docker build -f Dockerfile.kali -t guardian-cli-deluxe:v3.0 .
```

### Verify SAST Tools
```bash
docker run -it --rm guardian-cli-deluxe:v3.0 semgrep --version
docker run -it --rm guardian-cli-deluxe:v3.0 trivy --version
docker run -it --rm guardian-cli-deluxe:v3.0 trufflehog --version
docker run -it --rm guardian-cli-deluxe:v3.0 gitleaks version
```

### Verify ProjectDiscovery Tools
```bash
docker run -it --rm guardian-cli-deluxe:v3.0 httpx -version
docker run -it --rm guardian-cli-deluxe:v3.0 nuclei -version
docker run -it --rm guardian-cli-deluxe:v3.0 subfinder -version
```

### Verify Python Packages
```bash
docker run -it --rm guardian-cli-deluxe:v3.0 \
  python3 -c "from langchain_ollama import ChatOllama; print('✓')"

docker run -it --rm guardian-cli-deluxe:v3.0 \
  python3 -c "import requests; assert requests.__version__ >= '2.32.0'; print('✓')"
```

### Run a Workflow
```bash
docker run -it --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v $(pwd)/reports:/guardian/reports \
  guardian-cli-deluxe:v3.0 \
  python -m cli.main workflow list
```

---

## Breaking Changes

### None!

This is a purely additive update. All existing functionality is preserved.

---

## Migration Guide

### From v2.0 to v3.0

No migration needed - just rebuild:

```bash
# Pull latest code
git pull

# Rebuild image
docker build -f Dockerfile.kali -t guardian-cli-deluxe:latest .

# Verify tools
docker run -it --rm guardian-cli-deluxe:latest bash
```

### From Native setup.sh to Docker

```bash
# Build Docker image
docker build -f Dockerfile.kali -t guardian-cli-deluxe:latest .

# Run with same commands
docker run -it --rm \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -v $(pwd)/reports:/guardian/reports \
  guardian-cli-deluxe:latest \
  python -m cli.main workflow run --name web --target https://example.com
```

---

## Next Steps

1. ✅ **Test the build** - Verify all tools install correctly
2. ✅ **Run workflows** - Test SAST + DAST correlation
3. ✅ **Update CI/CD** - Use v3.0 in automated pipelines
4. ✅ **Document usage** - Share DOCKER.md with team

---

## Credits

- All tools match `setup.sh` line-by-line
- Dependency versions from setup.sh:313-322
- Verification logic from setup.sh:928-984
- Smart wrappers from setup.sh:846-892

---

## Support

If you encounter any issues:

1. Check `DOCKER.md` troubleshooting section
2. Compare with `setup.sh` to ensure parity
3. Open GitHub issue with build logs

---

## Conclusion

**Docker container now has 100% feature parity with native setup.sh!** 🎉

All missing tools, dependencies, and enhancements have been added.

Native Kali + setup.sh is still recommended for:
- Active pentesting (performance)
- Frequent tool updates (idempotency)
- Hardware access (GPU, network adapters)

Docker is perfect for:
- CI/CD automation
- Non-Kali systems
- Isolated environments
- Reproducible builds
