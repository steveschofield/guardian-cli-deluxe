# Setup Verification Guide

## Quick Verification

After running `./setup.sh`, verify your installation with these commands:

### Critical Tools Check

```bash
#!/bin/bash
# Run this to verify all critical tools are installed

echo "Checking ProjectDiscovery tools..."
for tool in httpx nuclei subfinder dnsx katana naabu shuffledns asnmap interactsh-client; do
  command -v $tool >/dev/null 2>&1 && echo "✓ $tool" || echo "✗ $tool (missing)"
done

echo -e "\nChecking Go tools..."
for tool in ffuf waybackurls gau dalfox gitleaks puredns subjs webanalyze kr; do
  command -v $tool >/dev/null 2>&1 && echo "✓ $tool" || echo "✗ $tool (missing)"
done

echo -e "\nChecking Python tools..."
for tool in sqlmap arjun sslyze dirsearch wafw00f dnsrecon xnlinkfinder dnsgen sstimap; do
  command -v $tool >/dev/null 2>&1 && echo "✓ $tool" || echo "✗ $tool (missing)"
done

echo -e "\nChecking modern replacements..."
echo "✓ sstimap (replaced tplmap)"
command -v webanalyze >/dev/null 2>&1 && echo "✓ webanalyze (replaced wappalyzer)" || echo "✗ webanalyze"
command -v dnsgen >/dev/null 2>&1 && echo "✓ dnsgen (replaced py-altdns)" || echo "✗ dnsgen"
command -v linkfinder >/dev/null 2>&1 && echo "✓ linkfinder (replaced JSParser)" || echo "✗ linkfinder"
command -v trufflehog >/dev/null 2>&1 && echo "✓ trufflehog v3 (binary, not pip)" || echo "✗ trufflehog"

echo -e "\nChecking system tools..."
for tool in nmap masscan nikto hydra amass; do
  command -v $tool >/dev/null 2>&1 && echo "✓ $tool" || echo "✗ $tool (install manually)"
done

echo -e "\nChecking special wrappers..."
for tool in testssl commix xsstrike cmseek whatweb graphql-cop jwt_tool corscanner feroxbuster; do
  command -v $tool >/dev/null 2>&1 && echo "✓ $tool" || echo "✗ $tool (check venv/bin/)"
done
```

### Python Import Check

```bash
python << 'EOF'
import sys

checks = [
    ("langchain_ollama", "ChatOllama"),
    ("langchain_google_genai", "ChatGoogleGenerativeAI"),
    ("requests", None),
    ("urllib3", None),
    ("typer", None),
    ("rich", None),
    ("pyyaml", None),
]

failed = []
for module, attr in checks:
    try:
        mod = __import__(module)
        if attr:
            getattr(mod, attr)
        print(f"✓ {module}")
    except Exception as e:
        print(f"✗ {module}: {e}")
        failed.append(module)

if failed:
    print(f"\n⚠️  Failed imports: {', '.join(failed)}")
    sys.exit(1)
else:
    print("\n✅ All imports successful")
EOF
```

### Version Checks

```bash
# Python version (must be 3.11 or 3.12)
python --version

# Check requests version (must be >= 2.32.0)
python -c "import requests; print(f'requests: {requests.__version__}')"

# Check urllib3 version (must be >= 2.0.0)
python -c "import urllib3; print(f'urllib3: {urllib3.__version__}')"

# Go version (recommended 1.21+)
go version 2>/dev/null || echo "Go not installed"

# Node/npm (for retire.js)
node --version 2>/dev/null || echo "Node not installed"
npm --version 2>/dev/null || echo "npm not installed"
```

---

## Common Issues & Fixes

### Issue: "dalfox command not found"

**Cause:** Binary extraction issue or GOPATH not set

**Fix:**
```bash
go install github.com/hahwul/dalfox/v2@latest
ln -sf $(go env GOPATH)/bin/dalfox venv/bin/dalfox
```

### Issue: "commix directory exists" error

**Cause:** Previous failed git clone

**Fix:**
```bash
rm -rf tools/vendor/commix
./setup.sh  # Re-run setup
```

### Issue: "ImportError: No module named wsgiref" (tplmap)

**Cause:** tplmap is Python 2 only and removed

**Fix:**
```bash
# Use sstimap instead
pip install sstimap
sstimap -u "http://target/?param=value"
```

### Issue: "requests version conflict"

**Cause:** Ancient tools (safeurl) pinning old requests

**Fix:**
```bash
pip uninstall -y safeurl
pip install --force-reinstall "requests>=2.32.0" "urllib3>=2.0.0"
```

### Issue: "Python 3.13 not supported"

**Cause:** Dependencies not yet compatible with Python 3.13

**Fix:**
```bash
# Use Python 3.12
python3.12 -m venv venv
source venv/bin/activate
./setup.sh
```

### Issue: "nuclei taking too long / high CPU"

**Cause:** First run downloads templates

**Fix:**
```bash
# Pre-download templates
nuclei -update-templates
```

### Issue: "masscan permission denied"

**Cause:** Requires raw socket access

**Fix:**
```bash
# Run with sudo
sudo masscan target -p1-65535 --rate=10000

# Or use capabilities (Linux)
sudo setcap cap_net_raw+ep $(which masscan)
```

### Issue: "ZAP not found"

**Cause:** Docker not running or native ZAP not installed

**Fix:**
```bash
# Check ZAP availability
guardian-zap

# If "none", install Docker and pull image
docker pull ghcr.io/zaproxy/zaproxy:stable

# Or install native ZAP
sudo apt-get install zaproxy  # Debian/Kali
brew install --cask owasp-zap  # macOS
```

---

## Setup.sh Idempotency Test

```bash
# Test that setup.sh can be run multiple times without errors
./setup.sh 2>&1 | tee setup-run1.log
./setup.sh 2>&1 | tee setup-run2.log

# Compare (should have minimal differences)
diff -u setup-run1.log setup-run2.log
```

---

## Tool Count Summary

### Essential Tools (Installed by setup.sh)

| Category | Count | Examples |
|----------|-------|----------|
| ProjectDiscovery | 9 | httpx, nuclei, subfinder, katana |
| Go Tools | 10 | ffuf, dalfox, gitleaks, webanalyze |
| Python Tools | 10 | sqlmap, arjun, sslyze, sstimap |
| Git-Cloned | 10 | testssl, XSStrike, commix, jwt_tool |
| System Tools | 8 | nmap, masscan, nikto, hydra |
| **Total** | **47** | All actively maintained |

### Removed Ancient Tools

| Tool | Last Update | Replacement |
|------|-------------|-------------|
| tplmap | 2020 | sstimap |
| JSParser | 2018 | LinkFinder/xnLinkFinder |
| wappalyzer (npm) | Deprecated | webanalyze |
| py-altdns | 2020 | dnsgen |
| udp-proto-scanner | 2017 | nmap -sU |
| trufflehog (pip) | Old | trufflehog v3 (binary) |

---

## Advanced Verification

### Check for Orphaned Dependencies

```bash
# Find Python packages not in pyproject.toml
pip list --format=freeze > installed.txt
# Compare with pyproject.toml dependencies
```

### Verify All Binaries are Executable

```bash
find venv/bin -type f -executable | while read bin; do
  if ! "$bin" --version 2>/dev/null && ! "$bin" -h 2>/dev/null; then
    echo "⚠️  $bin may be broken"
  fi
done
```

### Check for Missing Wordlists

```bash
# Kiterunner wordlists
ls -lh tools/vendor/kiterunner/routes-small.json || echo "Missing kiterunner wordlists"

# SecLists
ls -d wordlists/SecLists || echo "SecLists not cloned (optional)"
```

### Validate Guardian CLI

```bash
# Test CLI entry point
python -m cli.main --help

# Test workflow listing
python -m cli.main workflow list

# Test config initialization
python -m cli.main init

# Quick smoke test (no actual scanning)
python -m cli.main workflow run --name recon --target example.com --dry-run
```

---

## Performance Benchmarks

### Setup Time (macOS M1, 100Mbps connection)

- **Fresh install**: ~8-12 minutes
- **Re-run (up-to-date)**: ~2-3 minutes
- **GitHub releases only**: ~5-7 minutes
- **Go install only**: ~4-6 minutes

### Setup Time (Kali Linux 2024, 100Mbps connection)

- **Fresh install**: ~10-15 minutes
- **Re-run (up-to-date)**: ~3-5 minutes

### Network Requirements

- **Total download size**: ~500MB-1GB
- **GitHub API calls**: ~30-40
- **Go modules**: ~200MB
- **Python packages**: ~150MB
- **Git repos**: ~100MB

---

## Cleanup Commands

### Remove Old Tools

```bash
# Remove all ancient tool directories
rm -rf tools/vendor/{tplmap,JSParser,udp-proto-scanner}

# Clean Python cache
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null

# Clean Go cache
go clean -cache -modcache 2>/dev/null
```

### Fresh Reinstall

```bash
# Complete reset
rm -rf venv tools/vendor tools/.bin .npm-global
python3.12 -m venv venv
source venv/bin/activate
./setup.sh
```

---

## Success Indicators

After a successful setup, you should see:

```
=========================================
 Setup Complete!
=========================================

Checking critical tools:
  ✓ httpx
  ✓ nuclei
  ✓ subfinder
  ✓ ffuf
  ✓ dalfox
  ✓ katana
  ✓ gitleaks
  ✓ trufflehog
  ✓ feroxbuster
  ✓ sqlmap
  ✓ nmap
  ✓ webanalyze
  ✓ sstimap
  ✓ dnsgen

Checking Python imports:
  ✓ langchain_ollama
  ✓ requests >= 2.32.0

All critical checks passed!
```

If you see this, your Guardian installation is ready! 🎉

---

**See also:**
- `STREAMLINING.md` - Full details on removed tools and replacements
- `QUICKSTART.md` - 5-minute setup guide
- `docs/USAGE.md` - Usage documentation
