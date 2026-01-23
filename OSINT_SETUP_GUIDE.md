# OSINT Enrichment Setup Guide

## Overview

Guardian now integrates three powerful OSINT (Open Source Intelligence) sources to enrich vulnerability findings with real-world threat intelligence:

1. **CISA KEV** - Known Exploited Vulnerabilities actively exploited in the wild
2. **GitHub PoCs** - Community exploit proof-of-concept repositories
3. **Vulners API** - Aggregated exploit intelligence from 100+ sources

## Quick Start (5 Minutes)

### 1. Enable CISA KEV (FREE - No Setup Required)

CISA KEV works out-of-the-box with no configuration needed!

```yaml
# config/guardian.yaml (already configured)
osint:
  enabled: true
  sources:
    cisa_kev:
      enabled: true  # ✅ Already enabled by default
```

**Test it:**
```bash
python -m cli.main workflow run --name network --target vulnerable-system

# Check report for KEV warnings:
grep -A 5 "CISA KEV" reports/*/report_*.md
```

### 2. Enable GitHub PoC Search (FREE - Optional Token)

**Without Token** (60 requests/hour):
```yaml
# config/guardian.yaml
osint:
  sources:
    github:
      enabled: true  # ✅ Works without token
      token: ""      # Leave empty
```

**With Token** (5,000 requests/hour - Recommended):

1. Create GitHub Personal Access Token:
   - Go to: https://github.com/settings/tokens
   - Click "Generate new token (classic)"
   - Select scopes: `public_repo` (read-only)
   - Generate token and copy it

2. Add to config:
   ```yaml
   # config/guardian.yaml
   osint:
     sources:
       github:
         enabled: true
         token: "ghp_your_token_here"  # Paste your token
         min_stars: 10
         max_results: 5
   ```

**Test it:**
```bash
python -m cli.main workflow run --name network --target vulnerable-system

# Check report for GitHub PoCs:
grep -A 3 "GitHub PoCs" reports/*/report_*.md
```

### 3. Enable Vulners API (FREE tier: 100 requests/day)

1. Get Vulners API Key:
   - Go to: https://vulners.com/userinfo
   - Sign up (free)
   - Copy your API key

2. Add to config:
   ```yaml
   # config/guardian.yaml
   osint:
     sources:
       vulners:
         enabled: true
         api_key: "YOUR_VULNERS_API_KEY_HERE"
   ```

**Test it:**
```bash
python -m cli.main workflow run --name network --target vulnerable-system

# Check report for Vulners data:
grep -A 2 "Vulners AI Risk Score" reports/*/report_*.md
```

## Complete Configuration Example

```yaml
# config/guardian.yaml
osint:
  enabled: true
  cache_ttl_hours: 24

  sources:
    # CISA KEV (FREE - No setup required)
    cisa_kev:
      enabled: true
      cache_ttl_hours: 24
      priority_flag: true

    # GitHub (FREE - Optional token for higher rate limits)
    github:
      enabled: true
      token: "ghp_xxxxxxxxxxxxxxxxxxxx"  # Optional: 5000/hour vs 60/hour
      min_stars: 10
      max_results: 5
      timeout: 10

    # Vulners (FREE tier: 100 req/day)
    vulners:
      enabled: true
      api_key: "XXXXXXXXXXXXXXXXXXXXXXXX"  # Required
      timeout: 10
```

## Example Report Output

### Before OSINT Integration
```markdown
### MS17-010 Remote Code Execution (CRITICAL)

* **CVE IDs:** CVE-2017-0143, CVE-2017-0144
* **Known Metasploit Modules:** MS17-010 EternalBlue
* **Known Exploit-DB:** EDB-42315
```

### After OSINT Integration
```markdown
### MS17-010 Remote Code Execution (CRITICAL) 🔥

* **⚠️ CRITICAL WARNING: This vulnerability is actively exploited in the wild (CISA KEV)**
  - **CISA KEV Status:** CONFIRMED - Actively exploited
  - **Ransomware Association:** WannaCry, NotPetya
  - **Government Deadline:** 2022-05-03
  - **Required Action:** Apply Microsoft security updates immediately

* **Exploitation Information:**
  - **CVE IDs:** CVE-2017-0143, CVE-2017-0144, CVE-2017-0145
  - **Known Metasploit Modules:** MS17-010 EternalBlue DOUBLEPULSAR
  - **Known Exploit-DB:** EDB-42315, EDB-42031
  - **GitHub PoCs (12 repositories):**
    * [worawit/MS17-010](https://github.com/worawit/MS17-010) ⭐ 2,145 stars
    * [3ndG4me/AutoBlue-MS17-010](https://github.com/3ndG4me/AutoBlue-MS17-010) ⭐ 1,823 stars
  - **Vulners AI Risk Score:** 9.5/10
  - **Total Exploits (all sources):** 18

| Severity | Finding | CVSS | Exploit Status |
|----------|---------|------|----------------|
| CRITICAL | MS17-010 RCE | 9.3 | 🔥🔥 CISA KEV - IN THE WILD |
```

## Features

### 1. CISA KEV Integration

**What it provides:**
- ✅ Identifies vulnerabilities actively exploited in the wild
- ✅ Government-mandated remediation deadlines
- ✅ Ransomware campaign associations
- ✅ Required remediation actions

**Example KEV Entry:**
```
🔥 CISA KEV: CVE-2017-0143 - ACTIVELY EXPLOITED IN THE WILD
   ⚠️ RANSOMWARE ASSOCIATED
   Required Action: Apply Microsoft updates per vendor instructions
   Government Deadline: 2022-05-03
```

### 2. GitHub PoC Search

**What it provides:**
- ✅ Community exploit repositories
- ✅ Star counts (popularity/reliability indicator)
- ✅ Active maintenance status
- ✅ Multiple implementation examples

**Example GitHub Entry:**
```
GitHub PoCs (12 repositories):
  - worawit/MS17-010 ⭐ 2,145 stars - https://github.com/worawit/MS17-010
  - 3ndG4me/AutoBlue-MS17-010 ⭐ 1,823 stars - https://github.com/3ndG4me/AutoBlue-MS17-010
```

### 3. Vulners API

**What it provides:**
- ✅ Aggregates 100+ exploit sources
- ✅ AI-based risk scoring (0-10)
- ✅ Total exploit count across all sources
- ✅ Additional references (PacketStorm, etc.)

**Example Vulners Entry:**
```
Vulners AI Risk Score: 9.5/10
Total Exploits (all sources): 18
```

## Rate Limits & Costs

| Source | Free Tier | Cost | Recommendation |
|--------|-----------|------|----------------|
| **CISA KEV** | Unlimited | FREE | ✅ Always enable |
| **GitHub** | 60/hour (5000 with token) | FREE | ✅ Use with token |
| **Vulners** | 100/day | FREE | ✅ Enable for critical scans |

**For heavy usage:**
- Vulners paid tier: $99/mo for 10,000 requests/day

## Usage Patterns

### Standard Scan (All Sources Enabled)
```bash
python -m cli.main workflow run --name network --target 192.168.1.0/24
```

**What happens:**
1. Tools discover vulnerabilities with CVEs
2. CISA KEV checks if CVEs are actively exploited ⚡ INSTANT
3. GitHub searches for exploit PoCs (1-2 seconds per CVE)
4. Vulners aggregates all exploit intelligence (1-2 seconds per CVE)
5. Report includes comprehensive threat context

### Quick Scan (CISA KEV Only)
```yaml
# config/guardian.yaml - For speed
osint:
  sources:
    cisa_kev:
      enabled: true
    github:
      enabled: false  # Disable for speed
    vulners:
      enabled: false  # Disable for speed
```

### Deep Intelligence Scan (All Sources + No Cache)
```yaml
# config/guardian.yaml
osint:
  cache_ttl_hours: 0  # Force fresh lookups every time
  sources:
    github:
      max_results: 10  # More PoCs
```

## Troubleshooting

### Issue: "Vulners API authentication failed"

**Cause:** Invalid or missing API key

**Fix:**
1. Verify your API key at https://vulners.com/userinfo
2. Ensure key is in config:
   ```yaml
   vulners:
     api_key: "YOUR_KEY_HERE"
   ```
3. Test with:
   ```bash
   python -c "from utils.osint import VulnersClient; import yaml; \
   c = VulnersClient(yaml.safe_load(open('config/guardian.yaml'))); \
   print(c.check_api_status())"
   ```

### Issue: "GitHub API rate limit exceeded"

**Cause:** Hit 60 requests/hour limit (no token)

**Fix:**
1. Add GitHub token (increases to 5000/hour)
2. Or reduce scans/day
3. Check current rate limit:
   ```bash
   python -c "from utils.osint import GitHubPoCSearch; import yaml; \
   c = GitHubPoCSearch(yaml.safe_load(open('config/guardian.yaml'))); \
   print(c.get_rate_limit_info())"
   ```

### Issue: "No OSINT data in reports"

**Checks:**
1. Is `osint.enabled: true`?
   ```bash
   grep "osint:" config/guardian.yaml
   ```

2. Do findings have CVEs?
   ```bash
   grep "CVE-" reports/*/report_*.md
   ```

3. Check OSINT logs:
   ```bash
   grep "OSINT" reports/*/session_*.json
   ```

### Issue: "CISA KEV data outdated"

**Fix:** Clear cache and force refresh
```bash
rm -rf ~/.guardian/cache/cisa_kev.json
python -m cli.main workflow run --name network --target target
```

## Performance Considerations

### Cache Benefits

OSINT data is cached to improve performance:

```
First scan:
- CISA KEV: 3s download, then cached 24h
- GitHub: 1-2s per CVE
- Vulners: 1-2s per CVE

Subsequent scans (within cache TTL):
- CISA KEV: <0.1s (from cache)
- GitHub: 1-2s per CVE (not cached)
- Vulners: 1-2s per CVE (not cached)
```

**Recommendation:** Accept cache defaults (24 hours) for best performance.

### Scan Time Impact

**Without OSINT:**
```
Network scan: 5-10 minutes
```

**With OSINT (10 CVEs found):**
```
Network scan: 5-10 minutes
OSINT enrichment: +20-30 seconds (first run)
OSINT enrichment: +10-20 seconds (cached KEV)
Total: 5-11 minutes
```

**Impact:** Minimal (<10% overhead for significant intelligence gain)

## API Key Security

### Securing Your API Keys

**DO NOT commit API keys to git:**
```bash
# Check if keys are in git:
git grep "api_key:" config/guardian.yaml

# If found, remove from git history:
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch config/guardian.yaml" \
  --prune-empty --tag-name-filter cat -- --all
```

**Best Practice:** Use environment variables
```yaml
# config/guardian.yaml
osint:
  sources:
    vulners:
      api_key: ${VULNERS_API_KEY}  # Read from environment
    github:
      token: ${GITHUB_TOKEN}
```

```bash
# Set in shell
export VULNERS_API_KEY="your-key-here"
export GITHUB_TOKEN="ghp_your-token-here"
```

## Advanced Configuration

### Customize GitHub Search

```yaml
github:
  enabled: true
  token: "ghp_xxx"
  min_stars: 50        # Only highly-starred repos
  max_results: 10      # More PoCs
  timeout: 30          # Longer timeout for slow networks
```

### Aggressive CISA KEV Flagging

```yaml
cisa_kev:
  enabled: true
  priority_flag: true  # Auto-escalate KEV findings to CRITICAL
```

When enabled, ANY finding in CISA KEV is automatically marked CRITICAL regardless of original severity.

### Disable Specific Sources

```yaml
osint:
  enabled: true  # Master switch
  sources:
    cisa_kev:
      enabled: true   # Keep this one
    github:
      enabled: false  # Disable GitHub
    vulners:
      enabled: false  # Disable Vulners
```

## Next Steps

1. **Enable CISA KEV** - Works immediately, no setup
2. **Get GitHub token** - 5 minutes, huge rate limit increase
3. **Get Vulners API key** - 5 minutes, adds comprehensive intelligence
4. **Run a scan** - See the difference in your reports!

## Support

- **CISA KEV Issues:** Check https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **GitHub API:** https://docs.github.com/en/rest
- **Vulners API:** https://vulners.com/docs

---

**Created:** 2026-01-22
**Version:** 1.0.0
**Status:** ✅ Production Ready
