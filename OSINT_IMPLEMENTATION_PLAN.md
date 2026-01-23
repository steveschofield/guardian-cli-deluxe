# OSINT Implementation Plan: CISA KEV + GitHub PoCs + Vulners

## Priority Implementation: 3 High-Value Sources

### 1. CISA KEV (Known Exploited Vulnerabilities) - HIGHEST PRIORITY 🔥

**Why this is critical:**
- Identifies CVEs actively exploited in the wild
- Government-mandated remediation deadlines
- Used by ransomware groups
- Authoritative source (US CISA)

**Implementation Complexity:** ⭐ Easy (static JSON file)

**Data Source:**
```
URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Format: JSON
Size: ~2MB
Update Frequency: Daily
Rate Limit: None (static file)
Cost: FREE
```

**Sample Data:**
```json
{
  "catalogVersion": "2024.01.22",
  "vulnerabilities": [
    {
      "cveID": "CVE-2017-0143",
      "vendorProject": "Microsoft",
      "product": "Windows SMB",
      "vulnerabilityName": "Microsoft Windows SMB Remote Code Execution Vulnerability",
      "dateAdded": "2021-11-03",
      "shortDescription": "Microsoft Windows SMB contains a remote code execution vulnerability...",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2022-05-03",
      "knownRansomwareCampaignUse": "Known",
      "notes": "https://nvd.nist.gov/vuln/detail/CVE-2017-0143"
    }
  ]
}
```

**Report Impact Example:**
```markdown
### MS17-010 Remote Code Execution (CRITICAL) 🔥

* **⚠️ ACTIVELY EXPLOITED IN THE WILD** (CISA KEV)
  - **Status:** CONFIRMED - Exploited by threat actors
  - **Date Added to KEV:** 2021-11-03
  - **Government Deadline:** 2022-05-03
  - **Ransomware Use:** CONFIRMED (WannaCry, NotPetya)
  - **Required Action:** Apply Microsoft updates immediately
```

### 2. GitHub Exploit Search - HIGH PRIORITY 💣

**Why this is valuable:**
- Community PoC exploits (often before Exploit-DB)
- Active development/maintenance status
- Multiple implementation examples
- Star count indicates reliability

**Implementation Complexity:** ⭐⭐ Medium (API + parsing)

**API Details:**
```
Endpoint: https://api.github.com/search/repositories
Rate Limit: 60/hour (no auth), 5,000/hour (with token)
Cost: FREE (token increases limit)
Authentication: Optional GitHub Personal Access Token
```

**Search Strategy:**
```python
# Search query for CVE-2017-0143
query = 'CVE-2017-0143 (exploit OR poc OR vulnerability) language:python OR language:ruby'

# Returns:
# - Repository name/URL
# - Description
# - Stars (popularity indicator)
# - Last update (actively maintained?)
# - Programming language
```

**Sample Results:**
```json
{
  "total_count": 47,
  "items": [
    {
      "name": "MS17-010",
      "full_name": "worawit/MS17-010",
      "html_url": "https://github.com/worawit/MS17-010",
      "description": "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
      "stargazers_count": 2145,
      "language": "Python",
      "updated_at": "2023-08-15T14:22:33Z",
      "topics": ["exploit", "eternalblue", "ms17-010"]
    },
    {
      "name": "AutoBlue-MS17-010",
      "full_name": "3ndG4me/AutoBlue-MS17-010",
      "html_url": "https://github.com/3ndG4me/AutoBlue-MS17-010",
      "description": "This is just an semi-automated exploitation script for MS17-010",
      "stargazers_count": 1823,
      "language": "Python",
      "updated_at": "2023-06-10T09:15:22Z"
    }
  ]
}
```

**Report Impact Example:**
```markdown
### MS17-010 Remote Code Execution (CRITICAL)

* **Exploitation Information:**
  + **GitHub PoC Exploits (12 available):**
    * [worawit/MS17-010](https://github.com/worawit/MS17-010) ⭐ 2,145 stars
      - Python implementation
      - Last updated: 2023-08-15
      - Well-maintained, highly tested
    * [3ndG4me/AutoBlue-MS17-010](https://github.com/3ndG4me/AutoBlue-MS17-010) ⭐ 1,823 stars
      - Automated exploitation script
      - Easy to use for penetration testing
```

### 3. Vulners API - HIGH PRIORITY 📊

**Why this is powerful:**
- Aggregates 100+ vulnerability sources
- Unified exploit references (Metasploit, Exploit-DB, GitHub, etc.)
- AI-based risk scoring
- Comprehensive CVE metadata

**Implementation Complexity:** ⭐⭐ Medium (REST API)

**API Details:**
```
Endpoint: https://vulners.com/api/v3/
Rate Limit: 100 requests/day (FREE), 10,000/day (PAID $99/mo)
Cost: FREE tier sufficient for most scans
Authentication: API key required (free registration)
```

**API Methods:**
```python
# Search by CVE
POST https://vulners.com/api/v3/search/lucene/
{
  "query": "cve:CVE-2017-0143"
}

# Search by CPE (product)
POST https://vulners.com/api/v3/burp/software/
{
  "software": "Microsoft Windows Server 2008",
  "version": "R2 SP1"
}
```

**Sample Response:**
```json
{
  "result": "OK",
  "data": {
    "total": 1,
    "search": [
      {
        "id": "CVE-2017-0143",
        "type": "cve",
        "title": "Microsoft Windows SMB Remote Code Execution Vulnerability",
        "description": "The SMBv1 server in Microsoft Windows...",
        "cvss": {
          "score": 8.1,
          "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "lastseen": "2024-01-22T10:30:15",
        "published": "2017-03-14T00:00:00",
        "cwe": ["CWE-119"],
        "sourceData": {
          "exploitdb": ["42315", "42031", "41987"],
          "metasploit": ["exploit/windows/smb/ms17_010_eternalblue"],
          "githubexploit": ["worawit/MS17-010"]
        },
        "ai_score": 9.5,
        "exploit_count": 18,
        "references": [
          "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0143"
        ]
      }
    ]
  }
}
```

**Report Impact Example:**
```markdown
### MS17-010 Remote Code Execution (CRITICAL)

* **Comprehensive Exploit Intelligence (via Vulners):**
  + **Exploit Count:** 18 public exploits found across all sources
  + **AI Risk Score:** 9.5/10 (Extremely High Risk)
  + **Sources:**
    * Metasploit: 3 modules
    * Exploit-DB: 7 exploits (EDB-42315, EDB-42031, EDB-41987, ...)
    * GitHub: 12 repositories
  + **Vendor Advisory:** [Microsoft Security Bulletin](https://portal.msrc.microsoft.com/...)
```

## Implementation Architecture

### File Structure
```
utils/
├── osint/
│   ├── __init__.py
│   ├── base.py           # Base OSINT client class
│   ├── cisa_kev.py       # CISA KEV implementation
│   ├── github_pocs.py    # GitHub exploit search
│   ├── vulners.py        # Vulners API client
│   └── enricher.py       # Main enrichment orchestrator
```

### Core Module: `utils/osint/enricher.py`

```python
from typing import Dict, List, Any
from core.memory import Finding
from utils.osint.cisa_kev import CISAKEVClient
from utils.osint.github_pocs import GitHubPoCSearch
from utils.osint.vulners import VulnersClient

class OSINTEnricher:
    """
    Enriches vulnerability findings with OSINT data
    """

    def __init__(self, config: Dict[str, Any], logger=None):
        self.config = config
        self.logger = logger
        self.enabled = config.get("osint", {}).get("enabled", True)

        # Initialize OSINT clients
        self.cisa_kev = CISAKEVClient(config, logger)
        self.github = GitHubPoCSearch(config, logger)
        self.vulners = VulnersClient(config, logger)

    def enrich_findings(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Enrich multiple findings with OSINT intelligence

        Returns:
            Dict with enrichment data keyed by finding ID
        """
        if not self.enabled:
            return {}

        enrichment_data = {}

        for finding in findings:
            if not finding.cve_ids:
                continue

            finding_enrichment = {
                "cve_data": {},
                "kev_status": {},
                "github_pocs": [],
                "vulners_data": {},
            }

            for cve_id in finding.cve_ids:
                # CISA KEV lookup (critical priority)
                kev_entry = self.cisa_kev.lookup(cve_id)
                if kev_entry:
                    finding_enrichment["kev_status"][cve_id] = kev_entry

                # GitHub PoC search
                pocs = self.github.search_exploits(cve_id)
                if pocs:
                    finding_enrichment["github_pocs"].extend(pocs)

                # Vulners comprehensive lookup
                vulners_data = self.vulners.lookup(cve_id)
                if vulners_data:
                    finding_enrichment["vulners_data"][cve_id] = vulners_data

            enrichment_data[finding.id] = finding_enrichment

        return enrichment_data

    def get_kev_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics about KEV findings

        Returns:
            Dict with counts and stats
        """
        return self.cisa_kev.get_summary()
```

### Module 1: CISA KEV Client

**File:** `utils/osint/cisa_kev.py`

```python
import json
import requests
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime, timedelta

class CISAKEVClient:
    """
    Client for CISA Known Exploited Vulnerabilities Catalog
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_FILE = Path.home() / ".guardian" / "cache" / "cisa_kev.json"
    CACHE_TTL_HOURS = 24

    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger
        self.enabled = config.get("osint", {}).get("sources", {}).get("cisa_kev", {}).get("enabled", True)
        self.kev_data = None

        if self.enabled:
            self._load_kev_data()

    def _load_kev_data(self):
        """Load KEV data from cache or fetch fresh"""
        # Check cache first
        if self.CACHE_FILE.exists():
            cache_age = datetime.now() - datetime.fromtimestamp(self.CACHE_FILE.stat().st_mtime)
            if cache_age < timedelta(hours=self.CACHE_TTL_HOURS):
                with open(self.CACHE_FILE, 'r') as f:
                    self.kev_data = json.load(f)
                    if self.logger:
                        self.logger.info(f"Loaded CISA KEV from cache ({len(self.kev_data.get('vulnerabilities', []))} entries)")
                    return

        # Fetch fresh data
        try:
            response = requests.get(self.KEV_URL, timeout=30)
            response.raise_for_status()
            self.kev_data = response.json()

            # Save to cache
            self.CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(self.kev_data, f, indent=2)

            if self.logger:
                vuln_count = len(self.kev_data.get("vulnerabilities", []))
                self.logger.info(f"Fetched CISA KEV catalog ({vuln_count} entries)")

        except Exception as e:
            if self.logger:
                self.logger.warning(f"Failed to fetch CISA KEV: {e}")
            self.kev_data = {"vulnerabilities": []}

    def lookup(self, cve_id: str) -> Optional[Dict]:
        """
        Check if CVE is in CISA KEV catalog

        Args:
            cve_id: CVE identifier (e.g., "CVE-2017-0143")

        Returns:
            KEV entry dict if found, None otherwise
        """
        if not self.enabled or not self.kev_data:
            return None

        cve_upper = cve_id.upper()
        for vuln in self.kev_data.get("vulnerabilities", []):
            if vuln.get("cveID", "").upper() == cve_upper:
                return {
                    "cve_id": vuln.get("cveID"),
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "name": vuln.get("vulnerabilityName"),
                    "date_added": vuln.get("dateAdded"),
                    "due_date": vuln.get("dueDate"),
                    "required_action": vuln.get("requiredAction"),
                    "ransomware_use": vuln.get("knownRansomwareCampaignUse") == "Known",
                    "notes": vuln.get("notes"),
                }

        return None

    def is_kev(self, cve_id: str) -> bool:
        """Quick check if CVE is in KEV catalog"""
        return self.lookup(cve_id) is not None

    def get_summary(self) -> Dict:
        """Get KEV catalog statistics"""
        if not self.kev_data:
            return {"total": 0, "catalog_version": None}

        vulnerabilities = self.kev_data.get("vulnerabilities", [])
        ransomware_count = sum(1 for v in vulnerabilities if v.get("knownRansomwareCampaignUse") == "Known")

        return {
            "total": len(vulnerabilities),
            "catalog_version": self.kev_data.get("catalogVersion"),
            "ransomware_associated": ransomware_count,
        }
```

### Module 2: GitHub PoC Search

**File:** `utils/osint/github_pocs.py`

```python
import requests
from typing import List, Dict, Optional
from time import sleep

class GitHubPoCSearch:
    """
    Search GitHub for exploit PoCs
    """

    API_URL = "https://api.github.com/search/repositories"

    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger
        gh_config = config.get("osint", {}).get("sources", {}).get("github", {})
        self.enabled = gh_config.get("enabled", True)
        self.token = gh_config.get("token", None)
        self.min_stars = gh_config.get("min_stars", 10)
        self.max_results = gh_config.get("max_results", 5)

    def search_exploits(self, cve_id: str) -> List[Dict]:
        """
        Search GitHub for exploit PoCs for a CVE

        Args:
            cve_id: CVE identifier

        Returns:
            List of GitHub repository dicts
        """
        if not self.enabled:
            return []

        # Build search query
        query = f'"{cve_id}" (exploit OR poc OR vulnerability) language:python OR language:ruby OR language:go'

        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        params = {
            "q": query,
            "sort": "stars",
            "order": "desc",
            "per_page": self.max_results * 2,  # Get extra in case we filter some
        }

        try:
            response = requests.get(self.API_URL, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            pocs = []
            for repo in data.get("items", []):
                # Filter by minimum stars
                if repo.get("stargazers_count", 0) < self.min_stars:
                    continue

                pocs.append({
                    "name": repo.get("full_name"),
                    "url": repo.get("html_url"),
                    "description": repo.get("description", ""),
                    "stars": repo.get("stargazers_count"),
                    "language": repo.get("language"),
                    "updated_at": repo.get("updated_at"),
                })

                if len(pocs) >= self.max_results:
                    break

            if self.logger and pocs:
                self.logger.info(f"Found {len(pocs)} GitHub PoCs for {cve_id}")

            return pocs

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:  # Rate limit
                if self.logger:
                    self.logger.warning(f"GitHub API rate limit hit for {cve_id}")
            return []

        except Exception as e:
            if self.logger:
                self.logger.warning(f"GitHub PoC search failed for {cve_id}: {e}")
            return []
```

### Module 3: Vulners API Client

**File:** `utils/osint/vulners.py`

```python
import requests
from typing import Dict, Optional

class VulnersClient:
    """
    Client for Vulners API
    """

    API_URL = "https://vulners.com/api/v3/search/lucene/"

    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger
        vulners_config = config.get("osint", {}).get("sources", {}).get("vulners", {})
        self.enabled = vulners_config.get("enabled", False)
        self.api_key = vulners_config.get("api_key", None)

    def lookup(self, cve_id: str) -> Optional[Dict]:
        """
        Lookup CVE in Vulners database

        Args:
            cve_id: CVE identifier

        Returns:
            Vulners data dict if found
        """
        if not self.enabled or not self.api_key:
            return None

        payload = {
            "query": f"cve:{cve_id}",
            "apiKey": self.api_key,
        }

        try:
            response = requests.post(self.API_URL, json=payload, timeout=10)
            response.raise_for_status()
            data = response.json()

            if data.get("result") != "OK":
                return None

            search_results = data.get("data", {}).get("search", [])
            if not search_results:
                return None

            vuln = search_results[0]  # Take first result

            return {
                "cve_id": vuln.get("id"),
                "title": vuln.get("title"),
                "cvss_score": vuln.get("cvss", {}).get("score"),
                "cvss_vector": vuln.get("cvss", {}).get("vector"),
                "cwe": vuln.get("cwe", []),
                "exploit_count": vuln.get("exploit_count", 0),
                "ai_score": vuln.get("ai_score"),
                "exploits": vuln.get("sourceData", {}),
                "references": vuln.get("references", []),
            }

        except Exception as e:
            if self.logger:
                self.logger.warning(f"Vulners API lookup failed for {cve_id}: {e}")
            return None
```

## Configuration

Add to `config/guardian.yaml`:

```yaml
# OSINT Enrichment Configuration
osint:
  enabled: true
  cache_ttl_hours: 24

  sources:
    # CISA Known Exploited Vulnerabilities (FREE)
    cisa_kev:
      enabled: true
      priority_flag: true  # Auto-escalate KEV findings to CRITICAL

    # GitHub Exploit Search (FREE with token)
    github:
      enabled: true
      token: ""  # Get from: https://github.com/settings/tokens
                 # Scopes needed: public_repo (read-only)
      min_stars: 10  # Only show repos with 10+ stars
      max_results: 5  # Max PoCs to include per CVE

    # Vulners API (100/day FREE, 10k/day PAID $99/mo)
    vulners:
      enabled: true  # Recommended even with free tier
      api_key: ""  # Get from: https://vulners.com/userinfo
```

## Integration with Reporter

Update `core/reporter_agent.py`:

```python
from utils.osint.enricher import OSINTEnricher

class ReporterAgent(BaseAgent):
    def __init__(self, config, llm_client, memory):
        super().__init__("Reporter", config, llm_client, memory)
        self.osint_enricher = OSINTEnricher(config, logger=self.logger)

    def _format_findings_detailed(self) -> str:
        findings = self._get_report_findings()
        exploit_lookup = self._get_exploit_lookup()
        osint_data = self.osint_enricher.enrich_findings(findings)  # NEW

        for f in findings:
            # ... existing code ...

            # Add OSINT enrichment
            enrichment = osint_data.get(f.id, {})

            # Check CISA KEV status
            kev_status = enrichment.get("kev_status", {})
            for cve_id, kev_entry in kev_status.items():
                exploit_info.append(f"🔥 CISA KEV: {cve_id} actively exploited in the wild")
                if kev_entry.get("ransomware_use"):
                    exploit_info.append(f"   ⚠️ Known ransomware use")
                exploit_info.append(f"   Required Action: {kev_entry.get('required_action')}")
                exploit_info.append(f"   Government Deadline: {kev_entry.get('due_date')}")

            # Add GitHub PoCs
            github_pocs = enrichment.get("github_pocs", [])
            if github_pocs:
                exploit_info.append(f"GitHub PoCs ({len(github_pocs)} available):")
                for poc in github_pocs[:3]:
                    exploit_info.append(f"  - {poc['name']} ⭐ {poc['stars']} stars - {poc['url']}")

            # Add Vulners comprehensive data
            vulners_data = enrichment.get("vulners_data", {})
            for cve_id, vdata in vulners_data.items():
                if vdata.get("ai_score"):
                    exploit_info.append(f"Vulners AI Risk Score: {vdata['ai_score']}/10")
                if vdata.get("exploit_count"):
                    exploit_info.append(f"Total exploits (all sources): {vdata['exploit_count']}")
```

## Testing Plan

### Test 1: CISA KEV Detection
```bash
# Target with known KEV vulnerability
python -m cli.main workflow run --name network --target 192.168.1.0/24

# Expected: MS17-010, BlueKeep, etc. flagged with KEV warnings
```

### Test 2: GitHub PoC Discovery
```bash
# Any scan that finds CVEs
python -m cli.main workflow run --name web --target https://test.com

# Expected: GitHub PoCs listed with star counts
```

### Test 3: Vulners Comprehensive
```bash
# Scan with Vulners enabled
python -m cli.main workflow run --name network --target vulnerable-box

# Expected: AI risk scores, exploit counts from all sources
```

## Rollout Strategy

### Week 1: CISA KEV
- [ ] Implement `cisa_kev.py`
- [ ] Add caching
- [ ] Test with known KEV CVEs
- [ ] Integrate into reports

### Week 2: GitHub PoCs
- [ ] Implement `github_pocs.py`
- [ ] Handle rate limiting
- [ ] Test with various CVEs
- [ ] Integrate into reports

### Week 3: Vulners API
- [ ] Implement `vulners.py`
- [ ] Test free tier limits
- [ ] Add comprehensive error handling
- [ ] Integrate into reports

### Week 4: Polish & Document
- [ ] Add configuration docs
- [ ] Create example reports
- [ ] Performance testing
- [ ] User guide

## Expected Report Improvements

### Before (Current)
```markdown
### MS17-010 RCE (CRITICAL)
* CVE: CVE-2017-0143
* Metasploit: 2 modules
* Exploit-DB: 3 exploits
```

### After (With OSINT)
```markdown
### MS17-010 RCE (CRITICAL) 🔥

* **⚠️ ACTIVELY EXPLOITED - CISA KEV CONFIRMED**
  - Date Added to KEV: 2021-11-03
  - Government Deadline: 2022-05-03
  - Known Ransomware Use: WannaCry, NotPetya
  - Required Action: Apply Microsoft updates immediately

* **Exploit Intelligence:**
  - CVE: CVE-2017-0143, CVE-2017-0144, CVE-2017-0145
  - **Vulners AI Risk Score: 9.5/10 (Extreme)**
  - **Total Exploits: 18 across all sources**
  - Metasploit: 3 modules
  - Exploit-DB: 7 exploits
  - GitHub PoCs: 12 repositories
    * [worawit/MS17-010](https://github.com/worawit/MS17-010) ⭐ 2,145
    * [3ndG4me/AutoBlue-MS17-010](https://github.com/3ndG4me/AutoBlue-MS17-010) ⭐ 1,823
```

## Cost Analysis

| Source | Free Tier | Cost | Recommendation |
|--------|-----------|------|----------------|
| CISA KEV | Unlimited | $0 | ✅ Always enable |
| GitHub | 60/hour (5000 with token) | $0 | ✅ Use with token |
| Vulners | 100/day | $0 | ✅ Enable, monitor usage |

**Total Cost:** $0 for typical penetration test usage

For heavy usage (100+ scans/day), Vulners paid tier ($99/mo) provides 10,000 requests/day.

## Success Metrics

- ✅ KEV vulnerabilities automatically flagged as CRITICAL
- ✅ GitHub PoC count increases exploit intelligence
- ✅ Vulners AI scores help prioritize findings
- ✅ Report value increases with minimal API cost
- ✅ Security teams have full threat context
