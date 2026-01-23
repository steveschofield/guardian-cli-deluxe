# OSINT Enrichment Enhancement Proposal

## Overview

Enhance Guardian's vulnerability intelligence by integrating multiple open-source intelligence (OSINT) feeds to provide comprehensive exploit and risk context.

## Current State

**Existing Sources:**
- ✅ Local Exploit-DB database (`/usr/share/exploitdb/files_exploits.csv`)
- ✅ Local Metasploit modules (`/usr/share/metasploit-framework/modules/exploits/`)

**Limitations:**
- No official CVE metadata (CVSS, CWE, CPE)
- No in-the-wild exploitation status
- No exploit probability predictions
- No vendor advisory links
- Limited to local databases (may be outdated)

## Proposed Architecture

### 1. New Module: `utils/osint_enrichment.py`

```python
class OSINTEnricher:
    """Enriches findings with multiple OSINT sources"""

    def __init__(self, config, cache_ttl_hours=24):
        self.nvd_client = NVDClient(config)
        self.cisa_kev = CISAKEVClient(config)
        self.epss = EPSSClient(config)
        self.github = GitHubExploitSearch(config)
        self.vulners = VulnersClient(config)

    def enrich_finding(self, finding: Finding) -> Dict[str, Any]:
        """Enrich a finding with OSINT data"""
        enrichment = {}

        if finding.cve_ids:
            for cve_id in finding.cve_ids:
                enrichment[cve_id] = {
                    "nvd": self.nvd_client.lookup(cve_id),
                    "kev": self.cisa_kev.is_exploited(cve_id),
                    "epss": self.epss.get_score(cve_id),
                    "github_pocs": self.github.search_exploits(cve_id),
                    "vulners": self.vulners.lookup(cve_id),
                }

        return enrichment
```

### 2. Data Sources Implementation

#### A. NVD (National Vulnerability Database)

**API**: https://services.nvd.nist.gov/rest/json/cves/2.0

**Rate Limits**: 5 requests/30 seconds (public), 50/30s (with API key)

**Data Retrieved**:
```json
{
  "cve_id": "CVE-2017-0143",
  "cvss_v3": {
    "score": 8.1,
    "vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "severity": "HIGH"
  },
  "cwe_ids": ["CWE-119"],
  "cpe": ["cpe:2.3:o:microsoft:windows_server_2008:r2:sp1"],
  "published": "2017-03-14T00:00:00",
  "references": [
    "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0143"
  ]
}
```

**Benefits**:
- ✅ Official/authoritative CVSS scores (replace estimated scores)
- ✅ Official CWE mappings
- ✅ Affected product versions (CPE)
- ✅ Vendor advisory links

#### B. CISA Known Exploited Vulnerabilities (KEV)

**API**: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

**Rate Limits**: None (static JSON file)

**Data Retrieved**:
```json
{
  "cve_id": "CVE-2017-0143",
  "vulnerability_name": "Microsoft Windows SMB Remote Code Execution",
  "date_added": "2021-11-03",
  "required_action": "Apply updates per vendor instructions",
  "due_date": "2022-05-03",
  "notes": "Used by ransomware groups"
}
```

**Benefits**:
- ✅ **Critical indicator**: Actively exploited in the wild
- ✅ Government remediation deadlines
- ✅ Ransomware associations
- ✅ Immediate priority flag for reports

#### C. EPSS (Exploit Prediction Scoring System)

**API**: https://api.first.org/data/v1/epss?cve=CVE-2017-0143

**Rate Limits**: None

**Data Retrieved**:
```json
{
  "cve": "CVE-2017-0143",
  "epss": 0.97545,
  "percentile": 0.99876,
  "date": "2024-01-22"
}
```

**Benefits**:
- ✅ Exploitation probability (0-100%)
- ✅ ML-based predictions
- ✅ Helps prioritize remediation efforts
- ✅ Example: 97.5% = very likely to be exploited

#### D. GitHub Exploit Search

**API**: GitHub REST API + Search

**Rate Limits**: 60/hour (unauthenticated), 5000/hour (authenticated)

**Search Query**:
```
"CVE-2017-0143" + (exploit OR poc OR vulnerability)
language:python OR language:ruby OR language:go
```

**Data Retrieved**:
```json
{
  "repositories": [
    {
      "name": "worawit/MS17-010",
      "url": "https://github.com/worawit/MS17-010",
      "stars": 2145,
      "description": "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
      "last_updated": "2023-08-15"
    }
  ]
}
```

**Benefits**:
- ✅ Community PoCs (often before Exploit-DB)
- ✅ Active exploit development
- ✅ Multiple implementation examples
- ✅ Star count = popularity/reliability indicator

#### E. Vulners API (Aggregator)

**API**: https://vulners.com/api/v3/search/lucene/

**Rate Limits**: 100 requests/day (free), 10k/day (paid)

**Data Retrieved**:
```json
{
  "cve_id": "CVE-2017-0143",
  "exploit_count": 15,
  "exploits": [
    {
      "source": "metasploit",
      "title": "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption"
    },
    {
      "source": "exploitdb",
      "id": "42315"
    },
    {
      "source": "seebug",
      "id": "SSV-97087"
    }
  ],
  "ai_score": 9.5,
  "cvss": 8.1
}
```

**Benefits**:
- ✅ Aggregates 100+ sources
- ✅ AI-based risk scoring
- ✅ Additional exploit references

## Enhanced Report Output

### Example: Technical Findings Section

```markdown
### 6. Remote Code Execution vulnerability in Microsoft SMBv1 servers (CRITICAL)

* **Title:** MS17-010 EternalBlue SMB RCE
* **Severity:** CRITICAL 🔥
* **Affected Component/Service:** Microsoft SMBv1 server
* **Technical Description:** Remote code execution vulnerability in Microsoft SMBv1 servers allows unauthenticated attackers to execute arbitrary code.

* **Exploitation Intelligence:**
    + **CVE IDs:** CVE-2017-0143, CVE-2017-0144, CVE-2017-0145
    + **CVSS v3.1:** 8.1 HIGH (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)
    + **CWE:** CWE-119 (Improper Restriction of Operations within Bounds of Memory Buffer)
    + **Affected Versions:** Windows Server 2008 R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 R2

    + **⚠️ CRITICAL: Actively Exploited in the Wild**
      - **CISA KEV Status:** CONFIRMED - Added 2021-11-03
      - **Required Action:** Apply updates per vendor instructions
      - **Government Deadline:** 2022-05-03
      - **Associated Threats:** Used by WannaCry, NotPetya ransomware campaigns

    + **Exploit Availability:**
      - **Metasploit Modules (3):**
        * MS17-010 EternalBlue DOUBLEPULSAR [Link](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue)
        * MS17-010 EternalRomance SMB RCE
        * MS17-010 EternalChampion SMB RCE
      - **Exploit-DB (7):**
        * EDB-42315: MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
        * EDB-42031: MS17-010 EternalRomance/EternalSynergy/EternalChampion
      - **GitHub PoCs (12):**
        * [worawit/MS17-010](https://github.com/worawit/MS17-010) ⭐ 2,145 stars
        * [3ndG4me/AutoBlue-MS17-010](https://github.com/3ndG4me/AutoBlue-MS17-010) ⭐ 1,823 stars

    + **Exploitation Risk Assessment:**
      - **EPSS Score:** 97.5% probability of exploitation in next 30 days
      - **EPSS Percentile:** 99.9th percentile (higher risk than 99.9% of all CVEs)
      - **Vulners AI Score:** 9.5/10 (extremely high risk)

* **Impact Analysis:**
    - Remote, unauthenticated code execution
    - Complete system compromise (CIA triad: High/High/High)
    - Wormable (self-propagating without user interaction)
    - Used in global ransomware campaigns (WannaCry affected 200k+ systems)

* **Vendor Advisories:**
    - [Microsoft Security Bulletin MS17-010](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0143)
    - [NIST NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2017-0143)
    - [CISA Alert AA17-132A](https://www.cisa.gov/news-events/alerts/2017/05/12/microsoft-releases-security-updates)

* **Remediation Steps:**
    1. **IMMEDIATE:** Disable SMBv1 protocol
    2. **URGENT:** Apply Microsoft patches KB4013389 (Win7/2008R2), KB4012215 (Win8.1/2012R2)
    3. Block TCP ports 139, 445 at network perimeter
    4. Enable SMB signing
    5. Implement network segmentation

* **CVSS v3.1 Score:** 8.1 HIGH
* **OWASP Top 10 (2021):** A06:2021 - Vulnerable and Outdated Components
* **CWE Mapping:** CWE-119, CWE-787
```

### Enhanced Standards Mapping Table

```markdown
| Severity | Finding | CVSS | KEV Status | EPSS | Exploit Status |
|----------|---------|------|------------|------|----------------|
| CRITICAL | MS17-010 RCE | 8.1 | 🔥 ACTIVELY EXPLOITED | 97.5% | 💣 MSF:3, EDB:7, GitHub:12 |
| HIGH | BlueKeep RDP RCE | 9.8 | ⚠️ KEV Listed | 85.2% | 💣 MSF:2, EDB:5, GitHub:8 |
| MEDIUM | SSL/TLS Weak Cipher | 5.3 | N/A | 2.1% | N/A |
```

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1)
- [ ] Create `utils/osint_enrichment.py` module
- [ ] Implement caching layer (SQLite or JSON)
- [ ] Add configuration options to `config/guardian.yaml`
- [ ] Create API client base class with rate limiting

### Phase 2: Primary Sources (Week 2-3)
- [ ] Implement NVD API client
- [ ] Implement CISA KEV client (JSON feed)
- [ ] Implement EPSS client
- [ ] Add CVE enrichment to finding workflow

### Phase 3: Secondary Sources (Week 4)
- [ ] Implement GitHub exploit search
- [ ] Implement Vulners API client (optional)
- [ ] Add error handling and fallbacks

### Phase 4: Report Integration (Week 5)
- [ ] Update `_format_findings_detailed()` with OSINT data
- [ ] Enhance Standards Mapping table
- [ ] Add "Exploitation Intelligence" section
- [ ] Update AI prompts to utilize new data

### Phase 5: Testing & Documentation (Week 6)
- [ ] Test with various CVEs
- [ ] Handle API failures gracefully
- [ ] Update documentation
- [ ] Add configuration examples

## Configuration

```yaml
# config/guardian.yaml
osint:
  enabled: true
  cache_ttl_hours: 24

  sources:
    nvd:
      enabled: true
      api_key: ""  # Optional: increases rate limit
      timeout: 10

    cisa_kev:
      enabled: true
      priority_flag: true  # Flag KEV CVEs as critical

    epss:
      enabled: true
      threshold: 0.50  # Flag CVEs with >50% exploitation probability

    github:
      enabled: true
      token: ""  # Optional: increases rate limit to 5000/hour
      min_stars: 10  # Only include repos with 10+ stars
      max_results: 5

    vulners:
      enabled: false  # Optional paid service
      api_key: ""

  rate_limiting:
    enabled: true
    retry_on_limit: true
    max_retries: 3

reporting:
  osint:
    include_kev_warnings: true
    include_epss_scores: true
    include_github_pocs: true
    show_vendor_advisories: true
```

## Benefits Summary

### For Security Teams
✅ **Better Prioritization** - EPSS scores + KEV status = clear priorities
✅ **Risk Context** - Know which vulns are actively exploited
✅ **Remediation Guidance** - Vendor advisories and patch links
✅ **Exploit Intelligence** - Multiple exploit sources (MSF + EDB + GitHub)

### For Management
✅ **Regulatory Compliance** - CISA KEV deadlines for federal/critical infrastructure
✅ **Business Risk** - "97% chance of exploitation" is clearer than "CVSS 8.1"
✅ **Trending Threats** - See which vulns are hot in attacker communities

### For Auditors
✅ **Authoritative Data** - NVD, CISA, FIRST.org (official sources)
✅ **Comprehensive Coverage** - Multiple intelligence feeds
✅ **Transparent Methodology** - Clear data sources cited

## Privacy & Compliance

### Data Handling
- All API calls logged for audit
- CVE IDs are public information (no sensitive data leaked)
- Target IPs/domains never sent to external APIs
- Caching reduces API calls and improves privacy

### Rate Limiting
- Respects all API rate limits
- Implements exponential backoff
- Falls back gracefully if APIs unavailable
- Can operate fully offline with cached data

## Cost Analysis

| Source | Free Tier | Paid Tier | Recommendation |
|--------|-----------|-----------|----------------|
| NVD | 5 req/30s | 50 req/30s ($0) | Use with API key (free) |
| CISA KEV | Unlimited | N/A | Always use |
| EPSS | Unlimited | N/A | Always use |
| GitHub | 60/hour | 5000/hour ($0) | Use with token (free) |
| Vulners | 100/day | 10k/day ($99/mo) | Optional |

**Recommended Setup:** All free tiers provide excellent coverage

## Example Use Cases

### Use Case 1: Vulnerability Assessment
```bash
python -m cli.main workflow run --name network --target 192.168.1.0/24
```
**Output:**
- Discovers MS17-010
- Checks NVD → Gets official CVSS 8.1
- Checks CISA KEV → 🔥 ACTIVELY EXPLOITED IN THE WILD
- Checks EPSS → 97.5% exploitation probability
- Checks GitHub → Found 12 public PoCs
- **Report:** Prominently flags as TOP PRIORITY with full context

### Use Case 2: Compliance Audit
```bash
python -m cli.main workflow run --name web --target https://example.com
```
**Output:**
- Discovers various CVEs
- Generates report with:
  - CISA KEV compliance status
  - Government remediation deadlines
  - Official CVSS scores from NVD
  - Vendor advisory links
- **Value:** Meets CISA BOD 22-01 requirements

### Use Case 3: Exploit Development Research
```bash
python -m cli.main workflow run --name network --target lab.internal
```
**Output:**
- Discovers vulnerability
- Shows all available exploit options:
  - Metasploit modules (automated)
  - Exploit-DB scripts (manual)
  - GitHub PoCs (research/customization)
- **Value:** Multiple attack paths for pen testing

## Future Enhancements

### Advanced Features
- [ ] Shodan integration (check if vuln is internet-exposed)
- [ ] GreyNoise integration (is this vuln being actively scanned?)
- [ ] Censys integration (certificate transparency logs)
- [ ] Social media threat intelligence (Twitter/Reddit mentions)
- [ ] Darkweb monitoring (exploit sales, ransom mentions)

### ML/AI Enhancements
- [ ] Custom EPSS model trained on client's industry
- [ ] Correlation between multiple CVEs for exploit chains
- [ ] Automated exploit PoC validation
- [ ] Natural language summaries of threat landscape

## References

- [NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [EPSS User Guide](https://www.first.org/epss/user-guide)
- [GitHub REST API](https://docs.github.com/en/rest)
- [Vulners API](https://vulners.com/docs)
