# OSINT Sources

Guardian CLI integrates multiple OSINT (Open Source Intelligence) sources to enrich vulnerability findings with comprehensive threat intelligence.

## Available Sources

### 1. CISA KEV (Known Exploited Vulnerabilities)
- **Status**: Active
- **Cost**: FREE
- **Rate Limit**: None (static JSON)
- **Purpose**: Identifies CVEs actively exploited in the wild
- **Source**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Config**: `osint.sources.cisa_kev`

### 2. GitHub Exploit PoC Search
- **Status**: Active
- **Cost**: FREE
- **Rate Limit**: 60/hour (no auth), 5000/hour (with token)
- **Purpose**: Searches GitHub for community exploit proof-of-concepts
- **Config**: `osint.sources.github`
- **Requires**: Optional GitHub Personal Access Token

### 3. Vulners API
- **Status**: Active
- **Cost**: FREE (100 req/day), PAID ($99/mo for 10,000 req/day)
- **Purpose**: Aggregates exploit intelligence from 100+ sources
- **Source**: https://vulners.com
- **Config**: `osint.sources.vulners`
- **Requires**: API key (free tier available)

### 4. EPSS (Exploit Prediction Scoring System) ✨ NEW
- **Status**: Active
- **Cost**: FREE
- **Rate Limit**: None
- **Purpose**: Provides exploitation probability predictions (0-1 scale)
- **Source**: https://api.first.org/data/v1/epss
- **Config**: `osint.sources.epss`
- **Features**:
  - Daily probability scores for CVE exploitation likelihood
  - Percentile rankings
  - Automatic risk level classification (critical/high/medium/low)

### 5. AttackerKB ✨ NEW
- **Status**: Active
- **Cost**: FREE tier available, PAID for higher limits
- **Purpose**: Community-driven exploitation assessments from Rapid7
- **Source**: https://attackerkb.com
- **Config**: `osint.sources.attackerkb`
- **Requires**: API key (free tier available)
- **Features**:
  - Rapid7 researcher analysis
  - Community exploitation ratings
  - Real-world attack observations
  - Exploit maturity assessments

### 6. PacketStorm Security ✨ NEW
- **Status**: Active
- **Cost**: FREE
- **Rate Limit**: None (web scraping)
- **Purpose**: One of the oldest exploit archives
- **Source**: https://packetstormsecurity.com
- **Config**: `osint.sources.packetstorm`
- **Features**:
  - Exploit code and PoCs
  - Security advisories
  - Whitepapers and tools
  - Shellcode and payloads
- **Note**: Uses web scraping, may be fragile to site changes

### 7. OSV (Open Source Vulnerabilities) ✨ NEW
- **Status**: Active
- **Cost**: FREE
- **Rate Limit**: None
- **Purpose**: Distributed vulnerability database for open source packages
- **Source**: https://api.osv.dev
- **Config**: `osint.sources.osv`
- **Features**:
  - Aggregates data from multiple ecosystems:
    - GitHub Security Advisories
    - Python PyPI advisories
    - Go vulndb
    - RustSec
    - npm advisories
    - Maven Central
  - Package-level vulnerability information
  - CVSS scoring and references

## Configuration

All OSINT sources can be configured in `config/guardian.yaml` under the `osint` section:

```yaml
osint:
  enabled: true
  cache_ttl_hours: 24

  sources:
    # Enable/disable individual sources
    cisa_kev:
      enabled: true

    github:
      enabled: true
      token: ""  # Optional but recommended

    vulners:
      enabled: true
      api_key: ""  # Required

    epss:
      enabled: true
      high_risk_threshold: 0.7

    attackerkb:
      enabled: true
      api_key: ""  # Required
      min_rapid7_score: 3

    packetstorm:
      enabled: true
      max_results: 5

    osv:
      enabled: true
      include_aliases: true
```

## Enrichment Data Structure

The OSINT enricher returns enrichment data keyed by finding ID with the following structure:

```python
{
    "finding_id": {
        "cve_data": {},
        "kev_status": {
            "CVE-YYYY-XXXXX": {
                "cve_id": "CVE-YYYY-XXXXX",
                "vulnerability_name": "...",
                "date_added": "YYYY-MM-DD",
                "due_date": "YYYY-MM-DD",
                "required_action": "..."
            }
        },
        "github_pocs": [
            {
                "name": "username/repo",
                "url": "https://github.com/...",
                "stars": 100,
                "language": "Python",
                "description": "..."
            }
        ],
        "vulners_data": {
            "CVE-YYYY-XXXXX": {
                "id": "CVE-YYYY-XXXXX",
                "cvss": 9.8,
                "exploits": [...],
                "bulletins": [...]
            }
        },
        "epss_scores": {
            "CVE-YYYY-XXXXX": {
                "epss": 0.85,
                "percentile": 0.95,
                "risk_level": "critical",
                "epss_percentage": "85.00%",
                "percentile_rank": "95.0th"
            }
        },
        "attackerkb_assessments": {
            "CVE-YYYY-XXXXX": {
                "rapid7_analysis": "...",
                "rapid7_score": 4,
                "exploitability_score": 8,
                "attacker_value": 9,
                "risk_level": "critical"
            }
        },
        "packetstorm_exploits": [
            {
                "title": "...",
                "url": "https://packetstormsecurity.com/...",
                "date": "YYYY-MM-DD",
                "type": "exploit",
                "tags": ["exploit", "poc"]
            }
        ],
        "osv_data": {
            "CVE-YYYY-XXXXX": {
                "id": "CVE-YYYY-XXXXX",
                "summary": "...",
                "affected_packages": [
                    {
                        "ecosystem": "PyPI",
                        "name": "package-name",
                        "purl": "pkg:pypi/package-name"
                    }
                ],
                "references": [...]
            }
        }
    }
}
```

## Usage

The OSINT enricher is automatically used by Guardian CLI when enabled in the configuration. It enriches vulnerability findings during scanning and includes the enrichment data in reports.

### Programmatic Usage

```python
from utils.osint import OSINTEnricher

# Initialize enricher with config
enricher = OSINTEnricher(config, logger)

# Enrich findings
enrichment_data = enricher.enrich_findings(findings)

# Get summary of OSINT sources
summary = enricher.get_summary()
```

## API Keys and Authentication

### Required API Keys

1. **Vulners**: Sign up at https://vulners.com/userinfo
   - Free tier: 100 requests/day
   - No credit card required

2. **AttackerKB**: Sign up at https://attackerkb.com/account
   - Free tier available
   - No credit card required

### Optional API Keys

1. **GitHub**: Create at https://github.com/settings/tokens
   - Increases rate limit from 60/hour to 5000/hour
   - Required scopes: `public_repo` (read-only)

## Dependencies

The new OSINT sources require the following Python packages (automatically installed):

- `beautifulsoup4>=4.12.0` - For PacketStorm web scraping
- `requests>=2.31.0` - For HTTP requests to OSINT APIs

## Performance Considerations

- **EPSS**: Very fast, single API call for multiple CVEs
- **AttackerKB**: One API call per CVE, may be slower for many CVEs
- **PacketStorm**: Web scraping-based, slower and less reliable
- **OSV**: Fast, supports batch queries

## Recommendations

1. **Enable all sources** for maximum coverage
2. **Set up API keys** for Vulners and AttackerKB (both have free tiers)
3. **Add GitHub token** if scanning frequently (rate limit improvement)
4. **Monitor rate limits** when scanning large numbers of CVEs
5. **Use caching** (default 24 hours) to reduce API calls

## Future Enhancements

Potential additional OSINT sources to consider:

- ExploitDB API (local database)
- NVD (National Vulnerability Database)
- VulnCheck KEV
- Tenable VPR (Vulnerability Priority Rating)
- GreyNoise (for threat intelligence correlation)
