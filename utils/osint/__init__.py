"""
OSINT (Open Source Intelligence) enrichment for vulnerability findings.

This module integrates multiple threat intelligence sources to provide
comprehensive context about vulnerabilities:
- CISA KEV: Known Exploited Vulnerabilities catalog
- GitHub: Community exploit PoCs
- Vulners: Aggregated exploit intelligence
"""

from utils.osint.enricher import OSINTEnricher
from utils.osint.cisa_kev import CISAKEVClient
from utils.osint.github_pocs import GitHubPoCSearch
from utils.osint.vulners import VulnersClient

__all__ = [
    "OSINTEnricher",
    "CISAKEVClient",
    "GitHubPoCSearch",
    "VulnersClient",
]
