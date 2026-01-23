"""
OSINT (Open Source Intelligence) enrichment for vulnerability findings.

This module integrates multiple threat intelligence sources to provide
comprehensive context about vulnerabilities:
- CISA KEV: Known Exploited Vulnerabilities catalog
- GitHub: Community exploit PoCs
- Vulners: Aggregated exploit intelligence
- EPSS: Exploitation probability predictions
- AttackerKB: Community exploitation assessments
- PacketStorm: Additional exploit archives
- OSV: Open source package vulnerabilities
"""

from utils.osint.enricher import OSINTEnricher
from utils.osint.cisa_kev import CISAKEVClient
from utils.osint.github_pocs import GitHubPoCSearch
from utils.osint.vulners import VulnersClient
from utils.osint.epss import EPSSClient
from utils.osint.attackerkb import AttackerKBClient
from utils.osint.packetstorm import PacketStormClient
from utils.osint.osv import OSVClient

__all__ = [
    "OSINTEnricher",
    "CISAKEVClient",
    "GitHubPoCSearch",
    "VulnersClient",
    "EPSSClient",
    "AttackerKBClient",
    "PacketStormClient",
    "OSVClient",
]
