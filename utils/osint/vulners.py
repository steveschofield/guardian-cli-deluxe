"""
Vulners API Client

Aggregates exploit intelligence from 100+ sources including
Metasploit, Exploit-DB, PacketStorm, and more.
"""

import requests
from typing import Dict, Optional, List
from utils.osint.base import OSINTClient


class VulnersClient(OSINTClient):
    """
    Client for Vulners API

    Requires: API key (free registration at https://vulners.com/userinfo)
    Rate limits: 100 requests/day (free), 10,000/day (paid $99/mo)
    """

    API_URL = "https://vulners.com/api/v3/search/lucene/"
    BURP_API_URL = "https://vulners.com/api/v3/burp/software/"

    def __init__(self, config: Dict, logger=None):
        # Set api_key BEFORE calling super().__init__() because _get_enabled_status() needs it
        vulners_config = config.get("osint", {}).get("sources", {}).get("vulners", {})
        self.api_key = vulners_config.get("api_key", None)
        self.timeout = vulners_config.get("timeout", 10)

        super().__init__(config, logger)

        if self.enabled and not self.api_key:
            self.log_warning("Vulners API enabled but no API key configured")

    def _get_enabled_status(self) -> bool:
        """Check if Vulners API is enabled"""
        enabled = self.config.get("osint", {}).get("sources", {}).get("vulners", {}).get("enabled", False)
        return enabled and self.api_key is not None

    def lookup(self, cve_id: str) -> Optional[Dict]:
        """
        Lookup CVE in Vulners database

        Args:
            cve_id: CVE identifier (e.g., "CVE-2017-0143")

        Returns:
            Vulners data dict if found, None otherwise
        """
        if not self.enabled:
            return None

        payload = {
            "query": f"cve:{cve_id}",
            "apiKey": self.api_key,
        }

        try:
            response = requests.post(
                self.API_URL,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            if data.get("result") != "OK":
                error_msg = data.get("data", {}).get("error", "Unknown error")
                self.log_debug(f"Vulners lookup failed for {cve_id}: {error_msg}")
                return None

            search_results = data.get("data", {}).get("search", [])
            if not search_results:
                return None

            vuln = search_results[0]  # Take first result

            # Extract exploit sources
            source_data = vuln.get("sourceData", {})
            exploits = {
                "metasploit": source_data.get("metasploit", []),
                "exploitdb": source_data.get("exploitdb", []),
                "packetstorm": source_data.get("packetstorm", []),
                "githubexploit": source_data.get("githubexploit", []),
            }

            # Count total exploits
            exploit_count = sum(len(v) if isinstance(v, list) else 1 for v in exploits.values() if v)

            result = {
                "cve_id": vuln.get("id"),
                "title": vuln.get("title"),
                "description": vuln.get("description", "")[:500],  # Limit length
                "cvss_score": vuln.get("cvss", {}).get("score"),
                "cvss_vector": vuln.get("cvss", {}).get("vector"),
                "cwe": vuln.get("cwe", []),
                "exploit_count": exploit_count,
                "ai_score": vuln.get("ai_score"),
                "exploits": exploits,
                "references": vuln.get("references", [])[:10],  # Limit references
                "published": vuln.get("published"),
                "modified": vuln.get("modified"),
            }

            self.log_info(f"Found Vulners data for {cve_id} ({exploit_count} exploits)")
            return result

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                self.log_warning(f"Vulners API authentication failed")
            elif e.response.status_code == 429:
                self.log_warning(f"Vulners API rate limit exceeded")
            else:
                self.log_error(f"Vulners API HTTP error for {cve_id}: {e}")
            return None

        except requests.exceptions.Timeout:
            self.log_warning(f"Vulners API timeout for {cve_id}")
            return None

        except Exception as e:
            self.log_error(f"Vulners API lookup failed for {cve_id}: {e}")
            return None

    def lookup_software(self, software: str, version: Optional[str] = None) -> List[Dict]:
        """
        Search vulnerabilities by software name and version

        Args:
            software: Software name (e.g., "Microsoft Windows Server 2008")
            version: Optional version (e.g., "R2 SP1")

        Returns:
            List of vulnerability dicts
        """
        if not self.enabled:
            return []

        payload = {
            "software": software,
            "apiKey": self.api_key,
        }
        if version:
            payload["version"] = version

        try:
            response = requests.post(
                self.BURP_API_URL,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            if data.get("result") != "OK":
                return []

            vulns = data.get("data", {}).get("search", [])
            self.log_info(f"Found {len(vulns)} vulnerabilities for {software} {version or ''}")

            results = []
            for vuln in vulns[:20]:  # Limit to first 20
                results.append({
                    "cve_id": vuln.get("id"),
                    "title": vuln.get("title"),
                    "cvss_score": vuln.get("cvss", {}).get("score"),
                    "exploit_count": vuln.get("exploit_count", 0),
                })

            return results

        except Exception as e:
            self.log_error(f"Vulners software lookup failed for {software}: {e}")
            return []

    def check_api_status(self) -> bool:
        """
        Check if Vulners API is accessible and API key is valid

        Returns:
            True if API is working, False otherwise
        """
        if not self.enabled:
            return False

        payload = {
            "query": "cve:CVE-2017-0144",  # Known CVE for testing
            "apiKey": self.api_key,
        }

        try:
            response = requests.post(self.API_URL, json=payload, timeout=5)
            response.raise_for_status()
            data = response.json()
            return data.get("result") == "OK"

        except Exception:
            return False
