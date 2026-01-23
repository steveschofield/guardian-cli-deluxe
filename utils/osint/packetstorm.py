"""
PacketStorm Security Client

Searches PacketStorm for exploit archives and security advisories.
"""

import requests
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
from utils.osint.base import OSINTClient


class PacketStormClient(OSINTClient):
    """
    Search PacketStorm Security for exploits and advisories

    PacketStorm is one of the oldest and most comprehensive exploit
    archives, containing:
    - Exploit code and PoCs
    - Security advisories
    - Whitepapers and tools
    - Shellcode and payloads

    Note: PacketStorm doesn't have an official API, so this uses
    web scraping which may be fragile to site changes.
    """

    BASE_URL = "https://packetstormsecurity.com"
    SEARCH_URL = f"{BASE_URL}/search/"

    def __init__(self, config: Dict, logger=None):
        super().__init__(config, logger)
        ps_config = config.get("osint", {}).get("sources", {}).get("packetstorm", {})
        self.timeout = ps_config.get("timeout", 15)
        self.max_results = ps_config.get("max_results", 5)
        self.user_agent = "Guardian-OSINT/1.0"

    def _get_enabled_status(self) -> bool:
        """Check if PacketStorm is enabled"""
        return self.config.get("osint", {}).get("sources", {}).get("packetstorm", {}).get("enabled", True)

    def search_exploits(self, cve_id: str) -> List[Dict]:
        """
        Search PacketStorm for exploits related to a CVE

        Args:
            cve_id: CVE identifier

        Returns:
            List of exploit/advisory dicts with title, url, date, etc.
        """
        if not self.enabled:
            return []

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml",
        }

        params = {
            "q": cve_id,
        }

        try:
            response = requests.get(
                self.SEARCH_URL,
                params=params,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            response.raise_for_status()

            # Parse HTML results
            soup = BeautifulSoup(response.content, 'html.parser')

            results = []

            # Find all result entries (dl tags with class 'file')
            for dl in soup.find_all('dl', class_='file'):
                try:
                    # Extract title and URL
                    dt = dl.find('dt')
                    if not dt:
                        continue

                    link = dt.find('a')
                    if not link:
                        continue

                    title = link.get_text(strip=True)
                    url = link.get('href', '')

                    # Make URL absolute if relative
                    if url.startswith('/'):
                        url = f"{self.BASE_URL}{url}"

                    # Extract date
                    date_elem = dl.find('dd', class_='datetime')
                    date = date_elem.get_text(strip=True) if date_elem else "Unknown"

                    # Extract description/tags
                    dd_tags = dl.find_all('dd')
                    tags = []
                    for dd in dd_tags:
                        if 'tags' in dd.get('class', []):
                            tags = [a.get_text(strip=True) for a in dd.find_all('a')]

                    # Determine type based on tags or title
                    exploit_type = "unknown"
                    if any(tag in ['exploit', 'dos'] for tag in tags):
                        exploit_type = "exploit"
                    elif 'advisory' in tags:
                        exploit_type = "advisory"
                    elif 'poc' in title.lower() or 'exploit' in title.lower():
                        exploit_type = "exploit"

                    results.append({
                        "title": title,
                        "url": url,
                        "date": date,
                        "type": exploit_type,
                        "tags": tags,
                        "source": "PacketStorm"
                    })

                    if len(results) >= self.max_results:
                        break

                except Exception as e:
                    self.log_debug(f"Error parsing PacketStorm result: {e}")
                    continue

            if results:
                self.log_info(f"Found {len(results)} PacketStorm entries for {cve_id}")

            return results

        except requests.exceptions.HTTPError as e:
            self.log_error(f"PacketStorm HTTP error for {cve_id}: {e}")
            return []

        except requests.exceptions.Timeout:
            self.log_warning(f"PacketStorm timeout for {cve_id}")
            return []

        except Exception as e:
            self.log_error(f"PacketStorm search failed for {cve_id}: {e}")
            return []

    def search_multiple(self, cve_ids: List[str]) -> Dict[str, List[Dict]]:
        """
        Search PacketStorm for multiple CVEs

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dict mapping CVE ID to list of exploits/advisories
        """
        results = {}

        for cve_id in cve_ids:
            exploits = self.search_exploits(cve_id)
            if exploits:
                results[cve_id] = exploits

        return results

    def get_exploit_types(self, cve_id: str) -> List[str]:
        """
        Get list of exploit types available for a CVE

        Args:
            cve_id: CVE identifier

        Returns:
            List of unique exploit types found
        """
        exploits = self.search_exploits(cve_id)
        types = set()

        for exploit in exploits:
            types.add(exploit.get("type", "unknown"))

        return list(types)
