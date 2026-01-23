"""
AttackerKB Client

Provides community-driven exploitation assessments and intelligence.
"""

import requests
from typing import Dict, List, Optional
from utils.osint.base import OSINTClient


class AttackerKBClient(OSINTClient):
    """
    Query AttackerKB for community exploitation assessments

    AttackerKB provides security community assessments of vulnerability
    exploitability, including:
    - Rapid7 researcher analysis
    - Community exploitation ratings
    - Real-world attack observations
    - Exploit maturity assessments

    API: https://api.attackerkb.com/v1/
    Requires: API key (free tier available)
    """

    API_URL = "https://api.attackerkb.com/v1"

    def __init__(self, config: Dict, logger=None):
        super().__init__(config, logger)
        akb_config = config.get("osint", {}).get("sources", {}).get("attackerkb", {})
        self.api_key = akb_config.get("api_key", None)
        self.timeout = akb_config.get("timeout", 10)
        self.min_rapid7_score = akb_config.get("min_rapid7_score", 3)

    def _get_enabled_status(self) -> bool:
        """Check if AttackerKB is enabled"""
        return self.config.get("osint", {}).get("sources", {}).get("attackerkb", {}).get("enabled", True)

    def get_assessment(self, cve_id: str) -> Optional[Dict]:
        """
        Get AttackerKB assessment for a CVE

        Args:
            cve_id: CVE identifier

        Returns:
            Assessment data dict or None if not found
        """
        if not self.enabled or not self.api_key:
            if not self.api_key and self.enabled:
                self.log_debug("AttackerKB API key not configured")
            return None

        # Remove CVE- prefix if present for search
        cve_num = cve_id.replace("CVE-", "")

        headers = {
            "Accept": "application/json",
            "User-Agent": "Guardian-OSINT/1.0",
            "X-API-Key": self.api_key
        }

        params = {
            "q": cve_num,
            "size": 1
        }

        try:
            response = requests.get(
                f"{self.API_URL}/topics",
                headers=headers,
                params=params,
                timeout=self.timeout
            )

            # Handle authentication errors gracefully
            if response.status_code == 401:
                self.log_warning("AttackerKB API key invalid or expired")
                return None

            response.raise_for_status()
            data = response.json()

            topics = data.get("data", [])
            if not topics:
                return None

            topic = topics[0]

            # Extract relevant assessment data
            assessment = {
                "id": topic.get("id"),
                "name": topic.get("name"),
                "rapid7_analysis": topic.get("rapid7Analysis"),
                "rapid7_score": topic.get("rapid7AnalysisScore", 0),
                "exploitability_score": topic.get("exploitabilityScore", 0),
                "attacker_value": topic.get("attackerValue", 0),
                "assessment_count": topic.get("assessmentCount", 0),
                "exploit_published": topic.get("exploitPublished", False),
                "url": f"https://attackerkb.com/topics/{topic.get('id')}",
                "created": topic.get("created"),
                "revised": topic.get("revised"),
            }

            # Determine risk level based on scores
            rapid7_score = assessment["rapid7_score"]
            if rapid7_score >= 4:
                assessment["risk_level"] = "critical"
            elif rapid7_score >= 3:
                assessment["risk_level"] = "high"
            elif rapid7_score >= 2:
                assessment["risk_level"] = "medium"
            else:
                assessment["risk_level"] = "low"

            self.log_info(f"Found AttackerKB assessment for {cve_id}")
            return assessment

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                self.log_debug(f"No AttackerKB assessment for {cve_id}")
            else:
                self.log_error(f"AttackerKB API HTTP error for {cve_id}: {e}")
            return None

        except requests.exceptions.Timeout:
            self.log_warning(f"AttackerKB API timeout for {cve_id}")
            return None

        except Exception as e:
            self.log_error(f"AttackerKB query failed for {cve_id}: {e}")
            return None

    def get_assessments(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """
        Get AttackerKB assessments for multiple CVEs

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            Dict mapping CVE ID to assessment data
        """
        results = {}

        for cve_id in cve_ids:
            assessment = self.get_assessment(cve_id)
            if assessment:
                results[cve_id] = assessment

        return results

    def get_high_value_targets(self, cve_ids: List[str]) -> List[str]:
        """
        Filter CVEs to those with high attacker value

        Args:
            cve_ids: List of CVE identifiers

        Returns:
            List of high-value CVE IDs based on Rapid7 analysis
        """
        assessments = self.get_assessments(cve_ids)
        high_value = []

        for cve_id, assessment in assessments.items():
            if assessment.get("rapid7_score", 0) >= self.min_rapid7_score:
                high_value.append(cve_id)

        return high_value
