"""
IP Reputation Service
Checks IP addresses against reputation databases
"""

import logging
from typing import Optional, Dict, Any
from app.utils.cache import cache_get, cache_set

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class IPReputationService:
    """Service for checking IP reputation via AbuseIPDB"""

    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests is required. Install: pip install requests")

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Check IP reputation using AbuseIPDB

        Args:
            ip: IP address to check

        Returns:
            Reputation data or None if unavailable
        """
        if not ip or not self.api_key:
            return None

        cached = cache_get(f"ip:{ip}")
        if cached is not None:
            return cached

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }

            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json().get('data', {})
            result = {
                'ipAddress': data.get('ipAddress'),
                'abuseConfidenceScore': data.get('abuseConfidenceScore'),
                'totalReports': data.get('totalReports'),
                'numDistinctUsers': data.get('numDistinctUsers'),
                'lastReportedAt': data.get('lastReportedAt'),
                'usageType': data.get('usageType'),
                'isp': data.get('isp'),
                'domain': data.get('domain'),
                'hostnames': data.get('hostnames'),
                'countryCode': data.get('countryCode'),
                'countryName': data.get('countryName'),
            }
            cache_set(f"ip:{ip}", result, 21600)
            return result
        except Exception as e:
            logger.warning(f"[IPReputationService] AbuseIPDB check failed for {ip}: {e}")
            return None

