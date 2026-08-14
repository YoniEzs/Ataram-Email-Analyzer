"""
IP Reputation Service
Checks IP addresses against reputation databases
"""

import logging
from typing import Optional, Dict, Any
from app.utils.cache import cache_get, cache_set, MISS
from app.utils.net_guard import is_public_ip

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# AbuseIPDB is a third party; its response is untrusted input as far as this
# service is concerned. Cap what is read and how long strings may be.
MAX_RESPONSE_BYTES = 512 * 1024
MAX_FIELD_LENGTH = 256
MAX_HOSTNAMES = 10


class IPReputationService:
    """Service for checking IP reputation via AbuseIPDB"""

    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests is required. Install: pip install requests")

    @staticmethod
    def _clip(value: Any) -> Any:
        if isinstance(value, str):
            return value[:MAX_FIELD_LENGTH]
        return value

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

        # The IP is parsed out of Received headers on an untrusted email, so it
        # must be confirmed as a real, routable address before it is spent
        # against the API quota or used as a cache key.
        if not is_public_ip(ip):
            logger.debug("[IPReputationService] Skipping non-public IP")
            return None

        normalised = ip.strip()

        cached = cache_get(f"ip:{normalised}", MISS)
        if cached is not MISS:
            return cached

        try:
            params = {
                'ipAddress': normalised,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }

            response = requests.get(
                ABUSEIPDB_URL,
                params=params,
                headers=headers,
                timeout=self.timeout,
                # A redirect off this host would send the API key somewhere else.
                allow_redirects=False,
            )
            response.raise_for_status()

            if len(response.content) > MAX_RESPONSE_BYTES:
                logger.warning("[IPReputationService] AbuseIPDB response exceeded size cap")
                return None

            data = response.json().get('data', {})
            if not isinstance(data, dict):
                return None

            hostnames = data.get('hostnames')
            if isinstance(hostnames, list):
                hostnames = [self._clip(h) for h in hostnames[:MAX_HOSTNAMES]]
            else:
                hostnames = None

            result = {
                'ipAddress': self._clip(data.get('ipAddress')),
                'abuseConfidenceScore': data.get('abuseConfidenceScore'),
                'totalReports': data.get('totalReports'),
                'numDistinctUsers': data.get('numDistinctUsers'),
                'lastReportedAt': self._clip(data.get('lastReportedAt')),
                'usageType': self._clip(data.get('usageType')),
                'isp': self._clip(data.get('isp')),
                'domain': self._clip(data.get('domain')),
                'hostnames': hostnames,
                'countryCode': self._clip(data.get('countryCode')),
                'countryName': self._clip(data.get('countryName')),
            }
            cache_set(f"ip:{normalised}", result, 21600)
            return result
        except Exception as e:
            # Never let the exception text reach a caller: it can contain the
            # request URL, and requests includes headers in some error paths.
            logger.warning(f"[IPReputationService] AbuseIPDB check failed: {type(e).__name__}")
            cache_set(f"ip:{normalised}", None, 300)
            return None
