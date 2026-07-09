"""
VirusTotal Service
Looks up attachment hashes against the VirusTotal v3 API.

Results are cached aggressively (hashes are immutable) and every failure
degrades to "no data" — a VT outage or missing key never blocks analysis.
"""

import logging
from typing import Any, Dict, List, Optional

from app.utils.cache import cache_get, cache_set

logger = logging.getLogger(__name__)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

_API_BASE = 'https://www.virustotal.com/api/v3'
_CACHE_TTL_SECONDS = 86_400
_MAX_LOOKUPS_PER_EMAIL = 4


class VirusTotalService:
    """File-hash reputation lookups against VirusTotal."""

    def __init__(self, api_key: Optional[str], timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests is required. Install: pip install requests")

    def check_hashes(self, sha256_hashes: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """Check up to _MAX_LOOKUPS_PER_EMAIL unique hashes."""
        results: Dict[str, Optional[Dict[str, Any]]] = {}
        if not self.api_key:
            return results

        unique = list(dict.fromkeys(h for h in sha256_hashes if h))
        for sha256 in unique[:_MAX_LOOKUPS_PER_EMAIL]:
            results[sha256] = self.check_hash(sha256)
        return results

    def check_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Return a verdict summary for one file hash, or None if unknown."""
        if not sha256 or not self.api_key:
            return None

        cached = cache_get(f"vt:{sha256}")
        if cached is not None:
            return cached

        try:
            response = requests.get(
                f"{_API_BASE}/files/{sha256}",
                headers={'x-apikey': self.api_key, 'Accept': 'application/json'},
                timeout=self.timeout,
            )
            if response.status_code == 404:
                # Unknown to VT — cache the miss so we don't burn quota
                miss: Dict[str, Any] = {'known': False}
                cache_set(f"vt:{sha256}", miss, _CACHE_TTL_SECONDS)
                return miss
            response.raise_for_status()

            attributes = response.json().get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {}) or {}
            result: Dict[str, Any] = {
                'known': True,
                'malicious': int(stats.get('malicious', 0) or 0),
                'suspicious': int(stats.get('suspicious', 0) or 0),
                'harmless': int(stats.get('harmless', 0) or 0),
                'undetected': int(stats.get('undetected', 0) or 0),
                'reputation': attributes.get('reputation'),
                'type_description': attributes.get('type_description'),
                'popular_threat_label': (
                    (attributes.get('popular_threat_classification') or {})
                    .get('suggested_threat_label')
                ),
            }
            cache_set(f"vt:{sha256}", result, _CACHE_TTL_SECONDS)
            return result
        except Exception as e:
            logger.warning(f"[VirusTotalService] Lookup failed for {sha256[:12]}…: {e}")
            return None
