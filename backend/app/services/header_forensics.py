"""
Header Forensics Service
Extracts routing intelligence from email Received headers.
"""

from typing import Any, Dict, List, Optional
import logging
import re

from app.utils.extractors import iter_ip_candidates, is_global_ip

logger = logging.getLogger(__name__)

# Timezone offset in a Date: header. RFC 5322 spells it "+0300"; the MSG
# parser falls back to datetime.isoformat(), which spells it "+03:00". Both
# are accepted and reported in the RFC 5322 form.
_TZ_PATTERN = re.compile(r'([+-]\d{2}):?(\d{2})(?!\d)')


class HeaderForensicsService:
    """Extracts routing and timezone intelligence from email headers."""

    def analyze(self, hops: List[str], date_header: str, sender_domain: str) -> Dict[str, Any]:
        """
        Analyze Received: hop chain and Date: header for forensic signals.

        Args:
            hops: List of raw Received: header strings (newest first)
            date_header: Raw Date: header value
            sender_domain: Sender domain for context

        Returns:
            {
                'public_ips': list of unique public IPs in route order,
                'hop_count': total number of hops,
                'originating_ip': first public IP in the chain (oldest hop),
                'timezone_offset': timezone string from Date header e.g. "+0300"
            }
        """
        try:
            public_ips: List[str] = []
            seen: set = set()

            for hop in hops:
                for ip_str in iter_ip_candidates(hop):
                    if ip_str in seen or not is_global_ip(ip_str):
                        continue
                    public_ips.append(ip_str)
                    seen.add(ip_str)

            # Originating IP: oldest hop = last item in list (hops are newest-first).
            originating_ip: Optional[str] = None
            for hop in reversed(hops):
                for ip_str in iter_ip_candidates(hop):
                    if is_global_ip(ip_str):
                        originating_ip = ip_str
                        break
                if originating_ip:
                    break

            timezone_offset: Optional[str] = None
            if date_header:
                tz_match = _TZ_PATTERN.search(date_header)
                if tz_match:
                    timezone_offset = tz_match.group(1) + tz_match.group(2)

            return {
                'public_ips': public_ips,
                'hop_count': len(hops),
                'originating_ip': originating_ip,
                'timezone_offset': timezone_offset,
            }

        except Exception as e:
            logger.warning(f'[HeaderForensicsService] Analysis failed: {e}')
            return {
                'public_ips': [],
                'hop_count': 0,
                'originating_ip': None,
                'timezone_offset': None,
            }
