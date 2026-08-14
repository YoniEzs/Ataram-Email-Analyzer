"""
Header Forensics Service
Extracts routing intelligence from email Received headers
"""

import re
import ipaddress
import logging
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

# Regex to find bracketed IPv4 addresses in Received: headers
_IP_PATTERN = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')
# Regex to extract timezone offset from Date: headers, e.g. "+0300" or "-0500"
_TZ_PATTERN = re.compile(r'([+-]\d{4})')


class HeaderForensicsService:
    """Extracts routing and timezone intelligence from email headers"""

    def __init__(self):
        pass

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
                for ip_str in _IP_PATTERN.findall(hop):
                    if ip_str in seen:
                        continue
                    try:
                        if ipaddress.ip_address(ip_str).is_global:
                            public_ips.append(ip_str)
                            seen.add(ip_str)
                    except ValueError:
                        pass

            # Originating IP: oldest hop = last item in list (hops are newest-first)
            originating_ip: Optional[str] = None
            for hop in reversed(hops):
                for ip_str in _IP_PATTERN.findall(hop):
                    try:
                        if ipaddress.ip_address(ip_str).is_global:
                            originating_ip = ip_str
                            break
                    except ValueError:
                        pass
                if originating_ip:
                    break

            # Extract timezone offset from date header
            timezone_offset: Optional[str] = None
            if date_header:
                tz_match = _TZ_PATTERN.search(date_header)
                if tz_match:
                    timezone_offset = tz_match.group(1)

            return {
                'public_ips': public_ips,
                'hop_count': len(hops),
                'originating_ip': originating_ip,
                'timezone_offset': timezone_offset,
            }

        except Exception as e:
            logger.warning(f"[HeaderForensicsService] Analysis failed: {e}")
            return {
                'public_ips': [],
                'hop_count': 0,
                'originating_ip': None,
                'timezone_offset': None,
            }
