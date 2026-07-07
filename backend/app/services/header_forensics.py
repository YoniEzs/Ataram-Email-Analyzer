"""
Header Forensics Service
Extracts routing intelligence from email Received headers.
"""

from typing import Any, Dict, Iterable, List, Optional
import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

# Bracketed IPv4/IPv6 literals in Received: headers, including IPv6: prefixes.
_BRACKETED_IP_PATTERN = re.compile(r'\[([^\]\s]+)\]')
# Conservative unbracketed IPv4 fallback for non-standard Received: headers.
_UNBRACKETED_IPV4_PATTERN = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
# Regex to extract timezone offset from Date: headers, e.g. "+0300" or "-0500".
_TZ_PATTERN = re.compile(r'([+-]\d{4})')


def _normalize_ip_candidate(candidate: str) -> str:
    candidate = candidate.strip()
    if candidate.lower().startswith('ipv6:'):
        return candidate[5:]
    return candidate


def _iter_ip_candidates(hop: str) -> Iterable[str]:
    """Yield IP-like candidates from one Received: header."""
    if not hop:
        return

    yielded = set()
    for candidate in _BRACKETED_IP_PATTERN.findall(hop):
        normalized = _normalize_ip_candidate(candidate)
        if normalized not in yielded:
            yielded.add(normalized)
            yield normalized

    for candidate in _UNBRACKETED_IPV4_PATTERN.findall(hop):
        if candidate not in yielded:
            yielded.add(candidate)
            yield candidate


def _is_global_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


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
                for ip_str in _iter_ip_candidates(hop):
                    if ip_str in seen or not _is_global_ip(ip_str):
                        continue
                    public_ips.append(ip_str)
                    seen.add(ip_str)

            # Originating IP: oldest hop = last item in list (hops are newest-first).
            originating_ip: Optional[str] = None
            for hop in reversed(hops):
                for ip_str in _iter_ip_candidates(hop):
                    if _is_global_ip(ip_str):
                        originating_ip = ip_str
                        break
                if originating_ip:
                    break

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
            logger.warning(f'[HeaderForensicsService] Analysis failed: {e}')
            return {
                'public_ips': [],
                'hop_count': 0,
                'originating_ip': None,
                'timezone_offset': None,
            }