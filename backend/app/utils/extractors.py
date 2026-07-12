"""
Information extraction utilities
"""

import re
import ipaddress
from typing import Iterable, Optional, List
from email.utils import parseaddr


IPV4_PATTERN = re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')

# Bracketed IPv4/IPv6 literals in Received: headers, including IPv6: prefixes.
_BRACKETED_IP_PATTERN = re.compile(r'\[([^\]\s]+)\]')
# Conservative unbracketed IPv4 fallback for non-standard Received: headers.
_UNBRACKETED_IPV4_PATTERN = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')


def extract_sender_domain(from_header: str) -> Optional[str]:
    """
    Extract domain from From header

    Args:
        from_header: Email From header

    Returns:
        Domain or None
    """
    if not from_header:
        return None

    name, addr = parseaddr(from_header)
    if '@' in addr:
        return addr.split('@')[1].strip().lower()
    return None

def email_domain(email_or_header: str) -> str:
    """
    Extract domain from email address or header

    Args:
        email_or_header: Email address or header value

    Returns:
        Domain string (empty if not found)
    """
    if not email_or_header:
        return ""

    try:
        # Handle full email headers like "Name <email@domain.com>"
        if '<' in email_or_header or '>' in email_or_header:
            addr = parseaddr(email_or_header)[1]
        else:
            addr = email_or_header.strip()

        if not addr:
            return ""

        if '@' in addr:
            return addr.split('@', 1)[1].strip().lower().strip("<>;:")

        # Try regex extraction
        m = re.search(r"@([^>]+)>?", email_or_header or "")
        return (m.group(1).lower() if m else '').strip()

    except Exception:
        return ""


def _normalize_ip_candidate(candidate: str) -> str:
    candidate = candidate.strip()
    if candidate.lower().startswith('ipv6:'):
        return candidate[5:]
    return candidate


def iter_ip_candidates(hop: str) -> Iterable[str]:
    """Yield IP-like candidates (IPv4 and IPv6) from one Received: header."""
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


def is_global_ip(ip: str) -> bool:
    """Check if a string is a globally-routable IPv4 or IPv6 address."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def is_public_ipv4(ip: str) -> bool:
    """
    Check if IP is a public IPv4 address

    Args:
        ip: IP address string

    Returns:
        True if public IPv4
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_global
    except ValueError:
        return False


def extract_sender_ip(received_headers: List[str]) -> Optional[str]:
    """
    Extract sender IP from Received headers

    Args:
        received_headers: List of Received headers (newest first)

    Returns:
        First public IPv4 or IPv6 address found in the oldest hop, or None
    """
    if not received_headers:
        return None

    # Start from the last (oldest) Received header
    for header in reversed(received_headers):
        for candidate in iter_ip_candidates(header):
            if is_global_ip(candidate):
                return candidate

    return None
