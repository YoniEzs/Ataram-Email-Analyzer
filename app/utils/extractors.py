"""
Information extraction utilities
"""

import re
import ipaddress
from typing import Optional, List
from email.utils import getaddresses, parseaddr


IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)


def _first_address(header: str) -> str:
    """
    First address in a header that may legitimately hold several.

    `parseaddr` returns ('', '') for a mailbox-LIST — which RFC 5322 permits in
    From, and which mail clients render normally. One extra address therefore
    silently disabled every sender-domain check downstream: SPF, DMARC, WHOIS,
    domain age and the Return-Path/Reply-To comparisons all key on this value,
    and a measured email dropped from score 38 to 2 on the strength of a second
    address in From. `getaddresses` parses the list properly.
    """
    if not header:
        return ''
    try:
        parsed = getaddresses([header])
    except Exception:
        return ''
    for _display, address in parsed:
        if address and '@' in address:
            return address
    return ''


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

    addr = _first_address(from_header)
    if '@' in addr:
        return addr.split('@')[1].strip().lower().strip('<>;:, ')
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
        # Handle full email headers like "Name <email@domain.com>", including
        # the multi-address case parseaddr cannot represent.
        if '<' in email_or_header or '>' in email_or_header or ',' in email_or_header:
            addr = _first_address(email_or_header) or parseaddr(email_or_header)[1]
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
        received_headers: List of Received headers

    Returns:
        First public IP found or None
    """
    if not received_headers:
        return None

    # Start from the last (oldest) Received header
    for header in reversed(received_headers):
        # Find all IPv4 addresses in this header
        for ip in IPV4_PATTERN.findall(header):
            if is_public_ipv4(ip):
                return ip

    return None
