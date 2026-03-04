"""
Information extraction utilities
"""

import re
import ipaddress
from typing import Optional, List
from email.utils import parseaddr


IPV4_PATTERN = re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')


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
