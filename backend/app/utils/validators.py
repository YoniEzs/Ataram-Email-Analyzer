"""
Validation utilities
"""

import ipaddress
import re
from typing import Tuple

ALLOWED_EXTENSIONS = {'eml', 'msg'}

_DOMAIN_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$',
    re.IGNORECASE,
)


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_domain(domain: str) -> bool:
    """Return True if domain is a syntactically valid, publicly resolvable domain.

    Rejects: empty strings, oversized labels, localhost/private TLD keywords,
    and raw IP addresses — all of which could be used for SSRF.
    """
    if not domain or len(domain) > 253:
        return False
    if not _DOMAIN_RE.match(domain):
        return False
    parts = domain.lower().split('.')
    blocked = {'localhost', 'local', 'internal', 'corp', 'home', 'lan', 'test', 'example', 'invalid'}
    return parts[-1] not in blocked and parts[0] != 'localhost'


def validate_public_ip(ip: str) -> bool:
    """Return True if ip is a syntactically valid, globally-routable address.

    Rejects private, loopback, link-local, multicast, and reserved ranges.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_global
            and not addr.is_loopback
            and not addr.is_private
            and not addr.is_link_local
            and not addr.is_multicast
            and not addr.is_reserved
            and not addr.is_unspecified
        )
    except ValueError:
        return False


def validate_email_file(file_data: bytes, filename: str) -> Tuple[bool, str]:
    """Validate email file content.

    Returns:
        (is_valid, error_message)
    """
    if not file_data:
        return False, "File is empty"

    if len(file_data) < 10:
        return False, "File is too small to be a valid email"

    if len(file_data) > 50 * 1024 * 1024:
        return False, "File exceeds maximum size of 50MB"

    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

    if ext == 'eml':
        try:
            content = file_data[:1000].decode('utf-8', errors='ignore')
            required_indicators = ['From:', 'To:', 'Subject:', 'Date:']
            if not any(indicator in content for indicator in required_indicators):
                return False, "File does not appear to be a valid EML file"
        except Exception:
            return False, "Unable to read EML file content"

    elif ext == 'msg':
        if not file_data.startswith(b"\xD0\xCF\x11\xE0"):
            return False, "File does not appear to be a valid MSG file"

    return True, ""
