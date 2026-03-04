"""
WHOIS Service
Domain registration information lookup
"""

from typing import Optional, Dict, Any
from datetime import datetime

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


class WhoisService:
    """Service for WHOIS domain lookups"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        if not WHOIS_AVAILABLE:
            self.whois_module = None
        else:
            self.whois_module = whois

    def lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Perform WHOIS lookup for domain

        Returns domain registration info or None if unavailable
        """
        if not domain or not self.whois_module:
            return None

        try:
            w = self.whois_module.whois(domain)

            def format_value(value):
                """Format various value types to strings"""
                if isinstance(value, list):
                    value = value[0] if value else None
                if isinstance(value, datetime):
                    return value.isoformat()
                return str(value) if value is not None else None

            return {
                'domain': domain,
                'registrar': getattr(w, 'registrar', None),
                'creation_date': format_value(getattr(w, 'creation_date', None)),
                'expiration_date': format_value(getattr(w, 'expiration_date', None)),
                'updated_date': format_value(getattr(w, 'updated_date', None)),
                'status': getattr(w, 'status', None),
                'name_servers': list(getattr(w, 'name_servers', []) or []),
            }
        except Exception:
            return None
