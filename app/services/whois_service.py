"""
WHOIS Service
Domain registration information lookup
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime
from app.utils.cache import cache_get, cache_set, MISS
from app.utils.net_guard import is_public_domain, registrable_domain

logger = logging.getLogger(__name__)

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# WHOIS output is controlled by whoever registered the domain being analysed,
# and every field here is rendered in the UI. Cap the strings so a hostile
# registrar record cannot bloat the response or the cache.
MAX_FIELD_LENGTH = 512
MAX_NAME_SERVERS = 20

def _is_valid_public_domain(domain: str) -> bool:
    return is_public_domain(domain)


class WhoisService:
    """Service for WHOIS domain lookups"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        if not WHOIS_AVAILABLE:
            self.whois_module = None
        else:
            self.whois_module = whois

    @staticmethod
    def _clip(value: Any) -> Optional[str]:
        """Coerce an untrusted WHOIS field to a bounded string."""
        if value is None:
            return None
        if isinstance(value, list):
            value = value[0] if value else None
            if value is None:
                return None
        return str(value)[:MAX_FIELD_LENGTH]

    def lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Perform WHOIS lookup for domain

        Returns domain registration info or None if unavailable
        """
        if not domain or not self.whois_module:
            return None

        if not is_public_domain(domain):
            logger.warning("[WhoisService] Rejected invalid/internal domain")
            return None

        # Look up and cache the registrable domain, not the full hostname:
        # a.example.com, b.example.com and c.example.com all share one WHOIS
        # record, so varying the subdomain must not produce a new lookup.
        normalised = registrable_domain(domain)
        if not normalised:
            return None

        cached = cache_get(f"whois:{normalised}", MISS)
        if cached is not MISS:
            return cached

        try:
            # self.timeout was stored and never used, so the configured
            # WHOIS_TIMEOUT had no effect and the library's own per-socket
            # default applied — across a chained IANA -> registry -> registrar
            # referral, each leg with its own budget.
            try:
                w = self.whois_module.whois(normalised, timeout=self.timeout)
            except TypeError:
                # Older python-whois releases do not accept the keyword.
                w = self.whois_module.whois(normalised)

            def format_value(value):
                """Format various value types to bounded strings"""
                if isinstance(value, list):
                    value = value[0] if value else None
                if isinstance(value, datetime):
                    return value.isoformat()
                return str(value)[:MAX_FIELD_LENGTH] if value is not None else None

            name_servers = [
                str(ns)[:MAX_FIELD_LENGTH]
                for ns in (getattr(w, 'name_servers', []) or [])
            ][:MAX_NAME_SERVERS]

            result = {
                'domain': normalised,
                'registrar': self._clip(getattr(w, 'registrar', None)),
                'creation_date': format_value(getattr(w, 'creation_date', None)),
                'expiration_date': format_value(getattr(w, 'expiration_date', None)),
                'updated_date': format_value(getattr(w, 'updated_date', None)),
                'status': self._clip(getattr(w, 'status', None)),
                'name_servers': name_servers,
            }
            cache_set(f"whois:{normalised}", result, 86400)
            return result
        except Exception as e:
            # Only the exception TYPE is logged. python-whois embeds the raw
            # WHOIS server response in its exception text, and that text is
            # written by whoever registered the domain being analysed — logging
            # it verbatim allows log forgery (injected newlines and fake log
            # lines) and unbounded log growth.
            logger.warning(f"[WhoisService] WHOIS lookup failed: {type(e).__name__}")
            # Short negative TTL: long enough to stop a lookup storm re-opening
            # a socket per request, short enough that a transient registry
            # outage does not silently disable domain-age detection for every
            # user of this instance for the rest of the hour.
            cache_set(f"whois:{normalised}", None, 120)
            return None
