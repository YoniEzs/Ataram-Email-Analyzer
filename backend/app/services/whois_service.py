"""
WHOIS Service
Domain registration information lookup
"""

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Optional, Dict, Any
from datetime import datetime
from app.utils.cache import cache_get, cache_set
from app.utils.validators import validate_domain

logger = logging.getLogger(__name__)

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
        if not validate_domain(domain) or not self.whois_module:
            return None

        cached = cache_get(f"whois:{domain}")
        if cached is not None:
            return cached

        try:
            # python-whois has no timeout parameter and can block on slow
            # WHOIS servers, so enforce the timeout from a worker thread.
            # shutdown(wait=False) so a hung lookup can't block this request.
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(self.whois_module.whois, domain)
                w = future.result(timeout=self.timeout)
            finally:
                executor.shutdown(wait=False, cancel_futures=True)

            def format_value(value):
                """Format various value types to strings"""
                if isinstance(value, list):
                    value = value[0] if value else None
                if isinstance(value, datetime):
                    return value.isoformat()
                return str(value) if value is not None else None

            result = {
                'domain': domain,
                'registrar': format_value(getattr(w, 'registrar', None)),
                'creation_date': format_value(getattr(w, 'creation_date', None)),
                'expiration_date': format_value(getattr(w, 'expiration_date', None)),
                'updated_date': format_value(getattr(w, 'updated_date', None)),
                'status': getattr(w, 'status', None),
                'name_servers': list(getattr(w, 'name_servers', []) or []),
            }
            cache_set(f"whois:{domain}", result, 86400)
            return result
        except FutureTimeoutError:
            logger.warning(f"[WhoisService] WHOIS lookup timed out for {domain} after {self.timeout}s")
            return None
        except Exception as e:
            logger.warning(f"[WhoisService] WHOIS lookup failed for {domain}: {e}")
            return None
