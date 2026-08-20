"""Bounded RDAP domain-registration lookup.

RDAP replaces the legacy ``python-whois`` call, whose socket operations could
continue indefinitely after the request timeout. The hardened HTTPS transport
lives in :mod:`app.utils.http_json` and is shared with the RDAP IP lookup.
"""

import logging
from typing import Any, Dict, Optional
from urllib.parse import quote

from app.utils.cache import cache_get, cache_set
from app.utils.http_json import get_json
from app.utils.rdap import entity_name, event_date
from app.utils.validators import validate_domain

logger = logging.getLogger(__name__)

_RDAP_BASE = 'https://rdap.org/domain/'


class WhoisService:
    """Compatibility name for an RDAP-backed registration lookup."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        domain = (domain or '').strip().lower().rstrip('.')
        if not validate_domain(domain):
            return None

        cached = cache_get(f'rdap:{domain}')
        if cached is not None:
            return cached

        payload = get_json(
            _RDAP_BASE + quote(domain, safe=''),
            timeout=self.timeout,
            accept='application/rdap+json, application/json',
            label='WhoisService',
        )
        if not isinstance(payload, dict):
            return None

        result: Dict[str, Any] = {
            'domain': domain,
            'registrar': entity_name(payload, 'registrar'),
            'creation_date': event_date(payload, {'registration', 'registered'}),
            'expiration_date': event_date(payload, {'expiration', 'expiry'}),
            'updated_date': event_date(
                payload, {'last changed', 'last update of rdap database'}
            ),
            'status': payload.get('status') or [],
            'name_servers': [
                str(ns.get('ldhName') or ns.get('unicodeName'))
                for ns in (payload.get('nameservers') or [])
                if ns.get('ldhName') or ns.get('unicodeName')
            ],
            'source': 'rdap',
        }
        cache_set(f'rdap:{domain}', result, 86_400)
        return result
