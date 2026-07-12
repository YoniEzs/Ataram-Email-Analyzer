"""Bounded RDAP domain-registration lookup.

RDAP replaces the legacy ``python-whois`` call, whose socket operations could
continue indefinitely after the request timeout. HTTPS requests have explicit
connect/read timeouts and redirects are followed only to public HTTPS hosts.
"""

import ipaddress
import json
import logging
import socket
from typing import Any, Dict, Optional
from urllib.parse import quote, urljoin, urlparse

import requests

from app.utils.cache import cache_get, cache_set
from app.utils.validators import validate_domain

logger = logging.getLogger(__name__)

_RDAP_BASE = 'https://rdap.org/domain/'
_MAX_REDIRECTS = 3
_MAX_RDAP_BYTES = 1024 * 1024


def _is_public_https_url(url: str) -> bool:
    """Reject non-HTTPS, credentialed, unusual-port, or private targets."""
    try:
        parsed = urlparse(url)
        if (
            parsed.scheme != 'https'
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 443)
        ):
            return False
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
        }
        if not addresses:
            return False
        return all(ipaddress.ip_address(ip).is_global for ip in addresses)
    except (OSError, ValueError):
        return False


def _event_date(payload: Dict[str, Any], actions: set[str]) -> Optional[str]:
    for event in payload.get('events', []) or []:
        if str(event.get('eventAction', '')).lower() in actions:
            value = event.get('eventDate')
            return str(value) if value else None
    return None


def _registrar_name(payload: Dict[str, Any]) -> Optional[str]:
    for entity in payload.get('entities', []) or []:
        roles = {str(role).lower() for role in (entity.get('roles') or [])}
        if 'registrar' not in roles:
            continue
        vcard = entity.get('vcardArray') or []
        rows = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []
        for row in rows:
            if isinstance(row, list) and len(row) >= 4 and row[0] == 'fn':
                return str(row[3])
        handle = entity.get('handle')
        return str(handle) if handle else None
    return None


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

        url = _RDAP_BASE + quote(domain, safe='')
        try:
            response = None
            for _ in range(_MAX_REDIRECTS + 1):
                if not _is_public_https_url(url):
                    logger.warning('[WhoisService] blocked unsafe RDAP target')
                    return None
                response = requests.get(
                    url,
                    headers={
                        'Accept': 'application/rdap+json, application/json',
                        'User-Agent': 'Ataram-Email-Analyzer/0.1',
                    },
                    timeout=(min(3, self.timeout), self.timeout),
                    allow_redirects=False,
                    stream=True,
                )
                if response.status_code not in {301, 302, 303, 307, 308}:
                    break
                location = response.headers.get('Location')
                response.close()
                if not location:
                    return None
                url = urljoin(url, location)
            else:
                return None

            if response is None:
                return None
            if response.status_code == 404:
                response.close()
                return None
            try:
                response.raise_for_status()
                chunks = []
                total = 0
                for chunk in response.iter_content(chunk_size=65_536):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > _MAX_RDAP_BYTES:
                        logger.warning('[WhoisService] RDAP response exceeded size limit')
                        return None
                    chunks.append(chunk)
                payload = json.loads(b''.join(chunks))
            finally:
                response.close()
            if not isinstance(payload, dict):
                return None

            result: Dict[str, Any] = {
                'domain': domain,
                'registrar': _registrar_name(payload),
                'creation_date': _event_date(
                    payload, {'registration', 'registered'}
                ),
                'expiration_date': _event_date(
                    payload, {'expiration', 'expiry'}
                ),
                'updated_date': _event_date(
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
        except (requests.RequestException, ValueError, TypeError) as exc:
            logger.warning('[WhoisService] RDAP lookup failed for %s: %s', domain, exc)
            return None
