"""Bounded, SSRF-resistant JSON fetching over HTTPS.

Extracted from ``whois_service`` so the RDAP domain lookup and the RDAP IP
lookup share one hardened transport. Every request has explicit connect/read
timeouts, redirects are followed manually and only to public HTTPS hosts, and
the response body is capped before it is parsed.
"""

import ipaddress
import json
import logging
import socket
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger(__name__)

DEFAULT_MAX_BYTES = 1024 * 1024
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_USER_AGENT = 'Ataram-Email-Analyzer/0.1'


def is_public_https_url(url: str) -> bool:
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


def get_json(
    url: str,
    *,
    timeout: int,
    accept: str = 'application/json',
    user_agent: str = DEFAULT_USER_AGENT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    label: str = 'http_json',
) -> Optional[Any]:
    """GET ``url`` and return parsed JSON, or None on any failure.

    A 404 is treated as "no data" rather than an error, matching how the
    registries signal an unknown object.
    """
    headers: Dict[str, str] = {'Accept': accept, 'User-Agent': user_agent}
    try:
        response = None
        for _ in range(max_redirects + 1):
            if not is_public_https_url(url):
                logger.warning('[%s] blocked unsafe target', label)
                return None
            response = requests.get(
                url,
                headers=headers,
                timeout=(min(3, timeout), timeout),
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
                if total > max_bytes:
                    logger.warning('[%s] response exceeded size limit', label)
                    return None
                chunks.append(chunk)
            return json.loads(b''.join(chunks))
        finally:
            response.close()
    except (requests.RequestException, ValueError, TypeError) as exc:
        logger.warning('[%s] request failed for %s: %s', label, url, exc)
        return None
