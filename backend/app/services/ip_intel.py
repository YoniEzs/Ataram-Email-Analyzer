"""Free, keyless intelligence about a sending IP address.

Two sources, both optional and independently failure-tolerant:

Team Cymru (DNS)
    ``origin.asn.cymru.com`` / ``origin6.asn.cymru.com`` map an address to its
    announcing ASN and BGP prefix; ``AS<n>.asn.cymru.com`` names the ASN. This
    is the primary source because it needs nothing but a DNS resolver, so it
    keeps working in deployments where outbound HTTPS is restricted.

IP RDAP
    ``rdap.org/ip/<ip>`` adds the registry's network name, allocation type and
    abuse contact. A missing RDAP answer is normal, not an error.

Everything here is *observed* evidence: it describes the address itself, not
anything the uploaded file claims about it.
"""

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.services.dns_checker import DNSCheckerService
from app.utils.cache import cache_get, cache_set
from app.utils.http_json import get_json
from app.utils.rdap import entity_with_role, event_date, vcard_field
from app.utils.validators import validate_public_ip

logger = logging.getLogger(__name__)

_RDAP_IP_BASE = 'https://rdap.org/ip/'
_CYMRU_ORIGIN_V4 = 'origin.asn.cymru.com'
_CYMRU_ORIGIN_V6 = 'origin6.asn.cymru.com'
_CYMRU_AS = 'asn.cymru.com'

_MAX_ASN = 4_294_967_295
_MAX_FIELD_CHARS = 128
_MAX_RECORDS = 8
_MAX_RDAP_STR = 256
_MAX_RDAP_LIST = 8

_TTL_ORIGIN = 86_400
_TTL_AS_NAME = 604_800
_TTL_RDAP = 86_400


def cymru_origin_name(ip: str) -> Optional[str]:
    """DNS name that Team Cymru answers with the origin record for ``ip``."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if address.version == 4:
        return '.'.join(reversed(str(address).split('.'))) + '.' + _CYMRU_ORIGIN_V4
    nibbles = address.exploded.replace(':', '')
    return '.'.join(reversed(nibbles)) + '.' + _CYMRU_ORIGIN_V6


def _split_fields(record: str, expected: int) -> List[Optional[str]]:
    """Split a pipe-delimited Cymru record, padded to ``expected`` fields.

    Records legitimately vary in field count and carry empty fields, so
    positional indexing must never assume a fixed width.
    """
    parts = [p.strip()[:_MAX_FIELD_CHARS] or None for p in record.split('|')]
    parts.extend([None] * max(0, expected - len(parts)))
    return parts[:expected]


def _valid_asns(field: Optional[str]) -> List[str]:
    """ASNs from field 1, which holds several for a multi-origin prefix."""
    if not field:
        return []
    asns = []
    for token in field.split():
        if token.isdigit() and 0 < int(token) <= _MAX_ASN:
            asns.append(token)
    return asns


def _prefix_length(prefix: Optional[str]) -> int:
    try:
        return ipaddress.ip_network(prefix, strict=False).prefixlen if prefix else -1
    except ValueError:
        return -1


def _clip(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text[:_MAX_RDAP_STR] if text else None


class IPIntelService:
    """ASN and registry context for a public IP address."""

    def __init__(
        self,
        *,
        dns_checker: DNSCheckerService,
        http_timeout: int = 10,
        enable_rdap: bool = True,
        enable_asn: bool = True,
    ) -> None:
        self.dns_checker = dns_checker
        self.http_timeout = http_timeout
        self.enable_rdap = enable_rdap
        self.enable_asn = enable_asn

    # -- Team Cymru --------------------------------------------------------

    def asn_origin(self, ip: str) -> Optional[Dict[str, Any]]:
        """Announcing ASN and BGP prefix for ``ip``, via Team Cymru DNS."""
        name = cymru_origin_name(ip)
        if not name:
            return None

        cache_key = f'asn:{ip}'
        cached = cache_get(cache_key)
        if cached is not None:
            return cached

        records = self.dns_checker.get_txt_records(name)
        if not records:
            return None

        parsed: List[Dict[str, Any]] = []
        for record in records[:_MAX_RECORDS]:
            # "ASN | BGP prefix | CC | registry | allocated"
            asn_field, prefix, country, registry, allocated = _split_fields(record, 5)
            asns = _valid_asns(asn_field)
            if not asns:
                continue
            parsed.append({
                'asns': asns,
                'bgp_prefix': prefix,
                'country': country,
                'registry': registry,
                'allocated': allocated,
            })
        if not parsed:
            return None

        # Overlapping announcements are normal; the longest prefix is the one
        # actually carrying traffic for this address.
        primary = max(parsed, key=lambda item: _prefix_length(item['bgp_prefix']))
        result: Dict[str, Any] = dict(primary)
        result['records'] = parsed
        cache_set(cache_key, result, _TTL_ORIGIN)
        return result

    def asn_info(self, asn: str) -> Optional[Dict[str, Any]]:
        """Registry metadata and name for an ASN."""
        if not asn or not str(asn).isdigit():
            return None

        cache_key = f'asname:{asn}'
        cached = cache_get(cache_key)
        if cached is not None:
            return cached

        records = self.dns_checker.get_txt_records(f'AS{asn}.{_CYMRU_AS}')
        if not records:
            return None

        # "ASN | CC | registry | allocated | AS name"
        # The name field itself contains commas, so it is taken whole.
        _, country, registry, allocated, as_name = _split_fields(records[0], 5)
        result: Dict[str, Any] = {
            'asn': str(asn),
            'as_name': as_name,
            'country': country,
            'registry': registry,
            'allocated': allocated,
        }
        cache_set(cache_key, result, _TTL_AS_NAME)
        return result

    # -- RDAP --------------------------------------------------------------

    def rdap_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Registry network object for ``ip``."""
        cache_key = f'rdapip:{ip}'
        cached = cache_get(cache_key)
        if cached is not None:
            return cached

        payload = get_json(
            _RDAP_IP_BASE + ip,
            timeout=self.http_timeout,
            accept='application/rdap+json, application/json',
            label='IPIntelService',
        )
        if not isinstance(payload, dict):
            return None

        cidr = None
        cidrs = payload.get('cidr0_cidrs')
        if isinstance(cidrs, list) and cidrs:
            first = cidrs[0]
            if isinstance(first, dict):
                prefix = first.get('v4prefix') or first.get('v6prefix')
                length = first.get('length')
                if prefix and length is not None:
                    cidr = f'{prefix}/{length}'

        abuse = entity_with_role(payload, 'abuse')
        result: Dict[str, Any] = {
            'handle': _clip(payload.get('handle')),
            'name': _clip(payload.get('name')),
            'start_address': _clip(payload.get('startAddress')),
            'end_address': _clip(payload.get('endAddress')),
            'cidr': _clip(cidr),
            'ip_version': _clip(payload.get('ipVersion')),
            'type': _clip(payload.get('type')),
            'country': _clip(payload.get('country')),
            'parent_handle': _clip(payload.get('parentHandle')),
            'registration_date': _clip(
                event_date(payload, {'registration', 'registered'})
            ),
            'last_changed_date': _clip(
                event_date(payload, {'last changed', 'last update of rdap database'})
            ),
            'abuse_email': _clip(vcard_field(abuse, 'email')) if abuse else None,
            'abuse_name': _clip(vcard_field(abuse, 'fn')) if abuse else None,
            'status': [
                _clip(s) for s in (payload.get('status') or [])[:_MAX_RDAP_LIST]
            ],
            'source': 'rdap_ip',
        }
        cache_set(cache_key, result, _TTL_RDAP)
        return result

    # -- Combined ----------------------------------------------------------

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """Merge both sources. Returns None only when neither yields anything."""
        if not validate_public_ip(ip):
            return None

        origin: Optional[Dict[str, Any]] = None
        as_info: Optional[Dict[str, Any]] = None
        rdap: Optional[Dict[str, Any]] = None
        sources: List[str] = []

        if self.enable_asn:
            try:
                origin = self.asn_origin(ip)
                if origin and origin.get('asns'):
                    sources.append('team_cymru_dns')
                    as_info = self.asn_info(origin['asns'][0])
            except Exception as exc:
                logger.warning('[IPIntelService] ASN lookup failed for %s: %s', ip, exc)

        if self.enable_rdap:
            try:
                rdap = self.rdap_ip(ip)
                if rdap:
                    sources.append('rdap_ip')
            except Exception as exc:
                logger.warning('[IPIntelService] RDAP lookup failed for %s: %s', ip, exc)

        if not sources:
            return None

        asns = (origin or {}).get('asns') or []
        return {
            'ip': ip,
            'asn': asns[0] if asns else None,
            'asns': asns,
            'as_name': (as_info or {}).get('as_name'),
            'bgp_prefix': (origin or {}).get('bgp_prefix'),
            'country': (origin or {}).get('country') or (rdap or {}).get('country'),
            'registry': (origin or {}).get('registry') or (as_info or {}).get('registry'),
            'allocated': (origin or {}).get('allocated'),
            'rdap': rdap,
            'trust': 'observed',
            'source': ' + '.join(sources),
            'checked_at': datetime.now(timezone.utc).isoformat(),
        }
