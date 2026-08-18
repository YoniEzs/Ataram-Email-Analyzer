"""
DNS Checker Service
Handles SPF, DMARC, and DKIM DNS queries
"""

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.utils.cache import cache_get, cache_set
from app.utils.validators import validate_public_ip

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.exception
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DNSCheckerService:
    """Service for DNS-based email authentication checks"""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        if not DNS_AVAILABLE:
            raise ImportError("dnspython is required. Install: pip install dnspython")

    def get_txt_records(self, domain: str) -> Optional[List[str]]:
        """Query TXT records for a domain"""
        cached = cache_get(f"dns:{domain}")
        if cached is not None:
            return cached

        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=self.timeout)
            records = []
            for rdata in answers:
                # Long TXT records are split into multiple <=255-byte strings;
                # join them (to_text() would leave '" "' separators inside).
                chunks = getattr(rdata, 'strings', ())
                txt = b''.join(chunks).decode('utf-8', errors='replace')
                records.append(txt)
            result = records if records else None
            cache_set(f"dns:{domain}", result, 3600)
            return result
        except dns.exception.DNSException:
            return None
        except Exception as e:
            logger.warning(f"[DNSCheckerService] Unexpected DNS error for {domain}: {e}")
            return None

    def _resolve(
        self, name: str, rdtype: str, cache_key: str, *, ttl: int = 3600,
        limit: int = 8,
    ) -> Optional[List[str]]:
        """Resolve one record type into plain strings, cached and bounded."""
        cached = cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            answers = dns.resolver.resolve(name, rdtype, lifetime=self.timeout)
            records = []
            for rdata in answers:
                if rdtype == 'MX':
                    value = str(getattr(rdata, 'exchange', '')).rstrip('.').lower()
                elif rdtype == 'PTR':
                    value = str(getattr(rdata, 'target', rdata)).rstrip('.').lower()
                else:
                    value = str(getattr(rdata, 'address', rdata))
                if value:
                    records.append(value)
                if len(records) >= limit:
                    break
            result = records if records else None
            cache_set(cache_key, result, ttl)
            return result
        except dns.exception.DNSException:
            return None
        except Exception as e:
            logger.warning(
                f"[DNSCheckerService] Unexpected {rdtype} error for {name}: {e}"
            )
            return None

    def get_ptr_records(self, ip: str) -> Optional[List[str]]:
        """Reverse-DNS names for a public IP, newest lookup cached for an hour.

        Private and reserved addresses are rejected before any query so an
        internal Received chain never discloses RFC1918 space to the resolver.
        """
        if not validate_public_ip(ip):
            return None
        try:
            name = dns.reversename.from_address(ip).to_text()
        except Exception:
            return None
        return self._resolve(name, 'PTR', f"dns:ptr:{ip}", limit=4)

    def get_host_ips(self, host: str) -> Optional[List[str]]:
        """A and AAAA addresses for a host name."""
        if not host:
            return None
        cache_key = f"dns:addr:{host}"
        cached = cache_get(cache_key)
        if cached is not None:
            return cached

        addresses: List[str] = []
        for rdtype in ('A', 'AAAA'):
            found = self._resolve(host, rdtype, f"dns:{rdtype.lower()}:{host}")
            addresses.extend(found or [])
        result = addresses if addresses else None
        cache_set(cache_key, result, 3600)
        return result

    def get_mx_records(self, domain: str) -> Optional[List[str]]:
        """Mail exchangers for a domain."""
        if not domain:
            return None
        return self._resolve(domain, 'MX', f"dns:mx:{domain}")

    def reverse_dns(self, ip: str) -> Optional[Dict[str, Any]]:
        """Reverse DNS plus forward confirmation (FCrDNS) for a sending IP.

        FCrDNS passes when the PTR name resolves forward to the same address.
        Unlike anything read out of the message, this is a live fact about the
        address, so it is classified as observed evidence and may be scored.
        """
        if not validate_public_ip(ip):
            return None

        cache_key = f"rdns:{ip}"
        cached = cache_get(cache_key)
        if cached is not None:
            return cached

        result: Dict[str, Any] = {
            'ip': ip,
            'ptr': [],
            'ptr_name': None,
            'forward_ips': {},
            'fcrdns': 'no_ptr',
            'source': 'live_dns',
            'checked_at': datetime.now(timezone.utc).isoformat(),
        }

        ptr_names = self.get_ptr_records(ip)
        if ptr_names is None:
            result['fcrdns'] = 'lookup_failed'
            cache_set(cache_key, result, 300)
            return result
        if not ptr_names:
            cache_set(cache_key, result, 3600)
            return result

        result['ptr'] = ptr_names
        result['ptr_name'] = ptr_names[0]

        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return result

        confirmed = False
        # Two names is enough: each costs up to two further round-trips, and
        # the whole batch shares the analyzer's global lookup deadline.
        for name in ptr_names[:2]:
            forward = self.get_host_ips(name) or []
            result['forward_ips'][name] = forward
            for address in forward:
                try:
                    if ipaddress.ip_address(address) == target:
                        confirmed = True
                        break
                except ValueError:
                    continue
            if confirmed:
                break

        result['fcrdns'] = 'pass' if confirmed else 'fail'
        cache_set(cache_key, result, 3600)
        return result

    def check_spf(self, domain: str) -> Optional[str]:
        """Check SPF record for domain"""
        if not domain:
            return None

        records = self.get_txt_records(domain) or []
        for record in records:
            if record.lower().startswith('v=spf1'):
                return record
        return None

    def check_dmarc(self, domain: str) -> Optional[str]:
        """Check DMARC record for domain"""
        if not domain:
            return None

        dmarc_domain = f"_dmarc.{domain}"
        records = self.get_txt_records(dmarc_domain) or []
        for record in records:
            if record.lower().startswith('v=dmarc1'):
                return record
        return None

    def parse_dkim_selector(self, dkim_signature: str) -> Optional[str]:
        """Extract DKIM selector from DKIM-Signature header"""
        if not dkim_signature:
            return None
        match = re.search(r'\bs=([A-Za-z0-9._-]+)', dkim_signature)
        return match.group(1) if match else None

    def parse_dkim_domain(self, dkim_signature: str) -> Optional[str]:
        """Extract signing domain (d= tag) from DKIM-Signature header"""
        if not dkim_signature:
            return None
        match = re.search(r'\bd=([A-Za-z0-9._-]+)', dkim_signature)
        return match.group(1) if match else None

    def check_dkim(self, domain: str, selector: Optional[str]) -> Optional[str]:
        """Check DKIM record for domain and selector.

        Only returns TXT records that carry a public-key tag (p=), so a
        random TXT record at the _domainkey name isn't mistaken for a key.
        """
        if not domain or not selector:
            return None

        dkim_domain = f"{selector}._domainkey.{domain}"
        records = self.get_txt_records(dkim_domain) or []
        for record in records:
            if re.search(r'(?:^|;)\s*p=', record):
                return record
        return None
