"""
DNS Checker Service
Handles SPF, DMARC, and DKIM DNS queries
"""

import re
import logging
from typing import Optional, List
from app.utils.cache import cache_get, cache_set

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
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

    def reverse_dns(self, ip: str) -> Optional[str]:
        """Resolve the PTR (reverse DNS) hostname for an IP address.

        Returns the first PTR hostname (without the trailing dot) or None
        when the address has no PTR record or the lookup fails. Results are
        cached, including "no record", so repeat lookups don't re-query DNS.
        """
        if not ip:
            return None

        cache_key = f"ptr:{ip}"
        cached = cache_get(cache_key)
        if cached is not None:
            # "" is the cached sentinel for a confirmed "no PTR record".
            return cached or None

        try:
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, 'PTR', lifetime=self.timeout)
            # Only PTR rdata carries a target; guard so a non-PTR answer in
            # the set can't raise (the generic Rdata type has no .target).
            hostnames = []
            for rdata in answers:
                target = getattr(rdata, 'target', None)
                if target is not None:
                    hostnames.append(str(target).rstrip('.'))
            result = hostnames[0] if hostnames else None
            cache_set(cache_key, result or "", 3600)
            return result
        except dns.exception.DNSException:
            cache_set(cache_key, "", 3600)
            return None
        except Exception as e:
            logger.warning(f"[DNSCheckerService] Reverse DNS error for {ip}: {e}")
            return None
