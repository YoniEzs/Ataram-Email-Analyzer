"""
DNS Checker Service
Handles SPF, DMARC, and DKIM DNS queries
"""

import re
import logging
from typing import Optional, List
from app.utils.cache import cache_get, cache_set, MISS
from app.utils.net_guard import (
    is_public_domain,
    is_safe_dns_query_name,
    is_safe_dkim_selector,
)

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# Cap on TXT records returned for one name. A hostile authoritative server can
# answer with an arbitrarily large TXT set; nothing downstream needs more than
# a handful, and the whole response is cached and serialised into the API reply.
MAX_TXT_RECORDS = 20
MAX_TXT_RECORD_LENGTH = 4096


def _is_valid_public_domain(domain: str) -> bool:
    """Return True only for syntactically valid, public, routable domains."""
    return is_public_domain(domain)


class DNSCheckerService:
    """Service for DNS-based email authentication checks"""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        if not DNS_AVAILABLE:
            raise ImportError("dnspython is required. Install: pip install dnspython")

    def get_txt_records(self, domain: str) -> Optional[List[str]]:
        """Query TXT records for a domain or authentication sub-name"""
        if not is_safe_dns_query_name(domain):
            logger.warning("[DNSCheckerService] Rejected invalid/internal DNS name")
            return None

        query_name = domain.strip().rstrip('.').lower()

        cached = cache_get(f"dns:{query_name}", MISS)
        if cached is not MISS:
            return cached

        try:
            answers = dns.resolver.resolve(query_name, 'TXT', lifetime=self.timeout)
            records = []
            for rdata in answers:
                if len(records) >= MAX_TXT_RECORDS:
                    break
                txt = rdata.to_text()
                # Remove surrounding quotes
                if txt.startswith('"') and txt.endswith('"'):
                    txt = txt[1:-1]
                records.append(txt[:MAX_TXT_RECORD_LENGTH])
            result = records if records else None
            cache_set(f"dns:{query_name}", result, 3600)
            return result
        except dns.exception.DNSException:
            # Cache the negative answer too: without this, a flood of lookups for
            # domains that do not resolve re-queries on every single request.
            cache_set(f"dns:{query_name}", None, 300)
            return None
        except Exception as e:
            logger.warning(f"[DNSCheckerService] Unexpected DNS error: {type(e).__name__}: {e}")
            return None

    def check_spf(self, domain: str) -> Optional[str]:
        """Check SPF record for domain"""
        if not is_public_domain(domain):
            return None

        records = self.get_txt_records(domain) or []
        for record in records:
            if record.lower().startswith('v=spf1'):
                return record
        return None

    def check_dmarc(self, domain: str) -> Optional[str]:
        """Check DMARC record for domain"""
        if not is_public_domain(domain):
            return None

        dmarc_domain = f"_dmarc.{domain.strip().rstrip('.').lower()}"
        records = self.get_txt_records(dmarc_domain) or []
        for record in records:
            if record.lower().startswith('v=dmarc1'):
                return record
        return None

    def parse_dkim_selector(self, dkim_signature: str) -> Optional[str]:
        """Extract DKIM selector from DKIM-Signature header"""
        if not dkim_signature:
            return None
        # Bound the header before running the search: it arrives from an
        # untrusted email and only the tag block is ever relevant.
        match = re.search(r'\bs=([A-Za-z0-9._-]{1,63})', dkim_signature[:4096])
        if not match:
            return None
        selector = match.group(1)
        return selector if is_safe_dkim_selector(selector) else None

    def check_dkim(self, domain: str, selector: Optional[str]) -> Optional[str]:
        """Check DKIM record for domain and selector"""
        if not is_public_domain(domain) or not is_safe_dkim_selector(selector or ''):
            return None

        dkim_domain = f"{selector}._domainkey.{domain.strip().rstrip('.').lower()}"
        records = self.get_txt_records(dkim_domain) or []
        return records[0] if records else None
