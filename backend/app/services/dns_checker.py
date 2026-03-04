"""
DNS Checker Service
Handles SPF, DMARC, and DKIM DNS queries
"""

import re
from typing import Optional, List

try:
    import dns.resolver
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
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=self.timeout)
            records = []
            for rdata in answers:
                txt = rdata.to_text()
                # Remove surrounding quotes
                if txt.startswith('"') and txt.endswith('"'):
                    txt = txt[1:-1]
                records.append(txt)
            return records if records else None
        except dns.exception.DNSException:
            return None
        except Exception:
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

    def check_dkim(self, domain: str, selector: Optional[str]) -> Optional[str]:
        """Check DKIM record for domain and selector"""
        if not domain or not selector:
            return None

        dkim_domain = f"{selector}._domainkey.{domain}"
        records = self.get_txt_records(dkim_domain) or []
        return records[0] if records else None
