"""
URL Analyzer Service
Analyzes URLs found in emails for suspicious characteristics
"""

import re
import logging
import urllib.parse
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Trailing punctuation that belongs to surrounding prose, not the URL itself
_TRAILING_JUNK = re.compile(r'[.,;:!?)>\]]+$')


class URLAnalyzerService:
    """Service for analyzing URLs in email content"""

    SUSPICIOUS_TLDS = {
        'cn', 'ru', 'zip', 'top', 'biz', 'tk', 'ga', 'ml', 'cf', 'gq',
        'xyz', 'ng', 'work', 'asia', 'club', 'link', 'click', 'download',
    }

    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
        'bit.do', 'cutt.ly', 'is.gd', 'tiny.cc', 'rb.gy', 'shorturl.at',
    }

    def __init__(self):
        # Broader pattern: stop at whitespace or HTML tag/attribute boundaries
        # The old r'https?://[\w./?=#@%&+-]+' had an unintentional '+' to '-'
        # character-class range that included ',' and missed many valid URL chars.
        self.url_pattern = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)

    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text, stripping trailing prose punctuation."""
        if not text:
            return []
        return [_TRAILING_JUNK.sub('', u) for u in self.url_pattern.findall(text)]

    def analyze_single_url(self, url: str, sender_domain: Optional[str] = None) -> Dict[str, Any]:
        """Analyze a single URL for suspicious characteristics."""
        issues = []
        domain = ""
        registered_domain = ""
        parsed = None

        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.hostname or ""
        except Exception as e:
            logger.debug('[URLAnalyzerService] URL parse error for %r: %s', url, e)

        if domain:
            parts = domain.lower().split('.')
            registered_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain.lower()

        if registered_domain in self.URL_SHORTENERS:
            issues.append('shortened_url')

        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', domain or ''):
            issues.append('ip_address_host')

        if domain.startswith('xn--'):
            issues.append('punycode_domain')

        if registered_domain:
            tld = registered_domain.split('.')[-1]
            if tld in self.SUSPICIOUS_TLDS:
                issues.append('suspicious_tld')

        # Credential-stealing pattern: user@host in authority
        # (userinfo only — '@' in the path or query is legitimate)
        if parsed is not None and parsed.username is not None:
            issues.append('url_contains_at_sign')

        if parsed is not None and parsed.path and len(parsed.path) > 80:
            issues.append('long_path')

        if any(param in url.lower() for param in ['redirect=', 'url=', 'next=', 'goto=']):
            issues.append('redirect_parameter')

        if sender_domain and registered_domain and sender_domain.lower() != registered_domain:
            issues.append('domain_mismatch_with_sender')

        if parsed is not None and parsed.query:
            suspicious_params = ['cmd=', 'exec=', 'shell=', 'token=', 'key=']
            if any(param in parsed.query.lower() for param in suspicious_params):
                issues.append('suspicious_parameters')

        return {
            'url': url,
            'domain': registered_domain or domain,
            'issues': issues,
            'is_suspicious': len(issues) > 0,
        }

    def analyze_urls(self, urls: List[str], sender_domain: Optional[str] = None) -> Dict[str, Any]:
        """Analyze multiple URLs."""
        if not urls:
            return {'total_count': 0, 'unique_count': 0, 'suspicious_count': 0, 'urls': []}

        unique_urls = list(dict.fromkeys(urls))
        analyzed = []
        suspicious_count = 0

        for url in unique_urls:
            result = self.analyze_single_url(url, sender_domain)
            analyzed.append(result)
            if result['is_suspicious']:
                suspicious_count += 1

        return {
            'total_count': len(urls),
            'unique_count': len(unique_urls),
            'suspicious_count': suspicious_count,
            'urls': analyzed,
        }
