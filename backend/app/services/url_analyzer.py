"""
URL Analyzer Service
Analyzes URLs found in emails for suspicious characteristics
"""

import re
import urllib.parse
from typing import List, Dict, Any, Optional


class URLAnalyzerService:
    """Service for analyzing URLs in email content"""

    # Suspicious TLDs often used in phishing
    SUSPICIOUS_TLDS = {
        'cn', 'ru', 'zip', 'top', 'biz', 'tk', 'ga', 'ml', 'cf', 'gq',
        'xyz', 'ng', 'work', 'asia', 'club', 'link', 'click', 'download'
    }

    # Known URL shorteners
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
        'bit.do', 'cutt.ly', 'is.gd', 'tiny.cc', 'rb.gy', 'shorturl.at'
    }

    def __init__(self):
        self.url_pattern = re.compile(r'https?://[\w./?=#@%&+-]+', re.IGNORECASE)

    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text"""
        if not text:
            return []
        return self.url_pattern.findall(text)

    def analyze_single_url(self, url: str, sender_domain: Optional[str] = None) -> Dict[str, Any]:
        """Analyze a single URL for suspicious characteristics"""
        issues = []
        domain = ""
        registered_domain = ""

        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.hostname or ""
        except Exception:
            domain = ""

        if domain:
            parts = domain.lower().split('.')
            registered_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain.lower()

        # Check for URL shortener
        if registered_domain in self.URL_SHORTENERS:
            issues.append('shortened_url')

        # Check for IP address instead of domain
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', domain or ''):
            issues.append('ip_address_host')

        # Check for punycode (IDN homograph attack)
        if domain.startswith('xn--'):
            issues.append('punycode_domain')

        # Check for suspicious TLD
        if registered_domain:
            tld = registered_domain.split('.')[-1]
            if tld in self.SUSPICIOUS_TLDS:
                issues.append('suspicious_tld')

        # Check for @ in URL (credential stealing)
        try:
            authority = url.split('/')[2]
            if '@' in authority:
                issues.append('url_contains_at_sign')
        except Exception:
            pass

        # Check for excessively long path
        try:
            if parsed.path and len(parsed.path) > 80:
                issues.append('long_path')
        except Exception:
            pass

        # Check for redirect parameters
        if any(param in url.lower() for param in ['redirect=', 'url=', 'next=', 'goto=']):
            issues.append('redirect_parameter')

        # Check for domain mismatch with sender
        if sender_domain and registered_domain and sender_domain.lower() != registered_domain:
            issues.append('domain_mismatch_with_sender')

        # Check for suspicious query parameters
        if parsed.query:
            suspicious_params = ['cmd=', 'exec=', 'shell=', 'token=', 'key=']
            if any(param in parsed.query.lower() for param in suspicious_params):
                issues.append('suspicious_parameters')

        return {
            'url': url,
            'domain': registered_domain or domain,
            'issues': issues,
            'is_suspicious': len(issues) > 0
        }

    def analyze_urls(self, urls: List[str], sender_domain: Optional[str] = None) -> Dict[str, Any]:
        """Analyze multiple URLs"""
        if not urls:
            return {
                'total_count': 0,
                'unique_count': 0,
                'suspicious_count': 0,
                'urls': []
            }

        # Remove duplicates while preserving order
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
            'urls': analyzed
        }
