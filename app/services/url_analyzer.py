"""
URL Analyzer Service
Analyzes URLs found in emails for suspicious characteristics
"""

import re
import logging
import urllib.parse
from typing import List, Dict, Any, Optional

from app.utils.net_guard import registrable_domain

logger = logging.getLogger(__name__)


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

    # Default ceiling on how many URLs one email contributes to the analysis.
    DEFAULT_MAX_URLS = 500

    # Longest URL kept intact in a result. Matches the regex bound.
    MAX_URL_LENGTH = 2048

    def __init__(self):
        self.url_pattern = re.compile(r'https?://[\w./?=#@%&+-]{1,2000}', re.IGNORECASE)

    # Brand names whose appearance in a hostname that is NOT the brand's own
    # domain is a strong phishing signal — e.g. microsoft.com.secure-update.com.
    IMPERSONATED_BRANDS = {
        'microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'live',
        'google', 'gmail', 'apple', 'icloud', 'amazon', 'aws', 'paypal',
        'netflix', 'facebook', 'instagram', 'whatsapp', 'linkedin', 'dropbox',
        'docusign', 'adobe', 'chase', 'wellsfargo', 'hsbc', 'barclays',
        'binance', 'coinbase', 'metamask', 'bankofamerica', 'citibank',
    }

    # Path fragments that advertise a sign-in flow. On a domain other than the
    # sender's, these are the shape credential harvesting usually takes.
    CREDENTIAL_PATH_HINTS = (
        'login', 'signin', 'sign-in', 'logon', 'auth', 'sso', 'oauth',
        'verify', 'validation', 'confirm', 'account', 'password', 'passwd',
        'credential', 'secure-update', 'unlock', 'reactivate', 'session',
    )

    @staticmethod
    def _browser_normalise(url: str) -> str:
        """
        Apply the WHATWG rule that a backslash is a path separator, but only
        within the scheme-and-authority portion, so query strings keep theirs.
        """
        match = re.match(r'^(https?://)([^/?#]*)(.*)$', url, re.IGNORECASE)
        if not match:
            return url
        scheme, authority, rest = match.groups()
        if '\\' not in authority:
            return url
        authority, _, tail = authority.replace('\\', '/').partition('/')
        return f'{scheme}{authority}/{tail}{rest}' if tail else f'{scheme}{authority}{rest}'

    def extract_urls(self, text: str, max_urls: int = DEFAULT_MAX_URLS) -> List[str]:
        """
        Extract URLs from text, stopping at `max_urls`.

        A body consisting of a million short links would otherwise produce a
        million dict-building analyses and a response to match. `finditer` stops
        scanning as soon as the cap is hit rather than materialising every match.
        """
        if not text:
            return []

        urls = []
        for match in self.url_pattern.finditer(text):
            urls.append(match.group(0))
            if len(urls) >= max_urls:
                break
        return urls

    def analyze_single_url(self, url: str, sender_domain: Optional[str] = None) -> Dict[str, Any]:
        """Analyze a single URL for suspicious characteristics"""
        issues = []
        domain = ""
        registered_domain = ""

        # Bound the value before parsing: it comes from an untrusted email body
        # and is echoed back in the response.
        url = (url or "")[:self.MAX_URL_LENGTH]

        # Normalise the way a browser does BEFORE parsing.
        #
        # Python treats U+005C as an ordinary character, so
        #   urlparse('https://evil.example\\.microsoft.com/x').hostname
        # is 'evil.example\\.microsoft.com', whose last two labels are
        # 'microsoft.com'. Every browser and Outlook's webview follow WHATWG,
        # where a backslash is a path separator in a special scheme — so the
        # link actually goes to evil.example. One character made a hostile link
        # score as the sender's own domain and trip no checks at all.
        normalised = self._browser_normalise(url)
        if normalised != url:
            issues.append('host_parser_confusion')
        url_for_parsing = normalised

        # `parsed` must exist even when urlparse raises (it does, for malformed
        # IPv6 literals) — later checks read it outside their own try blocks.
        parsed = urllib.parse.urlparse("")
        try:
            parsed = urllib.parse.urlparse(url_for_parsing)
            domain = parsed.hostname or ""
        except Exception as e:
            logger.debug(f"[URLAnalyzerService] URL parse error: {type(e).__name__}: {e}")
            domain = ""

        if domain:
            # Multi-part TLD aware: last-two-labels reduced
            # `login.microsoft.co.uk` to `co.uk`, which then read as brand
            # impersonation on Microsoft's own domain.
            registered_domain = registrable_domain(domain)

        # Check for URL shortener
        if registered_domain in self.URL_SHORTENERS:
            issues.append('shortened_url')

        # Check for IP address instead of domain
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', domain or ''):
            issues.append('ip_address_host')

        # Check for punycode (IDN homograph attack). Checked on EVERY label,
        # not just the first: `www.xn--pple-43d.com` was previously clean
        # because only the leading label was examined.
        if any(label.startswith('xn--') for label in (domain or '').split('.')):
            issues.append('punycode_domain')

        # A host containing characters no hostname may contain means the
        # analyzer and the mail client disagree about the destination. That
        # disagreement is itself the attack, not something to resolve quietly.
        if domain and not re.fullmatch(r'[a-z0-9.\-]+', domain, re.IGNORECASE):
            issues.append('invalid_host_characters')

        # A well-known brand appearing anywhere in the host EXCEPT as the
        # registrable domain — microsoft.com.secure-update.com resolves to
        # secure-update.com, which is exactly the point. The brand's own
        # domain, including on a multi-part TLD, must not match.
        if domain and registered_domain:
            brand_owner = registered_domain.split('.')[0]
            host_labels = domain.lower().split('.')
            for brand in self.IMPERSONATED_BRANDS:
                if brand != brand_owner and brand in host_labels:
                    issues.append('brand_impersonation_in_host')
                    break

        # A link whose path advertises a sign-in flow on a domain that is not
        # the sender's. Credential harvesting does not need a <form> in the
        # email — a link to an external login page is the commoner shape, and
        # it previously tripped no check at all.
        if registered_domain and sender_domain:
            path_and_query = f"{parsed.path}?{parsed.query}".lower()
            if (registered_domain != registrable_domain(sender_domain)
                    and any(word in path_and_query for word in self.CREDENTIAL_PATH_HINTS)):
                issues.append('external_credential_page')

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
        except Exception as e:
            logger.debug(f"[URLAnalyzerService] Authority parse error: {e}")

        # Check for excessively long path
        try:
            if parsed.path and len(parsed.path) > 80:
                issues.append('long_path')
        except Exception as e:
            logger.debug(f"[URLAnalyzerService] Path check error: {e}")

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
