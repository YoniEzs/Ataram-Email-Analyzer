"""
URL Analyzer Service
Analyzes URLs found in emails for suspicious characteristics
"""

import re
import logging
import urllib.parse
from typing import List, Dict, Any, Optional

from app.utils.domains import (
    is_homograph_label as _is_homograph_label,
    registered_domain as _registered_domain,
    registered_domain_and_suffix as _registered_domain_and_suffix,
)

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# Trailing punctuation that belongs to surrounding prose, not the URL itself
_TRAILING_JUNK = re.compile(r'[.,;:!?)>\]]+$')

class URLAnalyzerService:
    """Service for analyzing URLs in email content"""

    # Reported, never counted toward "suspicious". This fires on any link
    # whose registered domain is not the sender's, which is true of virtually
    # every legitimate bulk message: the ESP that sent it, the tracking and
    # unsubscribe links, the provider's own footer. At five points each it was
    # contributing the bulk of the score on clean marketing mail. The real
    # phishing signal is a *displayed* link disagreeing with its target, which
    # content_analyzer already reports separately.
    INFORMATIONAL_ISSUES = frozenset({'domain_mismatch_with_sender'})

    SUSPICIOUS_TLDS = {
        'cn', 'ru', 'zip', 'top', 'biz', 'tk', 'ga', 'ml', 'cf', 'gq',
        'xyz', 'ng', 'work', 'asia', 'club', 'link', 'click', 'download',
    }

    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
        'bit.do', 'cutt.ly', 'is.gd', 'tiny.cc', 'rb.gy', 'shorturl.at',
    }

    # Security gateways rewrite every link in a message so their own scanner
    # sits in front of the click. The wrapper's hostname then belongs to the
    # gateway -- often the *recipient's* own protection -- so analysing it
    # reports the defence as the threat and never looks at the real target,
    # which is sitting URL-encoded inside a query parameter.
    # Links the mail platform injects into a message, which the sender did
    # not choose and cannot control: Outlook's own sender-identification
    # footer, and the Safe Links wrapper the recipient's tenant applies. The
    # line is *who put the link there*, not "is this domain reputable" -- so
    # it stays a short, principled list rather than a reputation treadmill.
    #
    # They are excluded from the suspicious count and from bulk copy, because
    # an analyst pasting exported links into a blocklist must never end up
    # blocking aka.ms or their own tenant's Safe Links: that breaks Outlook
    # for the whole organisation.
    #
    # An ESP such as SendGrid is deliberately NOT here. The sender chose it,
    # it is their infrastructure, and it hosts phishing every day.
    PLATFORM_INFRASTRUCTURE = (
        'aka.ms',
        'safelinks.protection.outlook.com',
        'protection.outlook.com',
    )

    _SAFELINK_HOSTS = ('safelinks.protection.outlook.com',)

    @staticmethod
    def _host_is(host: str, domain: str) -> bool:
        """Exact host or a true subdomain of it -- never a bare suffix match.

        `host.endswith('urldefense.com')` is also true of
        `evilurldefense.com`, which anyone can register. Treating that as a
        trusted gateway would make this code unwrap whatever the attacker put
        in the query parameter, so the analyst would be shown a harmless
        target while the link actually points at the attacker's own host --
        turning the unwrapper into a way to hide a destination rather than
        reveal one.
        """
        host = (host or '').lower()
        domain = domain.lower()
        return host == domain or host.endswith('.' + domain)
    _WRAPPERS = {
        'safelinks.protection.outlook.com': ('Microsoft Safe Links', 'url'),
        'linkprotect.cudasvc.com': ('Barracuda Link Protection', 'a'),
        'www.google.com': ('Google redirect', 'q'),
        'google.com': ('Google redirect', 'q'),
    }

    def _is_platform_infrastructure(self, url: str) -> bool:
        """True when the mail platform, not the sender, put this link here."""
        try:
            host = (urllib.parse.urlparse(url).hostname or '').lower()
        except ValueError:
            return False
        return any(self._host_is(host, d) for d in self.PLATFORM_INFRASTRUCTURE)

    def unwrap_url(self, url: str, _depth: int = 0) -> tuple:
        """Return (real_url, wrapper_name) after peeling any known gateway.

        Depth-limited because a message can pass through more than one gateway
        -- a Proofpoint-wrapped link forwarded into a Safe Links tenant -- and
        because a hostile URL could otherwise nest wrappers to spin this.
        """
        if _depth >= 3 or not url:
            return url, None
        try:
            parsed = urllib.parse.urlparse(url)
        except ValueError:
            return url, None
        host = (parsed.hostname or '').lower()

        target = None
        name = None

        if any(self._host_is(host, h) for h in self._SAFELINK_HOSTS):
            name = 'Microsoft Safe Links'
            target = urllib.parse.parse_qs(parsed.query).get('url', [None])[0]
        elif host in self._WRAPPERS:
            name, param = self._WRAPPERS[host]
            target = urllib.parse.parse_qs(parsed.query).get(param, [None])[0]
        elif self._host_is(host, 'urldefense.proofpoint.com'):
            name = 'Proofpoint URL Defense'
            raw = urllib.parse.parse_qs(parsed.query).get('u', [None])[0]
            if raw:
                # v2 substitutes '-' for '%' and '_' for '/' before quoting.
                target = urllib.parse.unquote(raw.replace('-', '%').replace('_', '/'))
        elif self._host_is(host, 'urldefense.com'):
            name = 'Proofpoint URL Defense'
            # Index arithmetic rather than a regex: a lazy quantifier scanning
            # an attacker-supplied URL backtracks quadratically on input like
            # '/v3/__aaaa...', and this string comes straight out of a hostile
            # message.
            marker = '/v3/__'
            start = url.find(marker)
            if start != -1:
                end = url.find('__;', start + len(marker))
                if end != -1:
                    target = urllib.parse.unquote(url[start + len(marker):end])
        elif self._host_is(host, 'mimecast.com'):
            # Mimecast encodes the target server-side; it cannot be recovered
            # from the link alone. Name it so the analyst knows why the
            # hostname is not the sender's, and stop.
            return url, 'Mimecast (target not recoverable)'

        if not target or not target.lower().startswith(('http://', 'https://')):
            return url, name
        if target == url:
            return url, name
        deeper, inner = self.unwrap_url(target, _depth + 1)
        return deeper, inner or name

    def __init__(self, max_urls: int = 500, max_url_length: int = 4096):
        self.max_urls = max_urls
        self.max_url_length = max_url_length
        # Broader pattern: stop at whitespace or HTML tag/attribute boundaries
        # The old r'https?://[\w./?=#@%&+-]+' had an unintentional '+' to '-'
        # character-class range that included ',' and missed many valid URL chars.
        self.url_pattern = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
        # Scheme-less URLs ("www.example.com/x") that mail clients auto-link
        self.www_pattern = re.compile(r'(?<![\w@/.])www\.[^\s<>"\')\]]+', re.IGNORECASE)

    def extract_urls(self, text: str, html: str = '') -> List[str]:
        """Extract URLs from text and (optionally) HTML attributes.

        Covers plain https?:// links, scheme-less www. links, and href/src
        attribute values that a regex over rendered text can miss.
        De-duplicated, order preserved.
        """
        urls: List[str] = []

        if text:
            urls.extend(self.url_pattern.findall(text))
            urls.extend(
                f'http://{u}' for u in self.www_pattern.findall(text)
            )

        if html and BS4_AVAILABLE:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                for tag in soup.find_all(['a', 'area', 'form', 'iframe', 'img', 'script']):
                    for attr in ('href', 'src', 'action'):
                        raw_value = tag.get(attr)
                        # bs4 may return a list for multi-valued attributes
                        if isinstance(raw_value, list):
                            raw_value = ' '.join(str(v) for v in raw_value)
                        value = (raw_value or '').strip()
                        if value.lower().startswith(('http://', 'https://')):
                            urls.append(value)
                        elif value.lower().startswith('www.'):
                            urls.append(f'http://{value}')
            except Exception as e:
                logger.debug('[URLAnalyzerService] HTML URL extraction failed: %s', e)

        cleaned = [_TRAILING_JUNK.sub('', u) for u in urls]
        return list(dict.fromkeys(u for u in cleaned if u))[:self.max_urls]

    def analyze_single_url(self, url: str, sender_domain: Optional[str] = None) -> Dict[str, Any]:
        """Analyze a single URL for suspicious characteristics."""
        issues = []
        # Analyse where the link actually goes, not the gateway that rewrote
        # it. Without this the report names the recipient's own protection as
        # the suspicious host and never inspects the real target.
        wrapped_original = url
        url, wrapper = self.unwrap_url(url)
        # Classify the destination, not the wrapper. A Safe Links URL is
        # platform infrastructure, but what it points at belongs to the
        # sender -- and that target is exactly what an analyst needs in a
        # blocklist. Judging the wrapper would hide it.
        is_platform = self._is_platform_infrastructure(url)
        if wrapper:
            issues.append('security_gateway_wrapped')

        original_length = len(url)
        if original_length > self.max_url_length:
            issues.append('url_too_long')
            url = url[:self.max_url_length]
        domain = ""
        registered_domain = ""
        parsed = None

        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.hostname or ""
        except Exception as e:
            logger.debug('[URLAnalyzerService] URL parse error for %r: %s', url, e)

        suffix = ""
        if domain:
            registered_domain, suffix = _registered_domain_and_suffix(domain)

        if registered_domain in self.URL_SHORTENERS:
            issues.append('shortened_url')

        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', domain or ''):
            issues.append('ip_address_host')

        if any(label.startswith('xn--') for label in domain.lower().split('.')):
            issues.append('punycode_domain')

        if any(_is_homograph_label(label) for label in domain.lower().split('.')):
            issues.append('homograph_domain')

        if suffix and suffix.split('.')[-1] in self.SUSPICIOUS_TLDS:
            issues.append('suspicious_tld')

        # Credential-stealing pattern: user@host in authority
        # (userinfo only — '@' in the path or query is legitimate)
        if parsed is not None and parsed.username is not None:
            issues.append('url_contains_at_sign')

        if parsed is not None and parsed.path and len(parsed.path) > 80:
            issues.append('long_path')

        if any(param in url.lower() for param in ['redirect=', 'url=', 'next=', 'goto=']):
            issues.append('redirect_parameter')

        # Compare registered domains so www.example.com links in example.com
        # mail don't trip the mismatch flag.
        if sender_domain and registered_domain:
            if _registered_domain(sender_domain) != registered_domain:
                issues.append('domain_mismatch_with_sender')

        if parsed is not None and parsed.query:
            suspicious_params = ['cmd=', 'exec=', 'shell=', 'token=', 'key=']
            if any(param in parsed.query.lower() for param in suspicious_params):
                issues.append('suspicious_parameters')

        if is_platform:
            issues.append('platform_infrastructure')
        scored = [i for i in issues if i not in self.INFORMATIONAL_ISSUES
                  and i != 'security_gateway_wrapped']
        return {
            'url': url,
            'is_platform_infrastructure': is_platform,
            'safe_to_bulk_copy': not is_platform,
            'wrapped_original': wrapped_original if wrapper else None,
            'wrapper': wrapper,
            'original_length': original_length,
            'truncated': original_length > self.max_url_length,
            'domain': registered_domain or domain,
            'issues': issues,
            'informational_issues': [i for i in issues
                                     if i in self.INFORMATIONAL_ISSUES],
            'is_suspicious': bool(scored) and not is_platform,
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
