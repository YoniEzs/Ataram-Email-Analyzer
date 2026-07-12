"""
URL Analyzer Service
Analyzes URLs found in emails for suspicious characteristics
"""

import re
import logging
import unicodedata
import urllib.parse
from typing import List, Dict, Any, Optional

import tldextract

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# Trailing punctuation that belongs to surrounding prose, not the URL itself
_TRAILING_JUNK = re.compile(r'[.,;:!?)>\]]+$')

# Offline PSL extractor — uses the bundled Public Suffix List snapshot,
# never fetches over the network at runtime.
_tld_extract = tldextract.TLDExtract(suffix_list_urls=())


def _registered_domain(host: str) -> str:
    """PSL-aware registered domain (example.co.uk stays example.co.uk)."""
    if not host:
        return ""
    ext = _tld_extract(host.lower())
    return ext.top_domain_under_public_suffix or host.lower()


# Cyrillic letters that render (near-)identically to Latin ones — the raw
# material of homograph attacks like "pаypal.com".
_CYRILLIC_CONFUSABLES = set('аеорсухіјѕԛԝьӏԁɡ')

_SCRIPT_PREFIXES = ('LATIN', 'CYRILLIC', 'GREEK', 'HEBREW', 'ARABIC')


def _label_scripts(label: str) -> set:
    """Return the set of Unicode scripts used by letters in a label."""
    scripts = set()
    for ch in label:
        if not ch.isalpha():
            continue
        if ch.isascii():
            scripts.add('LATIN')
            continue
        name = unicodedata.name(ch, '')
        for prefix in _SCRIPT_PREFIXES:
            if name.startswith(prefix):
                scripts.add(prefix)
                break
        else:
            scripts.add('OTHER')
    return scripts


def _is_homograph_label(label: str) -> bool:
    """Detect labels crafted to impersonate Latin domain names."""
    if label.startswith('xn--'):
        try:
            label = label.encode('ascii').decode('idna')
        except Exception:
            return False

    scripts = _label_scripts(label)

    # Mixing Latin with Cyrillic/Greek in one label is the classic attack;
    # no legitimate registry allows it.
    if 'LATIN' in scripts and scripts & {'CYRILLIC', 'GREEK'}:
        return True

    # An all-Cyrillic label built only from Latin-lookalike letters
    # (e.g. "аррӏе") is visually indistinguishable from Latin.
    if scripts == {'CYRILLIC'}:
        letters = [ch for ch in label if ch.isalpha()]
        if letters and all(ch in _CYRILLIC_CONFUSABLES for ch in letters):
            return True

    return False


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
                        value = (tag.get(attr) or '').strip()
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
            ext = _tld_extract(domain.lower())
            registered_domain = ext.top_domain_under_public_suffix or domain.lower()
            suffix = ext.suffix

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

        return {
            'url': url,
            'original_length': original_length,
            'truncated': original_length > self.max_url_length,
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
