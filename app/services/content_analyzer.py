"""
Content Analyzer Service
Analyzes email content for phishing indicators
"""

import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class ContentAnalyzerService:
    """Service for analyzing email content and structure"""

    # Phishing keyword lists
    URGENT_PHRASES = [
        'important notice', 'action required', 'verify your account',
        'update your account', 'password expires', 'urgent', 'last warning',
        'immediate', 'suspended', 'locked', 'unusual activity', 'confirm your identity',
        'security alert', 'verify identity', 'update payment', 'billing problem',
        'reactivate', 'click here immediately', 'act now', 'limited time'
    ]

    GENERIC_GREETINGS = [
        'dear customer', 'dear user', 'dear friend', 'dear client',
        'dear member', 'dear sir', 'dear madam', 'valued customer',
        'valued member', 'hello user'
    ]

    CREDENTIAL_KEYWORDS = [
        'password', 'username', 'login', 'credentials', 'credit card',
        'ssn', 'social security', 'account number', 'pin', 'cvv',
        'security code', 'card number', 'expiration date', 'billing address'
    ]

    # Ceilings on what one email may push through the parsers. HTML parsing is
    # the expensive step — BeautifulSoup builds a full tree and the hidden-element
    # pass then walks every tag — so it gets the tighter cap.
    MAX_TEXT_CHARS = 2 * 1024 * 1024
    MAX_HTML_CHARS = 1024 * 1024
    MAX_ANCHOR_MISMATCHES = 200
    MAX_DOM_URLS = 500
    # Ceiling on tags walked. BeautifulSoup's find_all degrades badly on deeply
    # nested documents; without this a 1MB body of nested tags cost 123s.
    MAX_TAGS = 20000

    def __init__(self):
        pass

    def analyze(self, text: str, html: str = '') -> Dict[str, Any]:
        """
        Analyze email content for suspicious patterns

        Args:
            text: Plain text content
            html: HTML content

        Returns:
            Analysis results
        """
        # extract_msg returns htmlBody as Optional[bytes]; concatenating that
        # with str raised TypeError and failed the whole analysis.
        if isinstance(text, bytes):
            text = text.decode('utf-8', 'replace')
        if isinstance(html, bytes):
            html = html.decode('utf-8', 'replace')

        text = (text or '')[:self.MAX_TEXT_CHARS]
        html = (html or '')[:self.MAX_HTML_CHARS]

        language_analysis = self.analyze_language(text) if text else {}
        html_analysis = self.analyze_html(html) if html else {}
        yara_matches = self.scan_yara_like(text + "\n" + html)

        return {
            **language_analysis,
            **html_analysis,
            'yara_matches': yara_matches
        }

    def analyze_language(self, text: str) -> Dict[str, Any]:
        """Analyze text for phishing language patterns"""
        if not text:
            return {
                'urgent_phrases': [],
                'generic_greetings': [],
                'credential_requests': [],
                'exclamation_marks': 0,
                'uppercase_ratio': 0.0
            }

        lower_text = text.lower()

        # Find urgent phrases
        urgent_hits = [
            phrase for phrase in self.URGENT_PHRASES
            if phrase in lower_text
        ]

        # Find generic greetings
        generic_hits = [
            greeting for greeting in self.GENERIC_GREETINGS
            if greeting in lower_text
        ]

        # Find credential requests
        credential_hits = [
            keyword for keyword in self.CREDENTIAL_KEYWORDS
            if keyword in lower_text
        ]

        # Count exclamation marks
        exclamation_count = text.count('!')

        # Calculate uppercase ratio
        uppercase_letters = sum(1 for ch in text if ch.isupper())
        total_letters = sum(1 for ch in text if ch.isalpha()) or 1
        uppercase_ratio = round(uppercase_letters / total_letters, 3)

        return {
            'urgent_phrases': urgent_hits,
            'generic_greetings': generic_hits,
            'credential_requests': credential_hits,
            'exclamation_marks': exclamation_count,
            'uppercase_ratio': uppercase_ratio
        }

    def analyze_html(self, html: str) -> Dict[str, Any]:
        """Analyze HTML structure for suspicious elements"""
        if not html or not BS4_AVAILABLE:
            return {
                'forms': 0,
                'scripts': 0,
                'hidden_elements': 0,
                'anchor_mismatches': [],
                'dom_urls': [],
                'credential_inputs': 0,
                'external_form_actions': [],
            }

        forms = 0
        scripts = 0
        hidden_elements = 0
        anchor_mismatches = []
        dom_urls: List[str] = []
        credential_inputs = 0
        external_form_actions: List[str] = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Count forms
            form_tags = soup.find_all('form')
            forms = len(form_tags)

            # A form in an email posting somewhere is the phishing pattern
            # itself, regardless of what words surround it.
            for form in form_tags[:50]:
                action = form.get('action')
                if isinstance(action, str) and action.strip():
                    external_form_actions.append(action.strip()[:2048])

            # Password-style inputs, detected structurally rather than by
            # keyword. A masked field written as
            #   <input type="text" style="-webkit-text-security:disc">
            # is a real technique that renders as a password box while
            # containing none of the words 'password', 'login' or 'username' —
            # which was enough to score zero.
            for field in soup.find_all('input')[:200]:
                field_type = (field.get('type') or '').strip().lower()
                style = (field.get('style') or '').replace(' ', '').lower()
                autocomplete = (field.get('autocomplete') or '').strip().lower()
                if (field_type == 'password'
                        or 'text-security' in style
                        or autocomplete in ('current-password', 'new-password')):
                    credential_inputs += 1

            # Count scripts
            scripts = len(soup.find_all('script'))

            # ONE traversal for hidden elements and links. Two separate
            # find_all(True) walks doubled the cost of a deeply nested
            # document, and find_all is itself expensive on pathological
            # nesting — a 1.05MB body of nested tags cost 123 seconds.
            # MAX_TAGS bounds it regardless of shape.
            seen_urls = set()
            for index, tag in enumerate(soup.find_all(True)):
                if index >= self.MAX_TAGS:
                    logger.info('[ContentAnalyzerService] tag cap reached; walk stopped')
                    break

                style = (tag.get('style', '') or '').replace(' ', '').lower()
                classes = [c.lower() for c in (tag.get('class') or [])]
                if 'display:none' in style or 'visibility:hidden' in style or 'hidden' in classes:
                    hidden_elements += 1

                # Collect the links the parser actually resolved. BeautifulSoup
                # has already decoded HTML entities, so this sees hrefs a regex
                # over the raw source cannot — exactly how a live link is
                # hidden from URL scoring.
                if len(dom_urls) >= self.MAX_DOM_URLS:
                    continue
                for attribute in ('href', 'src', 'action', 'background'):
                    value = tag.get(attribute)
                    if not value or not isinstance(value, str):
                        continue
                    candidate = value.strip()
                    # Protocol-relative //host/path resolves to https:// in a
                    # mail client; normalise it so it is scored like any URL.
                    if candidate.startswith('//'):
                        candidate = 'https:' + candidate
                    if candidate.lower().startswith(('http://', 'https://')):
                        candidate = candidate[:2048]
                        if candidate not in seen_urls:
                            seen_urls.add(candidate)
                            dom_urls.append(candidate)

            # Check for anchor text mismatches
            for anchor in soup.find_all('a', href=True):
                link_text = anchor.get_text().strip()
                href = anchor['href']

                if link_text and (link_text.startswith('http') or link_text.startswith('www.')):
                    # Extract displayed domain
                    display_domain = link_text.split('://')[-1].split('/')[0].lower()

                    # Extract actual href domain
                    try:
                        import urllib.parse
                        href_domain = urllib.parse.urlparse(href).hostname or ''
                    except Exception:
                        href_domain = ''

                    if display_domain and href_domain and display_domain != href_domain.lower():
                        anchor_mismatches.append({
                            'displayed': display_domain[:253],
                            'actual': href_domain[:253]
                        })
                        if len(anchor_mismatches) >= self.MAX_ANCHOR_MISMATCHES:
                            break

        except Exception as e:
            logger.warning(f"[ContentAnalyzerService] HTML parsing failed: {e}")
            pass

        return {
            'forms': forms,
            'scripts': scripts,
            'hidden_elements': hidden_elements,
            'anchor_mismatches': anchor_mismatches,
            'dom_urls': dom_urls,
            'credential_inputs': credential_inputs,
            'external_form_actions': external_form_actions,
        }

    def scan_yara_like(self, content: str) -> List[str]:
        """Basic YARA-like pattern matching"""
        if not content:
            return []

        matches = []
        lower = content.lower()

        # Check for phishing forms.
        #
        # `<form[^>]*>` backtracks catastrophically: a body of `<form` repeated
        # with no closing `>` made a 1MB email cost 99.7 seconds. A substring
        # test answers the same question — "is there a form tag" — in linear
        # time, and the `>` was never load-bearing for this heuristic.
        if '<form' in lower and re.search(r'password|username|login', lower):
            matches.append('PhishingForm')

        # Check for JavaScript redirects
        if 'window.location' in lower or 'document.location' in lower:
            matches.append('JSRedirect')

        # Check for known phishing kit patterns
        known_patterns = [
            'paypal_verification', 'office365_login', 'bankofamerica_secure',
            'logintemplate', 'phishkit', 'login.php?userid=', 'verify.php',
            'secure-login', 'account-verify', 'billing-update'
        ]

        for pattern in known_patterns:
            if pattern in lower:
                matches.append(f'Kit:{pattern}')

        # Check for obfuscated JavaScript
        if re.search(r'eval\s*\(|unescape\s*\(|fromCharCode', content):
            matches.append('ObfuscatedJS')

        # Check for base64 encoded content
        if re.search(r'atob\s*\(|btoa\s*\(', content):
            matches.append('Base64Encoding')

        return matches
