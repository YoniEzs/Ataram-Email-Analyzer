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
                'anchor_mismatches': []
            }

        forms = 0
        scripts = 0
        hidden_elements = 0
        anchor_mismatches = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Count forms
            forms = len(soup.find_all('form'))

            # Count scripts
            scripts = len(soup.find_all('script'))

            # Count hidden elements
            for tag in soup.find_all(True):
                style = (tag.get('style', '') or '').replace(' ', '').lower()
                classes = [c.lower() for c in (tag.get('class') or [])]

                if 'display:none' in style or 'visibility:hidden' in style or 'hidden' in classes:
                    hidden_elements += 1

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
                            'displayed': display_domain,
                            'actual': href_domain
                        })

        except Exception as e:
            logger.warning(f"[ContentAnalyzerService] HTML parsing failed: {e}")
            pass

        return {
            'forms': forms,
            'scripts': scripts,
            'hidden_elements': hidden_elements,
            'anchor_mismatches': anchor_mismatches
        }

    def scan_yara_like(self, content: str) -> List[str]:
        """Basic YARA-like pattern matching"""
        if not content:
            return []

        matches = []
        lower = content.lower()

        # Check for phishing forms
        if re.search(r'<form[^>]*>', lower) and re.search(r'password|username|login', lower):
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
