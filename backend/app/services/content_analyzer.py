"""
Content Analyzer Service
Analyzes email content for phishing indicators
"""

import json
import os
import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

_KEYWORDS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'data', 'phishing_keywords',
)

# Minimal built-in fallback if the data files are missing/corrupt
_FALLBACK_KEYWORDS = {
    'urgent_phrases': [
        'action required', 'verify your account', 'urgent', 'suspended',
        'unusual activity', 'act now',
    ],
    'generic_greetings': ['dear customer', 'dear user', 'valued customer'],
    'credential_keywords': ['password', 'credit card', 'login', 'cvv'],
}


def _load_keyword_lists() -> Dict[str, List[str]]:
    """Merge phishing keyword lists across all language files.

    Emails routinely mix languages, so all lists are matched at once —
    no language detection step to get wrong.
    """
    merged: Dict[str, List[str]] = {
        'urgent_phrases': [],
        'generic_greetings': [],
        'credential_keywords': [],
    }
    loaded_any = False
    try:
        for fname in sorted(os.listdir(_KEYWORDS_DIR)):
            if not fname.endswith('.json'):
                continue
            path = os.path.join(_KEYWORDS_DIR, fname)
            try:
                with open(path, encoding='utf-8') as f:
                    data = json.load(f)
                for key in merged:
                    merged[key].extend(
                        str(kw).lower() for kw in data.get(key, [])
                    )
                loaded_any = True
            except Exception as e:
                logger.warning(f"[ContentAnalyzerService] Bad keyword file {fname}: {e}")
    except OSError as e:
        logger.warning(f"[ContentAnalyzerService] Keyword dir unavailable: {e}")

    if not loaded_any:
        return {k: list(v) for k, v in _FALLBACK_KEYWORDS.items()}
    # De-duplicate, preserve order
    return {k: list(dict.fromkeys(v)) for k, v in merged.items()}


_KEYWORDS = _load_keyword_lists()


class ContentAnalyzerService:
    """Service for analyzing email content and structure"""

    URGENT_PHRASES = _KEYWORDS['urgent_phrases']
    GENERIC_GREETINGS = _KEYWORDS['generic_greetings']
    CREDENTIAL_KEYWORDS = _KEYWORDS['credential_keywords']

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
                style = str(tag.get('style', '') or '').replace(' ', '').lower()
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
                        href_domain = urllib.parse.urlparse(str(href)).hostname or ''
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
