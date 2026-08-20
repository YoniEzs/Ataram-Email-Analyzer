"""Shared domain helpers.

The Public Suffix List lookup and the homograph heuristic were previously
duplicated across ``url_analyzer`` and ``auth_verifier``. They live here so
every caller agrees on what "the same domain" means.
"""

import unicodedata
from typing import Optional, Set, Tuple

import tldextract

# Offline PSL extractor — uses the bundled Public Suffix List snapshot,
# never fetches over the network at runtime.
_tld_extract = tldextract.TLDExtract(suffix_list_urls=())

# Cyrillic letters that render (near-)identically to Latin ones — the raw
# material of homograph attacks like "pаypal.com".
_CYRILLIC_CONFUSABLES = set('аеорсухіјѕԛԝьӏԁɡ')

_SCRIPT_PREFIXES = ('LATIN', 'CYRILLIC', 'GREEK', 'HEBREW', 'ARABIC')


def registered_domain(host: str) -> str:
    """PSL-aware registered domain (example.co.uk stays example.co.uk)."""
    if not host:
        return ""
    ext = _tld_extract(host.lower())
    return ext.top_domain_under_public_suffix or host.lower()


def registered_domain_and_suffix(host: str) -> Tuple[str, str]:
    """Registered domain and public suffix in one PSL lookup."""
    if not host:
        return "", ""
    ext = _tld_extract(host.lower())
    return (ext.top_domain_under_public_suffix or host.lower()), ext.suffix


def organizational_domain(domain: Optional[str]) -> Optional[str]:
    """``registered_domain`` that preserves None and strips trailing dots."""
    if not domain:
        return None
    clean = domain.strip().lower().rstrip('.')
    extracted = _tld_extract(clean)
    return extracted.top_domain_under_public_suffix or clean


def label_scripts(label: str) -> Set[str]:
    """Return the set of Unicode scripts used by letters in a label."""
    scripts: Set[str] = set()
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


def is_homograph_label(label: str) -> bool:
    """Detect labels crafted to impersonate Latin domain names."""
    if label.startswith('xn--'):
        try:
            label = label.encode('ascii').decode('idna')
        except Exception:
            return False

    scripts = label_scripts(label)

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


def is_homograph_domain(domain: str) -> bool:
    """True when any label of the domain looks like a homograph attack."""
    if not domain:
        return False
    return any(is_homograph_label(label) for label in domain.lower().split('.'))


def is_punycode_domain(domain: str) -> bool:
    """True when any label is IDNA/punycode-encoded."""
    if not domain:
        return False
    return any(label.startswith('xn--') for label in domain.lower().split('.'))


def decode_punycode_domain(domain: str) -> Optional[str]:
    """Best-effort Unicode rendering of a punycode domain, else None."""
    if not is_punycode_domain(domain):
        return None
    labels = []
    for label in domain.lower().split('.'):
        if label.startswith('xn--'):
            try:
                labels.append(label.encode('ascii').decode('idna'))
                continue
            except Exception:
                return None
        labels.append(label)
    return '.'.join(labels)
