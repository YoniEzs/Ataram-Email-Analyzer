"""
Network target validation.

Every lookup this service performs — DNS, WHOIS, AbuseIPDB — is triggered by
attacker-controlled input: a domain out of a From header, or a value posted
straight to the utility endpoints. That makes the server a lookup proxy, so the
targets have to be constrained before any packet leaves the box:

* internal names must be rejected, otherwise a stranger can use the resolver to
  map the private network behind it (does `backup.corp.internal` resolve?);
* non-public IPs must be rejected, so the reputation lookup can't be pointed at
  loopback, link-local metadata (169.254.169.254) or RFC1918 space;
* lengths must be capped, so a single request can't push a megabyte into a
  resolver or a WHOIS socket.
"""

import ipaddress
import re
from typing import Optional, Tuple

# RFC-1123 hostname: labels of alphanumerics and hyphens, not starting or
# ending with a hyphen, and an alphabetic TLD of at least two characters.
_DOMAIN_RE = re.compile(r'^(?!-)(?:[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$')

# Same shape, but underscore-prefixed labels are allowed. Email authentication
# records live under names like `_dmarc.example.com` and
# `selector._domainkey.example.com`, which are not valid hostnames and so are
# correctly rejected by _DOMAIN_RE. Validating those query names with the
# hostname pattern is why DMARC and DKIM lookups silently returned nothing.
_DNS_NAME_RE = re.compile(r'^(?:_?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')

MAX_DOMAIN_LENGTH = 253
MAX_URL_LENGTH = 2048
MAX_DKIM_SELECTOR_LENGTH = 63

# Suffixes that never belong to the public DNS. `.local` is mDNS, `.internal`
# is the convention on most cloud providers (and GCP's metadata name),
# `home.arpa` is RFC 8375, and the rest are RFC 6761/6762 special-use or common
# private conventions.
PRIVATE_SUFFIXES = (
    '.local',
    '.localhost',
    '.internal',
    '.intranet',
    '.private',
    '.corp',
    '.home',
    '.home.arpa',
    '.lan',
    '.test',
    '.example',
    '.invalid',
    '.onion',
    '.i2p',
    '.in-addr.arpa',
    '.ip6.arpa',
)

BLOCKED_HOSTNAMES = frozenset({
    'localhost',
    'localhost.localdomain',
    'metadata',
    'metadata.google.internal',
    'instance-data',
})


# Two-label public suffixes common enough to matter. Without this,
# `example.co.uk` reduces to `co.uk` — which made `login.microsoft.co.uk` and
# `www.google.co.uk` register as brand impersonation, and made WHOIS cache keys
# collide across every .co.uk domain. Not a full Public Suffix List; it does not
# need to be, because an imperfect reduction only costs precision, never safety.
MULTI_LABEL_SUFFIXES = frozenset({
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk', 'ltd.uk', 'plc.uk',
    'co.il', 'org.il', 'ac.il', 'gov.il', 'net.il', 'muni.il', 'idf.il',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au', 'asn.au',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'lg.jp',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'geek.nz',
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
    'com.mx', 'com.tr', 'com.sg', 'com.hk', 'com.tw', 'com.my', 'com.ph',
    'com.ar', 'com.pl', 'com.ua', 'com.vn', 'com.co', 'com.pe', 'com.eg',
    'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in',
    'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'ac.kr',
    'co.th', 'in.th', 'ac.th', 'go.th',
    'co.id', 'or.id', 'ac.id', 'go.id',
    'gov.uk', 'nhs.uk', 'police.uk', 'mod.uk',
})


def registrable_domain(domain: str) -> str:
    """
    Reduce a hostname to the domain that was actually registered.

    Shared by WHOIS caching (so `a.example.com` and `b.example.com` are one
    lookup) and by URL brand-impersonation scoring (so `login.microsoft.co.uk`
    is recognised as Microsoft's own domain rather than a lookalike).
    """
    labels = (domain or '').strip().rstrip('.').lower().split('.')
    labels = [label for label in labels if label]
    if len(labels) <= 2:
        return '.'.join(labels)
    if '.'.join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def is_public_domain(domain: str) -> bool:
    """
    True only for a syntactically valid domain that plausibly exists in public DNS.

    Rejects IP literals, single-label names, private/special-use suffixes and
    anything over the DNS length limit.
    """
    if not domain or not isinstance(domain, str):
        return False

    candidate = domain.strip().rstrip('.').lower()

    if not candidate or len(candidate) > MAX_DOMAIN_LENGTH:
        return False

    # A trailing-dot-stripped name must still contain no whitespace or control
    # characters; the regex covers this, but reject early and explicitly.
    if any(ch.isspace() or ord(ch) < 33 for ch in candidate):
        return False

    if candidate in BLOCKED_HOSTNAMES:
        return False

    # An IP literal is not a domain, and would otherwise slip past the suffix
    # checks for lookups that expect a name.
    try:
        ipaddress.ip_address(candidate)
        return False
    except ValueError:
        pass

    if any(candidate == suffix.lstrip('.') or candidate.endswith(suffix)
           for suffix in PRIVATE_SUFFIXES):
        return False

    return bool(_DOMAIN_RE.match(candidate))


def is_safe_dns_query_name(name: str) -> bool:
    """
    True for a DNS name this service may query.

    Looser than `is_public_domain` only in allowing underscore-prefixed labels,
    so `_dmarc.example.com` and `sel._domainkey.example.com` are queryable. The
    private/special-use suffix and length rules still apply, so it cannot be
    used to reach internal names.
    """
    if not name or not isinstance(name, str):
        return False

    candidate = name.strip().rstrip('.').lower()

    if not candidate or len(candidate) > MAX_DOMAIN_LENGTH:
        return False
    if any(ch.isspace() or ord(ch) < 33 for ch in candidate):
        return False
    if candidate in BLOCKED_HOSTNAMES:
        return False
    if any(candidate == suffix.lstrip('.') or candidate.endswith(suffix)
           for suffix in PRIVATE_SUFFIXES):
        return False

    return bool(_DNS_NAME_RE.match(candidate))


def is_safe_dkim_selector(selector: str) -> bool:
    """
    True for a DKIM selector safe to splice into a query name.

    The selector comes out of a DKIM-Signature header on an untrusted email, so
    it must not be able to introduce extra labels or overlong names.
    """
    if not selector or not isinstance(selector, str):
        return False
    if len(selector) > MAX_DKIM_SELECTOR_LENGTH:
        return False
    return bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', selector))


def is_public_ip(value: str) -> bool:
    """
    True only for a global unicast address.

    `is_global` is what excludes loopback, RFC1918, link-local (and with it the
    169.254.169.254 cloud metadata endpoint), CGNAT, multicast and reserved space.
    """
    if not value or not isinstance(value, str):
        return False
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return addr.is_global


def validate_domain_input(value) -> Tuple[bool, Optional[str], str]:
    """
    Validate a domain supplied in a request body.

    Returns (is_valid, normalised_domain, error_message).
    """
    if not isinstance(value, str):
        return False, None, 'Domain must be a string'

    candidate = value.strip().rstrip('.').lower()

    if not candidate:
        return False, None, 'Domain must not be empty'
    if len(candidate) > MAX_DOMAIN_LENGTH:
        return False, None, f'Domain must be at most {MAX_DOMAIN_LENGTH} characters'
    if not is_public_domain(candidate):
        return False, None, 'Only public, routable domain names can be checked'

    return True, candidate, ''


def validate_ip_input(value) -> Tuple[bool, Optional[str], str]:
    """
    Validate an IP supplied in a request body.

    Returns (is_valid, normalised_ip, error_message).
    """
    if not isinstance(value, str):
        return False, None, 'IP must be a string'

    candidate = value.strip()

    if not candidate:
        return False, None, 'IP must not be empty'
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return False, None, 'Not a valid IP address'
    if not addr.is_global:
        return False, None, 'Only public, routable IP addresses can be checked'

    return True, str(addr), ''


def validate_url_input(value) -> Tuple[bool, Optional[str], str]:
    """
    Validate a URL supplied in a request body.

    The analyzer never fetches the URL, so the constraint is on shape and size
    rather than on the destination: reject non-strings, oversized values and
    schemes that would be meaningless (or dangerous if a result were ever
    rendered as a link).

    Returns (is_valid, url, error_message).
    """
    if not isinstance(value, str):
        return False, None, 'URL must be a string'

    candidate = value.strip()

    if not candidate:
        return False, None, 'URL must not be empty'
    if len(candidate) > MAX_URL_LENGTH:
        return False, None, f'URL must be at most {MAX_URL_LENGTH} characters'
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
        return False, None, 'URL must not contain control characters'
    if not re.match(r'^https?://', candidate, re.IGNORECASE):
        return False, None, 'URL must start with http:// or https://'

    return True, candidate, ''
