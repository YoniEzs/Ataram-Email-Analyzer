"""Offline extraction of the analyst triage checklist.

Produces the seven artifacts a SOC analyst records for every reported message
— sender address, subject, recipients, date/time, sending server IP, reverse
DNS and Reply-To — plus the supporting fields needed to reason about them.

Everything here is CPU-only and deterministic: no DNS, no HTTP, no clock reads
outside the injectable ``now``. Live enrichment is layered on afterwards by
``EmailAnalyzerService``.

Trust vocabulary used throughout:

``header_claim``
    Read from the uploaded file. An attacker who supplies the file controls it.
``computed``
    A deterministic property *of* the claim — script mixing, bidi overrides,
    self-inconsistency. Choosing the string is itself the evidence, so these
    can be scored.
``observed``
    Re-derived from a live lookup at analysis time. Added by the analyzer.
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Callable, Dict, List, Optional

from app.services.received_parser import parse_received_chain
from app.utils.domains import (
    decode_punycode_domain,
    is_homograph_domain,
    is_punycode_domain,
    registered_domain,
)
from app.utils.extractors import email_domain, is_global_ip, iter_ip_candidates
from app.utils.text_flags import (
    BIDI_OVERRIDE_CHARS,
    ZERO_WIDTH_CHARS,
    find_chars,
)

logger = logging.getLogger(__name__)

MAX_ADDRESSES = 200
LARGE_RECIPIENT_LIST = 50
# MTA clocks drift; only disagreements beyond this are worth reporting.
CLOCK_TOLERANCE_SECONDS = 300
IMPLAUSIBLY_OLD_DAYS = 3650

_DOMAIN_LISTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'data', 'sender_domains',
)

_FALLBACK_FREEMAIL = frozenset({
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'aol.com',
    'icloud.com', 'proton.me', 'gmx.com', 'mail.ru', 'yandex.com',
})

_ROLE_LOCAL_PARTS = frozenset({
    'admin', 'administrator', 'support', 'billing', 'accounts', 'accounting',
    'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'postmaster', 'abuse',
    'info', 'sales', 'security', 'helpdesk', 'service', 'notifications',
    'alerts', 'webmaster', 'hostmaster', 'contact', 'office', 'hr', 'payroll',
})

# "Re:", "Fw:", "Fwd:", and the German/Swedish/Dutch equivalents, possibly
# stacked and possibly carrying a mailing-list counter like "Re[2]:".
_REPLY_PREFIX = re.compile(
    r'^\s*(?:(?:re|fw|fwd|aw|sv|antw|vs|tr)\s*(?:\[\d+\])?\s*:\s*)+', re.I
)
_ENCODED_WORD = re.compile(r'=\?([^?]{1,64})\?([bBqQ])\?')
_UNDISCLOSED = re.compile(r'undisclosed[-\s]?recipients', re.I)
_ADDRESS_IN_TEXT = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')


def _load_domain_list(filename: str, fallback: frozenset) -> frozenset:
    """Load one bundled domain list, degrading to a small built-in set."""
    path = os.path.join(_DOMAIN_LISTS_DIR, filename)
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
        domains = {
            str(d).strip().lower()
            for d in data.get('domains', [])
            if str(d).strip()
        }
        if domains:
            return frozenset(domains)
        logger.warning('[ArtifactExtractor] %s contained no domains', filename)
    except Exception as exc:
        logger.warning('[ArtifactExtractor] Bad domain file %s: %s', filename, exc)
    return fallback


FREEMAIL_DOMAINS = _load_domain_list('freemail.json', _FALLBACK_FREEMAIL)
DISPOSABLE_DOMAINS = _load_domain_list('disposable.json', frozenset())


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def split_address(value: str) -> Dict[str, Optional[str]]:
    """Split ``Display Name <local@domain>`` into its parts."""
    result: Dict[str, Optional[str]] = {
        'raw': value or None,
        'display_name': None,
        'address': None,
        'local_part': None,
        'domain': None,
        'registered_domain': None,
    }
    if not value:
        return result

    pairs = getaddresses([value])
    display, address = pairs[0] if pairs else ('', '')
    result['display_name'] = (display or '').strip() or None
    address = (address or '').strip().lower()
    result['address'] = address or None
    if address and '@' in address:
        local, _, domain = address.rpartition('@')
        result['local_part'] = local or None
        result['domain'] = domain or None
        result['registered_domain'] = registered_domain(domain) or None
    return result


def classify_domain(domain: Optional[str]) -> Dict[str, Any]:
    """Offline reputation-free classification of a sender domain."""
    if not domain:
        return {
            'freemail': False, 'disposable': False,
            'punycode': False, 'homoglyph': False, 'unicode_domain': None,
        }
    lowered = domain.lower()
    registered = registered_domain(lowered)
    return {
        'freemail': lowered in FREEMAIL_DOMAINS or registered in FREEMAIL_DOMAINS,
        'disposable': lowered in DISPOSABLE_DOMAINS or registered in DISPOSABLE_DOMAINS,
        'punycode': is_punycode_domain(lowered),
        'homoglyph': is_homograph_domain(lowered),
        'unicode_domain': decode_punycode_domain(lowered),
    }


def _is_role_account(local_part: Optional[str]) -> bool:
    if not local_part:
        return False
    return local_part.split('+')[0].lower() in _ROLE_LOCAL_PARTS


def _address_entries(raw_values: Any) -> List[Dict[str, str]]:
    """Normalise pre-parsed address entries coming from the parser."""
    entries: List[Dict[str, str]] = []
    for item in (raw_values or [])[:MAX_ADDRESSES]:
        if isinstance(item, dict):
            address = str(item.get('address') or '').strip().lower()
            name = str(item.get('name') or '').strip()
        else:
            parsed = split_address(str(item))
            address = parsed['address'] or ''
            name = parsed['display_name'] or ''
        if address or name:
            entries.append({'name': name, 'address': address})
    return entries


def _addresses_of(entries: List[Dict[str, str]]) -> List[str]:
    return [e['address'] for e in entries if e.get('address')]


# ---------------------------------------------------------------------------
# Per-artifact analysis
# ---------------------------------------------------------------------------

def analyze_sender(headers: Dict[str, Any]) -> Dict[str, Any]:
    raw = headers.get('sender') or ''
    parsed = split_address(raw)
    classification = classify_domain(parsed['domain'])
    from_entries = _address_entries(headers.get('from_addresses'))

    flags: List[str] = []
    if not parsed['address']:
        flags.append('no_from_header')
    if len(from_entries) > 1:
        flags.append('multiple_from_addresses')
    if classification['punycode']:
        flags.append('punycode_sender_domain')
    if classification['homoglyph']:
        flags.append('homoglyph_sender_domain')
    if classification['freemail']:
        flags.append('freemail_sender')
    if classification['disposable']:
        flags.append('disposable_sender_domain')

    # A display name that itself contains a different address is the classic
    # "Support <security@paypal.com>" dressing over an unrelated mailbox.
    display_name = parsed['display_name'] or ''
    embedded = _ADDRESS_IN_TEXT.search(display_name)
    embedded_address = None
    if embedded and parsed['registered_domain']:
        embedded_address = embedded.group(0).lower()
        embedded_registered = registered_domain(email_domain(embedded_address))
        if embedded_registered and embedded_registered != parsed['registered_domain']:
            flags.append('display_name_domain_mismatch')

    return {
        'value': raw or None,
        'trust': 'header_claim',
        'source': 'From',
        'display_name': parsed['display_name'],
        'address': parsed['address'],
        'local_part': parsed['local_part'],
        'domain': parsed['domain'],
        'registered_domain': parsed['registered_domain'],
        'address_count': len(from_entries),
        'embedded_display_address': embedded_address,
        'classification': {
            'freemail': classification['freemail'],
            'disposable': classification['disposable'],
            'role_account': _is_role_account(parsed['local_part']),
        },
        'is_punycode': classification['punycode'],
        'is_homoglyph': classification['homoglyph'],
        'unicode_domain': classification['unicode_domain'],
        'flags': flags,
        'enrichment': None,
    }


def analyze_subject(headers: Dict[str, Any]) -> Dict[str, Any]:
    decoded = headers.get('subject') or ''
    raw = headers.get('subject_raw') or decoded
    in_reply_to = (headers.get('in_reply_to') or '').strip()
    references = (headers.get('references') or '').strip()

    encoded_words = [
        {'charset': charset.lower(), 'encoding': encoding.upper()}
        for charset, encoding in _ENCODED_WORD.findall(raw)
    ]
    charsets = sorted({word['charset'] for word in encoded_words})

    # Subjects check override characters only. LRM/RLM are ordinary in Hebrew
    # and Arabic mail, so flagging them here would fire on normal traffic.
    bidi = find_chars(decoded, BIDI_OVERRIDE_CHARS)
    zero_width = find_chars(decoded, ZERO_WIDTH_CHARS)

    prefix_match = _REPLY_PREFIX.match(decoded)
    reply_prefixes = (
        [p.strip() for p in re.split(r'[:\s]+', prefix_match.group(0)) if p.strip()]
        if prefix_match else []
    )
    has_thread_headers = bool(in_reply_to or references)

    flags: List[str] = []
    if not decoded.strip():
        flags.append('empty_subject')
    if bidi:
        flags.append('bidi_override_in_subject')
    if zero_width:
        flags.append('zero_width_in_subject')
    if len(charsets) > 1:
        flags.append('mixed_charsets_in_subject')
    if reply_prefixes and not has_thread_headers:
        flags.append('reply_prefix_without_thread_headers')

    return {
        'value': decoded or None,
        'raw': raw or None,
        'trust': 'header_claim',
        'source': 'Subject',
        'length': len(decoded),
        'encoded_words': encoded_words,
        'charsets': charsets,
        'bidi_controls': bidi,
        'zero_width': zero_width,
        'reply_prefixes': reply_prefixes,
        'has_thread_headers': has_thread_headers,
        'flags': flags,
        'enrichment': None,
    }


def analyze_recipients(headers: Dict[str, Any]) -> Dict[str, Any]:
    to = _address_entries(headers.get('to'))
    cc = _address_entries(headers.get('cc'))
    bcc = _address_entries(headers.get('bcc'))

    envelope_sources: Dict[str, List[str]] = {}
    for header_name, key in (
        ('Delivered-To', 'delivered_to'),
        ('X-Original-To', 'x_original_to'),
        ('X-Envelope-To', 'x_envelope_to'),
    ):
        values = [
            str(v).strip().lower()
            for v in (headers.get(key) or [])[:MAX_ADDRESSES]
            if str(v).strip()
        ]
        # These headers may carry a bare address or a full name/address pair.
        normalised = []
        for value in values:
            parsed = split_address(value)
            normalised.append(parsed['address'] or value)
        if normalised:
            envelope_sources[header_name] = normalised

    envelope = list(dict.fromkeys(
        addr for values in envelope_sources.values() for addr in values
    ))
    visible = {a for a in _addresses_of(to) + _addresses_of(cc) + _addresses_of(bcc)}
    # An envelope recipient that appears in no visible header means this copy
    # was delivered off-list, which is what a Bcc looks like from the outside.
    bcc_inferred = [addr for addr in envelope if addr and addr not in visible]

    to_raw = headers.get('to_raw') or ''
    cc_raw = headers.get('cc_raw') or ''
    visible_total = len(to) + len(cc)
    undisclosed = bool(
        _UNDISCLOSED.search(to_raw) or _UNDISCLOSED.search(cc_raw)
        or (visible_total == 0 and bool(envelope))
    )

    flags: List[str] = []
    if bcc_inferred:
        flags.append('possible_bcc_delivery')
    if undisclosed:
        flags.append('undisclosed_recipients')
    if visible_total == 0 and not undisclosed:
        flags.append('no_visible_recipients')
    if visible_total > LARGE_RECIPIENT_LIST:
        flags.append('large_recipient_list')

    return {
        'value': headers.get('recipients') or None,
        'trust': 'header_claim',
        'source': 'To/Cc',
        'to': to,
        'cc': cc,
        'bcc': bcc,
        'to_count': len(to),
        'cc_count': len(cc),
        'bcc_count': len(bcc),
        'visible_total': visible_total,
        'envelope_recipients': envelope,
        'envelope_sources': envelope_sources,
        'bcc_inferred': bcc_inferred,
        'undisclosed': undisclosed,
        'flags': flags,
        'enrichment': None,
    }


def analyze_date(
    headers: Dict[str, Any],
    hops: List[Dict[str, Any]],
    now: datetime,
) -> Dict[str, Any]:
    raw = headers.get('date') or ''
    flags: List[str] = []

    parsed: Optional[datetime] = None
    offset_minutes: Optional[int] = None
    if raw.strip():
        try:
            parsed = parsedate_to_datetime(raw)
        except (ValueError, TypeError, IndexError):
            parsed = None
        if parsed is None:
            flags.append('unparseable_date')
        elif parsed.tzinfo is None:
            flags.append('missing_timezone')
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            offset = parsed.utcoffset()
            offset_minutes = int(offset.total_seconds() // 60) if offset else 0
    else:
        flags.append('missing_date')

    utc = parsed.astimezone(timezone.utc) if parsed else None

    stamps = sorted(
        datetime.fromisoformat(hop['timestamp'])
        for hop in hops
        if hop.get('timestamp')
    )
    oldest = stamps[0] if stamps else None
    newest = stamps[-1] if stamps else None

    transit_seconds = (
        int((newest - oldest).total_seconds()) if oldest and newest else None
    )
    skew_seconds = (
        int((utc - oldest).total_seconds()) if utc and oldest else None
    )

    if utc:
        if (utc - now).total_seconds() > CLOCK_TOLERANCE_SECONDS:
            flags.append('future_dated')
        if (now - utc) > timedelta(days=IMPLAUSIBLY_OLD_DAYS):
            flags.append('implausibly_old')
        if oldest and (oldest - utc).total_seconds() > CLOCK_TOLERANCE_SECONDS:
            flags.append('date_before_first_hop')
        if newest and (utc - newest).total_seconds() > CLOCK_TOLERANCE_SECONDS:
            flags.append('date_after_last_hop')

    # The chain is newest-first, so its timestamps should be non-increasing.
    ordered = [hop['timestamp'] for hop in hops if hop.get('timestamp')]
    for newer, older in zip(ordered, ordered[1:]):
        gap = (
            datetime.fromisoformat(older) - datetime.fromisoformat(newer)
        ).total_seconds()
        if gap > CLOCK_TOLERANCE_SECONDS:
            flags.append('received_chain_out_of_order')
            break

    return {
        'value': raw or None,
        'trust': 'header_claim',
        'source': 'Date',
        'utc': utc.isoformat() if utc else None,
        'offset_minutes': offset_minutes,
        'oldest_received_utc': oldest.isoformat() if oldest else None,
        'newest_received_utc': newest.isoformat() if newest else None,
        'transit_seconds': transit_seconds,
        'skew_vs_oldest_received_seconds': skew_seconds,
        'flags': flags,
        'enrichment': None,
    }


def analyze_sending_server(
    headers: Dict[str, Any], hops: List[Dict[str, Any]]
) -> Dict[str, Any]:
    chain: List[str] = []
    for hop in hops:
        ip = hop.get('from_ip')
        if ip and ip not in chain:
            chain.append(ip)

    # Oldest hop first == furthest from the recipient == the claimed origin.
    origin_ip = chain[-1] if chain else None
    edge_ip = chain[0] if chain else None

    helo_claimed = None
    helo_hop = None
    for hop in reversed(hops):
        if hop.get('from_ip') == origin_ip and hop.get('from_name'):
            helo_claimed = hop['from_name']
            helo_hop = hop.get('index')
            break

    x_originating = None
    for candidate in iter_ip_candidates(headers.get('x_originating_ip') or ''):
        if is_global_ip(candidate):
            x_originating = candidate
            break

    flags: List[str] = []
    if not origin_ip:
        flags.append('no_public_sender_ip')
    if x_originating and origin_ip and x_originating != origin_ip:
        flags.append('x_originating_ip_disagrees_with_chain')

    return {
        'value': origin_ip,
        'trust': 'header_claim',
        'source': 'Received',
        'ip': origin_ip,
        'ip_source': 'oldest_public_received_ip',
        'edge_ip': edge_ip,
        'ip_chain': chain,
        'enriched_ip': origin_ip,
        'helo_claimed': helo_claimed,
        'helo_source_hop': helo_hop,
        'x_originating_ip': x_originating,
        'hop_count': len(hops),
        'flags': flags,
        'enrichment': {},
    }


def _analyze_address_artifact(
    raw: str, source: str, sender: Dict[str, Any], mismatch_flag: str
) -> Dict[str, Any]:
    parsed = split_address(raw)
    classification = classify_domain(parsed['domain'])
    flags: List[str] = []

    sender_registered = sender.get('registered_domain')
    if parsed['registered_domain'] and sender_registered:
        if parsed['registered_domain'] != sender_registered:
            flags.append(mismatch_flag)
    if classification['disposable']:
        flags.append('disposable_domain')
    if classification['homoglyph']:
        flags.append('homoglyph_domain')
    if (
        classification['freemail']
        and not sender.get('classification', {}).get('freemail')
        and sender_registered
    ):
        flags.append('freemail_reply_target')

    return {
        'value': raw or None,
        'trust': 'header_claim',
        'source': source,
        'display_name': parsed['display_name'],
        'address': parsed['address'],
        'domain': parsed['domain'],
        'registered_domain': parsed['registered_domain'],
        'classification': {
            'freemail': classification['freemail'],
            'disposable': classification['disposable'],
            'role_account': _is_role_account(parsed['local_part']),
        },
        'flags': flags,
        'enrichment': None,
    }


def analyze_message_id(headers: Dict[str, Any], sender: Dict[str, Any]) -> Dict[str, Any]:
    raw = (headers.get('message_id') or '').strip()
    domain = email_domain(raw.strip('<>')) if raw else ''
    registered = registered_domain(domain) if domain else None

    flags: List[str] = []
    if not raw:
        flags.append('missing_message_id')
    elif registered and sender.get('registered_domain'):
        if registered != sender['registered_domain']:
            flags.append('message_id_domain_differs_from_sender')

    return {
        'value': raw or None,
        'trust': 'header_claim',
        'source': 'Message-ID',
        'domain': domain or None,
        'registered_domain': registered,
        'flags': flags,
        'enrichment': None,
    }


class ArtifactExtractorService:
    """Builds the offline artifact block from parsed headers."""

    def __init__(
        self,
        *,
        now: Optional[Callable[[], datetime]] = None,
        max_addresses: int = MAX_ADDRESSES,
    ) -> None:
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.max_addresses = max_addresses

    def extract(
        self, headers: Dict[str, Any], *, sender_domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """Extract every offline artifact. Never raises."""
        try:
            return self._extract(headers or {})
        except Exception as exc:
            logger.warning('[ArtifactExtractor] extraction failed: %s', exc)
            return {
                'schema_version': 1,
                'generated_at': self._now().isoformat(),
                'error': 'artifact_extraction_failed',
                'checklist': {},
                'flags': [],
                'enrichment_status': {},
            }

    def _extract(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        hops = parse_received_chain(headers.get('hops'))

        sender = analyze_sender(headers)
        subject = analyze_subject(headers)
        recipients = analyze_recipients(headers)
        date = analyze_date(headers, hops, self._now())
        sending_server = analyze_sending_server(headers, hops)
        reply_to = _analyze_address_artifact(
            headers.get('reply_to') or '', 'Reply-To', sender,
            'reply_to_differs_from_sender',
        )
        return_path = _analyze_address_artifact(
            headers.get('return_path') or '', 'Return-Path', sender,
            'return_path_differs_from_sender',
        )
        message_id = analyze_message_id(headers, sender)

        reverse_dns: Dict[str, Any] = {
            'value': None,
            'trust': 'observed',
            'source': 'live_dns',
            'status': 'pending',
            'flags': [],
            'enrichment': None,
        }

        artifacts: Dict[str, Any] = {
            'schema_version': 1,
            'generated_at': self._now().isoformat(),
            'sender': sender,
            'subject': subject,
            'recipients': recipients,
            'date': date,
            'sending_server': sending_server,
            'reverse_dns': reverse_dns,
            'reply_to': reply_to,
            'return_path': return_path,
            'message_id': message_id,
            'received_chain': hops,
            'authentication_advisory': {
                'spf': None,
                'received_spf_header_claim': headers.get('received_spf') or None,
            },
            'enrichment_status': {
                'reverse_dns': 'pending',
                'ip_intel': 'pending',
                'spf_advisory': 'pending',
            },
        }
        artifacts['checklist'] = self._build_checklist(artifacts)
        artifacts['flags'] = collect_flags(artifacts)
        # Consumed by the analyzer when building the advisory SPF job, then
        # dropped before serialization.
        artifacts['_spf_mail_from'] = (
            return_path.get('address') or sender.get('address')
        )
        return artifacts

    @staticmethod
    def _build_checklist(artifacts: Dict[str, Any]) -> Dict[str, Any]:
        recipients = artifacts['recipients']
        visible = _addresses_of(recipients['to']) + _addresses_of(recipients['cc'])
        return {
            'sender_address': artifacts['sender']['address'],
            'subject': artifacts['subject']['value'],
            'recipients': ', '.join(visible) or None,
            'date_utc': artifacts['date']['utc'],
            'sending_server_ip': artifacts['sending_server']['ip'],
            'reverse_dns': artifacts['reverse_dns']['value'],
            'reply_to': artifacts['reply_to']['address'],
        }


# Severity and trust for every artifact flag. Anything absent here is shown
# without a severity and never scored.
FLAG_METADATA: Dict[str, Dict[str, str]] = {
    # computed — properties of the attacker's own string
    'homoglyph_sender_domain': {'severity': 'high', 'trust': 'computed'},
    'punycode_sender_domain': {'severity': 'medium', 'trust': 'computed'},
    'display_name_domain_mismatch': {'severity': 'high', 'trust': 'computed'},
    'disposable_sender_domain': {'severity': 'medium', 'trust': 'computed'},
    'freemail_sender': {'severity': 'low', 'trust': 'computed'},
    'multiple_from_addresses': {'severity': 'medium', 'trust': 'computed'},
    'no_from_header': {'severity': 'medium', 'trust': 'computed'},
    'bidi_override_in_subject': {'severity': 'high', 'trust': 'computed'},
    'zero_width_in_subject': {'severity': 'medium', 'trust': 'computed'},
    'mixed_charsets_in_subject': {'severity': 'medium', 'trust': 'computed'},
    'reply_prefix_without_thread_headers': {'severity': 'medium', 'trust': 'computed'},
    'empty_subject': {'severity': 'low', 'trust': 'computed'},
    'date_before_first_hop': {'severity': 'medium', 'trust': 'computed'},
    'date_after_last_hop': {'severity': 'medium', 'trust': 'computed'},
    'received_chain_out_of_order': {'severity': 'medium', 'trust': 'computed'},
    'future_dated': {'severity': 'medium', 'trust': 'computed'},
    'implausibly_old': {'severity': 'low', 'trust': 'computed'},
    'unparseable_date': {'severity': 'low', 'trust': 'computed'},
    'missing_date': {'severity': 'low', 'trust': 'computed'},
    'missing_timezone': {'severity': 'low', 'trust': 'computed'},
    'homoglyph_domain': {'severity': 'high', 'trust': 'computed'},
    'disposable_domain': {'severity': 'medium', 'trust': 'computed'},
    'message_id_domain_differs_from_sender': {'severity': 'low', 'trust': 'computed'},
    'missing_message_id': {'severity': 'low', 'trust': 'computed'},
    # header_claim — depends on a forgeable field
    'possible_bcc_delivery': {'severity': 'info', 'trust': 'header_claim'},
    'undisclosed_recipients': {'severity': 'low', 'trust': 'header_claim'},
    'no_visible_recipients': {'severity': 'low', 'trust': 'header_claim'},
    'large_recipient_list': {'severity': 'low', 'trust': 'header_claim'},
    'reply_to_differs_from_sender': {'severity': 'low', 'trust': 'header_claim'},
    'return_path_differs_from_sender': {'severity': 'medium', 'trust': 'header_claim'},
    'freemail_reply_target': {'severity': 'medium', 'trust': 'header_claim'},
    'no_public_sender_ip': {'severity': 'low', 'trust': 'header_claim'},
    'x_originating_ip_disagrees_with_chain': {'severity': 'low', 'trust': 'header_claim'},
    'ptr_helo_mismatch': {'severity': 'medium', 'trust': 'header_claim'},
    # observed — live DNS facts
    'fcrdns_fail': {'severity': 'medium', 'trust': 'observed'},
    'no_ptr_record': {'severity': 'low', 'trust': 'observed'},
    'sender_domain_has_no_mx': {'severity': 'medium', 'trust': 'observed'},
}

_ARTIFACT_KEYS = (
    'sender', 'subject', 'recipients', 'date', 'sending_server',
    'reverse_dns', 'reply_to', 'return_path', 'message_id',
)


def collect_flags(artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten per-artifact flags into one list with severity and trust."""
    collected: List[Dict[str, Any]] = []
    seen = set()
    for key in _ARTIFACT_KEYS:
        artifact = artifacts.get(key) or {}
        for code in artifact.get('flags', []) or []:
            if (key, code) in seen:
                continue
            seen.add((key, code))
            meta = FLAG_METADATA.get(code, {})
            collected.append({
                'code': code,
                'scope': key,
                'severity': meta.get('severity', 'info'),
                'trust': meta.get('trust', 'header_claim'),
            })
    return collected
