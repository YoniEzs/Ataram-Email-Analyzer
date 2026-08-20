"""Structured parsing of ``Received:`` trace headers.

Everything produced here is an *untrusted claim*. A `Received` chain inside an
uploaded file is written by whoever produced the file, so the fields below are
useful for showing an analyst the route a message claims to have taken, and for
finding self-inconsistencies, but never for proving where it came from.

This lives outside ``HeaderForensicsService`` deliberately: that service has a
pinned return shape and its own tests assert exact dict equality.
"""

import ipaddress
import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional

from app.utils.extractors import is_global_ip, iter_ip_candidates

logger = logging.getLogger(__name__)

MAX_HOPS = 100
_MAX_RAW_CHARS = 2000

# Applied after folding, so a value never spans lines by the time we match.
_FROM = re.compile(r'\bfrom\s+([A-Za-z0-9._\-\[\]:]+)?\s*(?:\(([^)]*)\))?', re.I)
_BY = re.compile(r'\bby\s+([A-Za-z0-9._\-]+)', re.I)
_WITH = re.compile(r'\bwith\s+([A-Za-z0-9._\-/]+)', re.I)
_ID = re.compile(r'\bid\s+([A-Za-z0-9._\-@<>]+)', re.I)
_FOR = re.compile(r'\bfor\s+<?([^\s;<>]+@[^\s;<>]+?)>?\s*(?:;|$)', re.I)
_TLS = re.compile(r'\b(?:ESMTPS|ESMTPSA|HTTPS|version=TLS|cipher=)', re.I)
_UNFOLD = re.compile(r'\r?\n[ \t]+')


def _unfold(raw: str) -> str:
    return _UNFOLD.sub(' ', raw or '').strip()


def _parse_timestamp(unfolded: str) -> Optional[datetime]:
    """Parse the date that follows the final ``;`` of a Received header."""
    if ';' not in unfolded:
        return None
    candidate = unfolded.rsplit(';', 1)[1].strip()
    if not candidate:
        return None
    # Some MTAs append a parenthesised comment after the date.
    candidate = re.sub(r'\s*\([^)]*\)\s*$', '', candidate).strip()
    try:
        parsed = parsedate_to_datetime(candidate)
    except (ValueError, TypeError, IndexError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        # A Received header without an offset is malformed; assume UTC so the
        # chain stays comparable, and let the caller treat it as approximate.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _clean_host(value: Optional[str]) -> Optional[str]:
    """Normalise a claimed host name, returning None for bare IP literals.

    ``from [IPv6:2001:db8::1]`` announces an address, not a HELO name, so it
    must not surface as ``from_name`` and be compared against reverse DNS.
    """
    if not value:
        return None
    host = value.strip().strip('[]').rstrip('.').lower()
    if host.startswith('ipv6:'):
        host = host[5:]
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


def parse_received(raw: str) -> Dict[str, Any]:
    """Parse one ``Received:`` header into its component claims."""
    hop: Dict[str, Any] = {
        'raw': (raw or '')[:_MAX_RAW_CHARS],
        'from_name': None,
        'from_comment': None,
        'from_ip': None,
        'by_name': None,
        'with_protocol': None,
        'id': None,
        'for_address': None,
        'timestamp': None,
        'tls': False,
        'is_public_from_ip': False,
        'parse_error': False,
    }
    try:
        unfolded = _unfold(raw)
        if not unfolded:
            return hop

        from_match = _FROM.search(unfolded)
        from_clause = ''
        if from_match:
            hop['from_name'] = _clean_host(from_match.group(1))
            comment = (from_match.group(2) or '').strip()
            hop['from_comment'] = comment or None
            from_clause = from_match.group(0)

        # Prefer an IP inside the "from ... (...)" clause: that is the peer the
        # receiving MTA actually saw. Fall back to the first global IP anywhere.
        for candidate in iter_ip_candidates(from_clause):
            if is_global_ip(candidate):
                hop['from_ip'] = candidate
                break
        if not hop['from_ip']:
            for candidate in iter_ip_candidates(unfolded):
                if is_global_ip(candidate):
                    hop['from_ip'] = candidate
                    break
        hop['is_public_from_ip'] = bool(hop['from_ip'])

        by_match = _BY.search(unfolded)
        if by_match:
            hop['by_name'] = _clean_host(by_match.group(1))

        with_match = _WITH.search(unfolded)
        if with_match:
            hop['with_protocol'] = with_match.group(1).strip()

        id_match = _ID.search(unfolded)
        if id_match:
            hop['id'] = id_match.group(1).strip('<>')[:128]

        for_match = _FOR.search(unfolded)
        if for_match:
            hop['for_address'] = for_match.group(1).strip().lower()[:320]

        hop['tls'] = bool(_TLS.search(unfolded))

        timestamp = _parse_timestamp(unfolded)
        hop['timestamp'] = timestamp.isoformat() if timestamp else None
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug('[received_parser] hop parse failed: %s', exc)
        hop['parse_error'] = True
    return hop


def parse_received_chain(
    hops: Optional[List[str]], *, max_hops: int = MAX_HOPS
) -> List[Dict[str, Any]]:
    """Parse a full chain, newest first (index 0 is the last hop taken)."""
    if not hops:
        return []

    parsed: List[Dict[str, Any]] = []
    for index, raw in enumerate(list(hops)[:max_hops]):
        hop = parse_received(raw if isinstance(raw, str) else str(raw))
        hop['index'] = index
        parsed.append(hop)

    # Transit time between adjacent hops. The chain is newest-first, so hop N
    # happened before hop N-1; a negative delay means the timestamps disagree.
    for index, hop in enumerate(parsed):
        delay = None
        if index + 1 < len(parsed):
            newer = hop.get('timestamp')
            older = parsed[index + 1].get('timestamp')
            if newer and older:
                delay = int(
                    (
                        datetime.fromisoformat(newer) - datetime.fromisoformat(older)
                    ).total_seconds()
                )
        hop['delay_seconds'] = delay
    return parsed


def chain_timestamps(parsed: List[Dict[str, Any]]) -> List[datetime]:
    """Timestamps present in the chain, oldest first."""
    stamps = [
        datetime.fromisoformat(hop['timestamp'])
        for hop in parsed
        if hop.get('timestamp')
    ]
    return sorted(stamps)
