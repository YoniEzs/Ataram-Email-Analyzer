"""Advisory SPF re-evaluation.

This is **not** an authentication result. The receiving MTA evaluated SPF
against the real SMTP peer and envelope sender; neither survives into an
uploaded file. What this service does is take the IP the ``Received`` chain
*claims* the message came from, and the ``Return-Path`` it *claims* was the
envelope sender, and ask what SPF would say about that pair right now.

Both inputs are attacker-controlled. Forging a hop that names a legitimate
provider's IP manufactures a ``pass``; omitting hops manufactures ``none``. The
result is therefore display-only: it is never merged into the authentication
block and never contributes to the risk score. It exists so an analyst can see
what the claimed route implies, not so the tool can judge it.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.utils.extractors import email_domain
from app.utils.validators import validate_domain, validate_public_ip

logger = logging.getLogger(__name__)

DISCLAIMER = (
    'Advisory only. The client IP and MAIL FROM are taken from headers inside '
    'an uploaded file and can be forged. This is not the SPF result of the '
    'original SMTP transaction and does not affect the risk score.'
)

VALID_RESULTS = frozenset({
    'pass', 'fail', 'softfail', 'neutral', 'none', 'permerror', 'temperror',
})

try:
    import spf as _spf

    # pyspf picks its resolver at import time, preferring dnspython when it is
    # importable and otherwise falling back to py3dns. Pin it explicitly so the
    # backend never depends on import order, and so we never touch py3dns
    # (which probes the system resolver at import).
    if hasattr(_spf, 'DNSLookup_dnspython'):
        _spf.DNSLookup = _spf.DNSLookup_dnspython
    SPF_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when pyspf is absent
    _spf = None
    SPF_AVAILABLE = False


class SPFAdvisorService:
    """Re-evaluates SPF against header-claimed inputs, for display only."""

    def __init__(self, timeout: int = 8) -> None:
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return SPF_AVAILABLE

    def evaluate(
        self,
        *,
        ip: Optional[str],
        mail_from: Optional[str],
        helo: Optional[str],
        mail_from_source: str = 'return_path_header',
        ip_source: str = 'received_header_chain',
    ) -> Optional[Dict[str, Any]]:
        if not SPF_AVAILABLE:
            return None
        if not ip or not validate_public_ip(ip):
            return None

        sender = (mail_from or '').strip().lower()
        domain = email_domain(sender) if sender else ''
        # pyspf requires a non-empty HELO; the sender domain is the standard
        # substitute when the Received chain records no name.
        helo_name = (helo or '').strip().lower() or domain
        if not validate_domain(domain) and not validate_domain(helo_name):
            return None

        try:
            result, explanation = _spf.check2(
                i=ip,
                s=sender,
                h=helo_name,
                timeout=self.timeout,
                querytime=self.timeout,
            )
        except Exception as exc:
            logger.warning('[SPFAdvisorService] evaluation failed for %s: %s', ip, exc)
            return None

        result = str(result).lower()
        if result not in VALID_RESULTS:
            result = 'permerror'

        return {
            'available': True,
            'result': result,
            'explanation': str(explanation) if explanation else None,
            'evaluated_ip': ip,
            'evaluated_mail_from': sender or None,
            'evaluated_helo': helo_name or None,
            'mail_from_source': mail_from_source,
            'ip_source': ip_source,
            'trusted': False,
            'advisory': True,
            'affects_risk_score': False,
            'source': 'advisory_spf_reevaluation',
            'library': 'pyspf',
            'evaluated_at': datetime.now(timezone.utc).isoformat(),
            'disclaimer': DISCLAIMER,
        }
