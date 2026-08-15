"""Independent email-authentication verification.

An uploaded EML/MSG is not a trusted SMTP transaction. ``Received``,
``Return-Path`` and ``Authentication-Results`` can all be fabricated, so SPF
and DMARC cannot be re-created reliably from the file alone. This service only
scores evidence that can be verified from the raw message: DKIM signatures.
Header claims remain visible to the analyst but are never treated as trusted.
"""

import logging
import re
from typing import Any, Dict, Optional

import tldextract

logger = logging.getLogger(__name__)

try:
    import dkim
    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False


_tld_extract = tldextract.TLDExtract(suffix_list_urls=())


def _organizational_domain(domain: Optional[str]) -> Optional[str]:
    if not domain:
        return None
    clean = domain.strip().lower().rstrip('.')
    extracted = _tld_extract(clean)
    return extracted.top_domain_under_public_suffix or clean


class AuthVerifierService:
    """Cryptographic verification of evidence present in a raw message."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return DKIM_AVAILABLE

    def verify(
        self,
        raw_bytes: Optional[bytes],
        from_domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        signing_domain = self._extract_signing_domain(raw_bytes)
        dkim_result = self._verify_dkim(raw_bytes)

        alignment: Optional[str] = None
        if dkim_result == 'pass' and signing_domain and from_domain:
            alignment = (
                'pass'
                if _organizational_domain(signing_domain)
                == _organizational_domain(from_domain)
                else 'fail'
            )

        return {
            'available': self.available,
            'dkim': dkim_result,
            'dkim_signing_domain': signing_domain,
            'dkim_alignment_relaxed': alignment,
            'spf': None,
            'spf_status': 'not_verifiable_from_uploaded_file',
            'dmarc': None,
            'dmarc_status': 'not_fully_verifiable_from_uploaded_file',
            'source': 'independent_dkim_verification',
        }

    @staticmethod
    def _extract_signing_domain(raw_bytes: Optional[bytes]) -> Optional[str]:
        if not raw_bytes:
            return None
        header_block = raw_bytes[:131072].split(b'\r\n\r\n', 1)[0]
        unfolded = re.sub(br'\r?\n[ \t]+', b' ', header_block)
        match = re.search(
            br'(?im)^DKIM-Signature\s*:\s*[^\r\n]*?\bd=([A-Za-z0-9._-]+)',
            unfolded,
        )
        return match.group(1).decode('ascii').lower() if match else None

    def _verify_dkim(self, raw_bytes: Optional[bytes]) -> Optional[str]:
        """Verify a DKIM signature on the raw message.

        Returns ``'pass'``/``'fail'`` only for an actual cryptographic verdict.
        dkimpy already converts a bad or unpublished key into ``False``; the
        exceptions that escape it are transport problems (DNS timeout, no
        resolver, unreachable network). Reporting those as ``'fail'`` scored
        perfectly legitimate signed mail as forged whenever DNS was slow or the
        deployment was offline, so they are reported as ``'error'`` instead and
        never contribute to the risk score.
        """
        if not DKIM_AVAILABLE or not raw_bytes:
            return None
        if b'dkim-signature' not in raw_bytes[:131072].lower():
            return None
        try:
            return (
                'pass'
                if dkim.verify(raw_bytes, timeout=self.timeout)
                else 'fail'
            )
        except Exception as exc:
            logger.warning('[AuthVerifierService] DKIM verification error: %s', exc)
            return 'error'
