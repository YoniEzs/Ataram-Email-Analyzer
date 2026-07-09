"""
Authentication Verifier Service
Independently verifies DKIM signatures and evaluates SPF, instead of
trusting the results claimed in Authentication-Results headers.

Both pyspf and dkimpy are optional — when missing, verification reports
itself unavailable and analysis falls back to header-claimed results.
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import dkim
    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False

try:
    import spf
    SPF_AVAILABLE = True
except ImportError:
    SPF_AVAILABLE = False


class AuthVerifierService:
    """Cryptographic/DNS verification of email authentication."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return DKIM_AVAILABLE or SPF_AVAILABLE

    def verify(
        self,
        raw_bytes: Optional[bytes],
        sender_ip: Optional[str],
        mail_from_domain: Optional[str],
    ) -> Dict[str, Any]:
        """
        Returns:
            {
                'available': bool,
                'dkim': 'pass' | 'fail' | None (not verifiable),
                'spf': SPF result string | None (not verifiable),
            }
        """
        result: Dict[str, Any] = {
            'available': self.available,
            'dkim': self._verify_dkim(raw_bytes),
            'spf': self._check_spf(sender_ip, mail_from_domain),
        }
        return result

    def _verify_dkim(self, raw_bytes: Optional[bytes]) -> Optional[str]:
        """Verify the first DKIM signature on the raw message."""
        if not DKIM_AVAILABLE or not raw_bytes:
            return None
        if b'dkim-signature' not in raw_bytes[:65536].lower():
            return None
        try:
            return 'pass' if dkim.verify(raw_bytes) else 'fail'
        except Exception as e:
            logger.warning(f"[AuthVerifierService] DKIM verification error: {e}")
            return 'fail'

    def _check_spf(
        self, sender_ip: Optional[str], mail_from_domain: Optional[str]
    ) -> Optional[str]:
        """Evaluate the domain's SPF policy against the originating IP."""
        if not SPF_AVAILABLE or not sender_ip or not mail_from_domain:
            return None
        try:
            result, _explanation = spf.check2(
                i=sender_ip,
                s=f'postmaster@{mail_from_domain}',
                h=mail_from_domain,
                timeout=self.timeout,
            )
            return result  # pass/fail/softfail/neutral/none/permerror/temperror
        except Exception as e:
            logger.warning(f"[AuthVerifierService] SPF check error: {e}")
            return None
