"""
YARA Scanner Service
Compiles rules from YARA_RULES_PATH and scans bodies and attachments.

yara-python is an optional dependency: when it (or the rules directory)
is missing, the scanner reports itself unavailable and analysis proceeds
with the heuristic checks only.
"""

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

_RULE_EXTENSIONS = ('.yar', '.yara')
_SCAN_TIMEOUT_SECONDS = 10

# Mirrors the severity ladder in email_analyzer._calculate_risk_score.
_VALID_SEVERITIES = frozenset({'low', 'medium', 'high', 'critical'})
# A rule that declares nothing gets a middling weight, never the top one.
_DEFAULT_SEVERITY = 'medium'


class YaraScanner:
    """Compile-once YARA rule scanner."""

    def __init__(self, rules_path: Optional[str], max_scan_bytes: int = 8 * 1024 * 1024):
        self.rules = None
        self.available = False
        self.max_scan_bytes = max_scan_bytes

        if not YARA_AVAILABLE or not rules_path:
            return

        rule_files = self._find_rule_files(rules_path)
        if not rule_files:
            return

        try:
            self.rules = yara.compile(filepaths={
                os.path.basename(path): path for path in rule_files
            })
            self.available = True
            logger.info(f"[YaraScanner] Compiled {len(rule_files)} rule file(s) from {rules_path}")
        except Exception as e:
            logger.warning(f"[YaraScanner] Failed to compile rules from {rules_path}: {e}")

    @staticmethod
    def _find_rule_files(rules_path: str) -> List[str]:
        if not os.path.isdir(rules_path):
            return []
        return [
            os.path.join(rules_path, name)
            for name in sorted(os.listdir(rules_path))
            if name.lower().endswith(_RULE_EXTENSIONS)
        ]

    def scan(self, data: bytes) -> List[str]:
        """Scan bytes, returning matching rule names (empty when unavailable).

        Kept returning plain names because the names are what reaches the API
        response and the UI. Callers that need to weigh a match use
        ``scan_detailed``.
        """
        return [match['rule'] for match in self.scan_detailed(data)]

    def scan_detailed(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan bytes, returning each match as ``{'rule', 'severity', 'meta'}``.

        A rule may declare its own weight in ``meta.severity``; the starter
        rules already do. Without this, every match looks identical to the
        caller and a rule pack has no way to say "this is worth noting" rather
        than "this is malware". Unrecognised or absent values fall back to
        ``_DEFAULT_SEVERITY`` rather than to the most severe reading — a rule
        that forgot to declare should not be able to force a critical verdict.
        """
        if not self.available or not data or self.rules is None:
            return []
        try:
            matches = self.rules.match(
                data=data[:self.max_scan_bytes],
                timeout=_SCAN_TIMEOUT_SECONDS,
            )
        except Exception as e:
            logger.warning(f"[YaraScanner] Scan failed: {e}")
            return []

        detailed: List[Dict[str, Any]] = []
        for match in matches:
            meta = dict(getattr(match, 'meta', {}) or {})
            declared = str(meta.get('severity', '')).strip().lower()
            if declared not in _VALID_SEVERITIES:
                if declared:
                    logger.warning(
                        "[YaraScanner] Rule %s declares unknown severity %r; "
                        "treating as %s",
                        match.rule, meta.get('severity'), _DEFAULT_SEVERITY,
                    )
                declared = _DEFAULT_SEVERITY
            detailed.append(
                {'rule': match.rule, 'severity': declared, 'meta': meta}
            )
        return detailed


# Rules are compiled once per path and reused across requests
_scanners: dict[tuple[str, int], YaraScanner] = {}


def get_scanner(
    rules_path: Optional[str],
    max_scan_bytes: int = 8 * 1024 * 1024,
) -> YaraScanner:
    key = (rules_path or '', max_scan_bytes)
    if key not in _scanners:
        _scanners[key] = YaraScanner(rules_path, max_scan_bytes=max_scan_bytes)
    return _scanners[key]
