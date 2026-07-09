"""
YARA Scanner Service
Compiles rules from YARA_RULES_PATH and scans bodies and attachments.

yara-python is an optional dependency: when it (or the rules directory)
is missing, the scanner reports itself unavailable and analysis proceeds
with the heuristic checks only.
"""

import logging
import os
from typing import List, Optional

logger = logging.getLogger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

_RULE_EXTENSIONS = ('.yar', '.yara')
_SCAN_TIMEOUT_SECONDS = 10


class YaraScanner:
    """Compile-once YARA rule scanner."""

    def __init__(self, rules_path: Optional[str]):
        self.rules = None
        self.available = False

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
        """Scan bytes, returning matching rule names (empty when unavailable)."""
        if not self.available or not data or self.rules is None:
            return []
        try:
            matches = self.rules.match(data=data, timeout=_SCAN_TIMEOUT_SECONDS)
            return [m.rule for m in matches]
        except Exception as e:
            logger.warning(f"[YaraScanner] Scan failed: {e}")
            return []


# Rules are compiled once per path and reused across requests
_scanners: dict[str, YaraScanner] = {}


def get_scanner(rules_path: Optional[str]) -> YaraScanner:
    key = rules_path or ''
    if key not in _scanners:
        _scanners[key] = YaraScanner(rules_path)
    return _scanners[key]
