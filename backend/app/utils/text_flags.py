"""Unicode control-character sets shared by the filename and header checks.

Two different sets are exposed on purpose:

``BIDI_CONTROL_CHARS``
    Everything, including LRM/RLM. Used for *filenames*, where U+202E makes
    "annexe_<RLO>fdp.exe" display as "annexe_exe.pdf" and where legitimate
    names essentially never contain any of these.

``BIDI_OVERRIDE_CHARS``
    Embedding/override/isolate characters only, with LRM and RLM deliberately
    excluded. Used for *subject lines*. LRM/RLM are routine in legitimate
    Hebrew and Arabic mail — this project's own Hebrew UI strings contain them
    — so flagging them in a subject would fire on ordinary correspondence.
"""

from typing import FrozenSet, List

# LRM, RLM
_DIRECTIONAL_MARKS = '‎‏'
# LRE, RLE, PDF, LRO, RLO
_EMBEDDING_OVERRIDES = '‪‫‬‭‮'
# LRI, RLI, FSI, PDI
_ISOLATES = '⁦⁧⁨⁩'

BIDI_OVERRIDE_CHARS: FrozenSet[str] = frozenset(_EMBEDDING_OVERRIDES + _ISOLATES)
BIDI_CONTROL_CHARS: FrozenSet[str] = frozenset(
    _DIRECTIONAL_MARKS + _EMBEDDING_OVERRIDES + _ISOLATES
)

# ZWSP, ZWNJ, ZWJ, word joiner, BOM/ZWNBSP
ZERO_WIDTH_CHARS: FrozenSet[str] = frozenset(
    '​‌‍⁠﻿'
)


def find_chars(text: str, charset: FrozenSet[str]) -> List[str]:
    """Return the sorted ``U+XXXX`` names of ``charset`` members in ``text``."""
    if not text:
        return []
    found = {ch for ch in text if ch in charset}
    return sorted(f'U+{ord(ch):04X}' for ch in found)
