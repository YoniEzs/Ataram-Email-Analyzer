"""
Validation utilities
"""

import os
import re
from typing import Tuple

from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = {'eml', 'msg'}

MAX_FILENAME_LENGTH = 255
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024
MIN_FILE_SIZE = 10

# OLE compound-file magic — the container format .msg files use.
OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

# Characters that have no business in an uploaded filename. A NUL truncates the
# name in any C-level path API; separators and traversal sequences are what turn
# a filename into a path.
_FORBIDDEN_FILENAME_RE = re.compile(r'[\x00-\x1f\x7f/\\]')


def allowed_file(filename: str) -> bool:
    """
    Check that the filename is well-formed and carries an allowed extension.

    Rejects control characters, NUL bytes, path separators and traversal
    sequences before looking at the extension, so a name like
    "..\\..\\evil.exe\x00.eml" cannot pass by virtue of its tail.
    """
    if not filename or not isinstance(filename, str):
        return False
    if len(filename) > MAX_FILENAME_LENGTH:
        return False
    if _FORBIDDEN_FILENAME_RE.search(filename):
        return False
    if '..' in filename:
        return False
    if '.' not in filename:
        return False

    stem, _, extension = filename.rpartition('.')
    # A name that is nothing but an extension (".eml") has no basename; treat it
    # as malformed rather than letting it through on the strength of its suffix.
    if not stem.strip():
        return False

    return extension.lower() in ALLOWED_EXTENSIONS


def safe_display_filename(filename: str) -> str:
    """
    Reduce an uploaded filename to something safe to echo back and log.

    `secure_filename` strips directory components and every non-ASCII
    character. For a name written in Hebrew, Arabic or Chinese that removes the
    stem entirely — 'דואר.eml' comes back as 'eml', losing the dot along with
    it. Downstream code re-derives the extension from this string, so the
    extension has to be preserved explicitly or every non-Latin filename is
    rejected as "not an .eml".
    """
    original = filename or ''
    extension = ''
    if '.' in original:
        candidate = original.rsplit('.', 1)[1].lower()
        if candidate in ALLOWED_EXTENSIONS:
            extension = candidate

    cleaned = secure_filename(original)

    if not cleaned:
        stem = 'upload'
    else:
        stem = cleaned.rsplit('.', 1)[0] if '.' in cleaned else cleaned
        # secure_filename can reduce the stem to nothing while leaving the
        # extension behind (it drops the leading dot as well).
        if not stem or stem == extension:
            stem = 'upload'

    if not extension:
        extension = 'eml'

    return f'{stem[:MAX_FILENAME_LENGTH - len(extension) - 1]}.{extension}'


def validate_header_block(
    file_data: bytes,
    max_block_bytes: int = 256 * 1024,
    max_line_bytes: int = 16 * 1024,
    max_headers: int = 500,
) -> Tuple[bool, str]:
    """
    Bound the RFC 5322 header block before the email parser is allowed near it.

    This is the single most important guard in the upload path, and it has to
    operate on raw bytes. Python's email package parses header values lazily
    under `policy.default`, and that parsing is super-linear in the number of
    tokens a value contains — reading one crafted `To:` header costs minutes of
    CPU. Any limit expressed as "keep the first N headers" is useless, because
    the cost is paid by the access that produces the list, not by the list.

    Checks, in order of how cheaply they fail:
      - the header block must end within `max_block_bytes`
      - no single unfolded header may exceed `max_line_bytes`
      - the block must contain no more than `max_headers` headers

    Returns (is_valid, error_message).
    """
    # The header block ends at the first blank line. Search only as far as the
    # limit allows, so a file with no blank line at all is rejected cheaply
    # instead of being scanned to its end.
    window = file_data[:max_block_bytes + 2]
    for terminator in (b'\r\n\r\n', b'\n\n'):
        index = window.find(terminator)
        if index != -1:
            block = file_data[:index]
            break
    else:
        return False, 'Email headers are missing or exceed the maximum size'

    if len(block) > max_block_bytes:
        return False, 'Email headers exceed the maximum size'

    # Unfold: a header continues onto the next line when that line starts with
    # whitespace. Count logical headers and measure each unfolded length.
    header_count = 0
    current_length = 0
    for raw_line in block.split(b'\n'):
        line = raw_line.rstrip(b'\r')
        if line[:1] in (b' ', b'\t'):
            current_length += len(line)
        else:
            if current_length > max_line_bytes:
                return False, 'A single email header exceeds the maximum size'
            current_length = len(line)
            header_count += 1
            if header_count > max_headers:
                return False, 'Email contains too many headers'

    if current_length > max_line_bytes:
        return False, 'A single email header exceeds the maximum size'

    return True, ''


# Header names whose values Python parses structurally (and therefore
# super-linearly) on every access. These are the ones an attacker inflates.
_MIME_HEADER_RE = re.compile(
    rb'(?im)^(content-type|content-disposition|content-transfer-encoding|content-id)[ \t]*:'
)

# Boundary parameter of a multipart Content-Type, searched over the WHOLE file
# — nested multiparts declare their own, and only counting the top-level one
# left the entire flood uncounted.
# Also matches the RFC 2231 spellings the parser resolves — `boundary*=`,
# `boundary*0=`, `boundary*0*=` — with an optional charset'language' prefix.
# This is a secondary check only; the primary counter above needs no boundary.
_BOUNDARY_RE = re.compile(
    rb'(?i)boundary(?:\*\d*)?\*?[ \t]*=[ \t]*"?'
    rb"(?:[a-z0-9\-]{0,20}'[a-z\-]{0,10}')?([^\";\r\n]{1,200})"
)

# A legitimate message declares a handful of boundaries (one per nesting
# level). Thousands of declarations is itself the attack.
MAX_DECLARED_BOUNDARIES = 64


def _header_end(data: bytes, start: int, cap: int) -> int:
    """
    Offset just past the logical header beginning at `start`, following
    continuation lines and giving up once `cap` bytes have been consumed so the
    scan stays O(cap).
    """
    position = start
    size = len(data)
    while position < size:
        newline = data.find(b'\n', position)
        if newline == -1:
            return min(size, start + cap + 1)
        if newline - start > cap:
            return start + cap + 1
        # A following line that starts with whitespace continues this header.
        nxt = newline + 1
        if nxt < size and data[nxt:nxt + 1] in (b' ', b'\t'):
            position = nxt
            continue
        return newline
    return min(size, start + cap + 1)


def validate_mime_headers(
    file_data: bytes,
    max_line_bytes: int = 2048,
    max_headers: int = 5000,
    max_total_bytes: int = 64 * 1024,
    max_params: int = 64,
) -> Tuple[bool, str]:
    """
    Bound the headers of every MIME SUB-PART, not just the top-level block.

    `validate_header_block` stops at the first blank line, which is where the
    top-level headers end — every nested part's headers sit after it and were
    completely unbounded. Measured against this code before this guard: a 1MB
    .eml whose single sub-part carried `Content-Type: text/plain` followed by
    200,000 `; a=b` parameters cost **337 seconds of CPU and 698MB of RSS**,
    passing both existing guards in under 5ms. Ten of those per minute — what
    nginx already permits from one address — is roughly 3,400 worker-seconds
    of demand against the 240 that four workers provide.

    The cost is incurred by `part.get_content_type()` / `get_filename()` /
    `get('Content-Disposition')` during the MIME walk, so the check has to
    happen before the walk, on raw bytes.

    Only the structurally-parsed Content-* headers are scanned, which keeps
    this a handful of C-level regex matches rather than a full line split.

    THREE budgets are needed, not one. A per-header cap alone is not enough:
    1000 parts each carrying a Content-Type just under a 16KB per-header limit
    passed every guard in 20ms and then cost **652 seconds of CPU** in the
    parser, returning HTTP 200. Each header is individually "small"; the sum is
    what kills the worker. So the aggregate is bounded too, and the per-header
    cap is set where a real Content-Type actually lives (a legitimate one is
    well under 1KB) rather than at the RFC 5322 line limit.
    """
    if not file_data:
        return True, ''

    count = 0
    total = 0
    for match in _MIME_HEADER_RE.finditer(file_data):
        count += 1
        if count > max_headers:
            return False, 'Email contains too many MIME headers'

        end = _header_end(file_data, match.start(), max_line_bytes)
        length = end - match.start()
        if length > max_line_bytes:
            return False, 'A MIME part header exceeds the maximum size'

        # Bytes are the wrong unit. Python's Content-Type parser is
        # super-linear in the number of PARAMETER TOKENS, and the cost per byte
        # depends sharply on token shape: at an identical 16KB per header, a
        # `; a=b` filler cost 8.8s while a run of bare `;;` cost 133s — because
        # the same byte budget holds 2.5x more tokens. Cap the tokens directly.
        segment = file_data[match.start():end]
        if segment.count(b';') > max_params or segment.count(b'=') > max_params:
            return False, 'A MIME part header declares too many parameters'

        total += length
        if total > max_total_bytes:
            return False, 'Email MIME headers exceed the total size limit'

    return True, ''


def validate_mime_structure(file_data: bytes, max_parts: int = 1000) -> Tuple[bool, str]:
    """
    Reject a MIME part flood before the message tree is built.

    Capping the traversal is not sufficient on its own: `BytesParser` has to
    construct the whole tree before any walk begins, and that construction is
    where most of the cost of a 20,000-part message is paid. This counts a
    cheap proxy for the part count directly in the raw bytes.

    `bytes.count` is a C-level scan, so this stays in the low milliseconds even
    on a 50MB upload.

    Returns (is_valid, error_message).
    """
    if not file_data:
        return True, ''

    # Count delimiters for EVERY boundary declared anywhere in the file.
    #
    # Two earlier versions of this were each bypassed:
    #
    # 1. Counting `Content-Type:` failed because a MIME part needs no
    #    Content-Type at all (`--B\r\n\r\n` is a complete, legal, empty part),
    #    and the match was case-sensitive. 20,000 parts counted as 1.
    #
    # 2. Reading only the FIRST `boundary=` token in the top-level header block
    #    failed twice over. `Subject: boundary=DECOY` placed above the real
    #    Content-Type made the guard count `--DECOY` (once) and pass. And even
    #    with no decoy, a nested `multipart/mixed` sub-part declares its own
    #    boundary, which the top-level scan never saw — 762,601 inner parts in
    #    a 24MB file cost 142s of CPU and 882MB of RSS, returning HTTP 200.
    #
    # So: find every declaration, count every delimiter, sum them, and never
    # early-return past the Content-* fallback. MAX_MIME_PARTS in _walk_parts
    # stops the traversal but not the tree construction, which is where the
    # cost actually is — which is why this has to happen on raw bytes.
    # PRIMARY CHECK — independent of how the boundary is spelled.
    #
    # Knowing the boundary has now failed three times: counting `Content-Type:`
    # (a part needs none), reading only the first `boundary=` token (decoys and
    # nested multiparts), and matching the literal `boundary=` form (RFC 2231
    # gives `boundary*=utf-8''SEP` and `boundary*0=`/`boundary*1=`, all of which
    # Python's parser honours through collapse_rfc2231_value and the regex does
    # not see). That last one let a 24MB file build 2.8 million parts: 193
    # seconds and 907MB of RSS, returning HTTP 200.
    #
    # Every MIME part, whatever its boundary is called, is introduced by a line
    # beginning with `--`. Counting those needs no agreement with the parser
    # about spelling at all. Measured: 0.02s over 24MB, and a legitimate 20MB
    # base64-attachment email yields 2 hits against a cap of 1000.
    if file_data.count(b'\n--') > max_parts + 2:
        return False, 'Email contains too many MIME parts'

    seen_boundaries = set()
    total_parts = 0

    for match in _BOUNDARY_RE.finditer(file_data):
        boundary = match.group(1).strip()
        if not boundary or boundary in seen_boundaries:
            continue
        seen_boundaries.add(boundary)
        if len(seen_boundaries) > MAX_DECLARED_BOUNDARIES:
            return False, 'Email declares too many MIME boundaries'
        # bytes.count is a C-level scan and is the cheap path.
        total_parts += file_data.count(b'--' + boundary)
        if total_parts > max_parts + 2:  # +2 for the opening and closing delimiters
            return False, 'Email contains too many MIME parts'

    # Always also count the structurally-parsed headers — a message whose
    # declared boundary does not match what the body actually uses would
    # otherwise slip through the loop above entirely.
    part_markers = 0
    for _ in _MIME_HEADER_RE.finditer(file_data):
        part_markers += 1
        if part_markers > max_parts * 2:
            return False, 'Email contains too many MIME parts'

    return True, ''


def validate_email_file(
    file_data: bytes,
    filename: str,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
) -> Tuple[bool, str]:
    """
    Validate email file content

    Args:
        file_data: File content as bytes
        filename: Original filename
        max_size: Maximum accepted size in bytes

    Returns:
        (is_valid, error_message)
    """
    # Check if file is empty
    if not file_data:
        return False, "File is empty"

    # Check minimum size (at least a few bytes)
    if len(file_data) < MIN_FILE_SIZE:
        return False, "File is too small to be a valid email"

    if len(file_data) > max_size:
        return False, f"File exceeds maximum size of {max_size // (1024 * 1024)}MB"

    # Basic format validation
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

    if ext not in ALLOWED_EXTENSIONS:
        return False, "Only .eml and .msg files are supported"

    # Content must match the claimed extension. This is not a malware check —
    # it stops the parser being handed a format it was not chosen for, and
    # rejects a .msg payload wearing an .eml name (and the reverse).
    if ext == 'eml':
        if file_data.startswith(OLE_MAGIC):
            return False, "File is an OLE/MSG document but is named .eml"
        # EML files should contain email headers
        content = file_data[:4096].decode('utf-8', errors='ignore')
        required_indicators = ['from:', 'to:', 'subject:', 'date:', 'received:', 'message-id:']
        if not any(indicator in content.lower() for indicator in required_indicators):
            return False, "File does not appear to be a valid EML file"

    elif ext == 'msg':
        # Full 8-byte signature, matching EmailParserService.is_probably_msg.
        # Accepting a 4-byte prefix here while the router required 8 (or the
        # reverse) left a gap where a file satisfied one and not the other.
        if not file_data.startswith(OLE_MAGIC):
            return False, "File does not appear to be a valid MSG file"

    return True, ""
