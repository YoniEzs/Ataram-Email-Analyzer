"""
Email Parser Service
Handles parsing of EML and MSG files

SECURITY NOTE — why the caps in this file exist and where they must sit.

Every byte here is attacker-chosen. Python's `email` package under
`policy.default` parses header values LAZILY and super-linearly: the cost is
paid when a value is first read, not when the message is parsed. Measured
against this code, one crafted `To:` header in a 1.5MB file costs ~237s of CPU,
and a 1MB file of encoded-word `Received:` headers costs ~24s. With four sync
gunicorn workers and a 120s timeout, that is a complete outage from a file 3%
of the allowed upload size.

Consequently:
  - the raw header block is bounded by validate_header_block() BEFORE this
    service is constructed (see app/api/analysis.py);
  - caps here are applied DURING traversal, never afterwards. Slicing a list
    that has already been built is too late — building it was the expensive part.
"""

import io
import os
import logging
import mimetypes
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header


# Defaults used when no limits mapping is supplied. The API passes app config.
DEFAULT_PARSER_LIMITS = {
    'MAX_MIME_PARTS': 1000,
    'MAX_ANALYZED_ATTACHMENTS': 100,
    'MAX_ANALYZED_HOPS': 100,
    'MAX_HOP_CHARS': 4096,
    'MAX_ANALYZED_BODY_CHARS': 2 * 1024 * 1024,
    'MAX_ANALYZED_HTML_CHARS': 1024 * 1024,
}

# Longest single header value kept. Applied after the raw-bytes guard as a
# second line of defence for callers that construct the service directly.
MAX_HEADER_VALUE_CHARS = 16 * 1024


def _transfer_encoding(value) -> str:
    """
    The bare Content-Transfer-Encoding mechanism.

    RFC 5322 permits comments and trailing semicolons here, so `base64`,
    `base64;` and `base64 (encoded)` are all the same mechanism to a decoder
    but only the first matched an equality test.
    """
    if not value:
        return ''
    text = str(value)
    # Strip comments before splitting: `(...)` may contain a semicolon.
    text = re.sub(r'\([^)]*\)', ' ', text)
    return text.split(';')[0].strip().lower()


def attachment_extension(filename: str) -> str:
    """
    Derive the extension an operating system will actually act on.

    `os.path.splitext(name.lower())[1].lstrip('.')` looks obvious and is wrong
    in two ways that both hand an attacker a clean score:

      * `payload.exe.` -> splitext gives ('payload.exe', '.') -> lstrip('.')
        yields '' -> no extension -> no match against any deny-list. Windows
        strips trailing dots during path normalisation, so the saved file is a
        live `payload.exe`.
      * truncating the name to 255 characters BEFORE taking the extension
        removes the extension entirely from a long name.

    So: strip trailing dots, whitespace and unicode format characters first,
    and read the extension from the untruncated name.
    """
    if not filename:
        return ''
    # U+200B..U+200F and U+202A..U+202E are the zero-width and bidi-override
    # characters used to disguise an extension in a display name.
    cleaned = ''.join(
        ch for ch in str(filename)
        if not ('​' <= ch <= '‏' or '‪' <= ch <= '‮')
    )
    cleaned = cleaned.rstrip(' .\t\r\n ')
    if '.' not in cleaned:
        return ''
    return cleaned.rsplit('.', 1)[1].lower()[:32]


class EmailParserService:
    """Service for parsing email files"""

    def __init__(self, limits: Optional[Dict[str, Any]] = None):
        self.extract_msg = self._import_extract_msg()
        self.limits = {**DEFAULT_PARSER_LIMITS, **(limits or {})}

    def _limit(self, name: str) -> int:
        return int(self.limits.get(name, DEFAULT_PARSER_LIMITS[name]))

    @staticmethod
    def _import_extract_msg():
        """Lazy import of extract_msg"""
        try:
            import extract_msg
            return extract_msg
        except ImportError:
            return None

    @staticmethod
    def decode_header(val: Any) -> str:
        """Decode email header value, bounded."""
        if not val:
            return ""
        try:
            text = str(val)
        except Exception:
            return ""
        if len(text) > MAX_HEADER_VALUE_CHARS:
            text = text[:MAX_HEADER_VALUE_CHARS]
        try:
            return str(make_header(decode_header(text)))
        except Exception:
            return text

    # Full 8-byte OLE compound-file signature. Must match validators.OLE_MAGIC:
    # testing 4 bytes here while validate_email_file tested 8 meant a file
    # beginning D0 CF 11 E0 followed by anything, named .eml, was routed down
    # the MSG path (skipping both raw-byte guards) while the validator judged
    # it an EML.
    OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

    @staticmethod
    def is_probably_msg(file_bytes: bytes, filename: str) -> bool:
        """Determine if file is MSG format"""
        if filename.lower().endswith(".msg"):
            return True
        return file_bytes.startswith(EmailParserService.OLE_MAGIC)

    def parse_email(self, data: bytes, filename: str) -> Dict[str, Any]:
        """
        Parse email file and extract headers, body, and attachments

        Args:
            data: Raw file bytes
            filename: Original filename

        Returns:
            Dictionary containing parsed email data
        """
        try:
            is_msg = self.is_probably_msg(data, filename)

            if is_msg:
                return self._parse_msg(data)
            else:
                return self._parse_eml(data)

        except Exception as e:
            # The exception text can carry library internals and file content;
            # it used to be returned verbatim to anonymous callers.
            logger.warning(f"[EmailParserService] Parse failed: {type(e).__name__}: {e}")
            return {
                'error': 'The file could not be parsed as an email message.',
                'headers': {},
                'body_text': '',
                'body_html': '',
                'attachments': []
            }

    def _safe_get(self, msg, name: str) -> str:
        """Read a single header defensively."""
        try:
            return self.decode_header(msg.get(name, ""))
        except Exception as e:
            logger.debug(f"[EmailParserService] Header {name} unreadable: {type(e).__name__}: {e}")
            return ""

    def _parse_eml(self, data: bytes) -> Dict[str, Any]:
        """Parse EML format email"""
        msg = BytesParser(policy=policy.default).parsebytes(data)

        max_hops = self._limit('MAX_ANALYZED_HOPS')
        max_hop_chars = self._limit('MAX_HOP_CHARS')

        # True counts, recorded before truncation. Without these the analyzer
        # could only see the truncated list, so `hops_truncated` was always
        # False and a 300-hop email was reported as having 100 hops with no
        # indication anything had been dropped.
        header_counts: Dict[str, int] = {}

        def multi(name: str, limit: int, per_item_chars: int) -> List[str]:
            """
            Read a repeated header, bounded.

            The bound on `limit` cannot prevent the cost of get_all() itself —
            that is what validate_header_block() is for — but it does stop the
            decoded copies, the JSON serialisation and the response size from
            scaling with a hostile header count.
            """
            try:
                values = msg.get_all(name, []) or []
            except Exception as e:
                logger.debug(f"[EmailParserService] {name} unreadable: {type(e).__name__}: {e}")
                header_counts[name] = 0
                return []
            header_counts[name] = len(values)
            return [self.decode_header(v)[:per_item_chars] for v in values[:limit]]

        headers = {
            "sender": self._safe_get(msg, "From"),
            "recipients": ", ".join(
                x for x in [self._safe_get(msg, "To"), self._safe_get(msg, "Cc")] if x
            ),
            "reply_to": self._safe_get(msg, "Reply-To"),
            "date": self._safe_get(msg, "Date"),
            "subject": self._safe_get(msg, "Subject"),
            "auth_results": " | ".join(multi("Authentication-Results", 20, 4096)),
            "hops": multi("Received", max_hops, max_hop_chars),
            "dkim_signature": self._safe_get(msg, "DKIM-Signature"),
            "return_path": self._safe_get(msg, "Return-Path"),
            "message_id": self._safe_get(msg, "Message-ID"),
        }

        # One traversal for both bodies and attachments. Two separate walks
        # doubled the cost of a part flood for no benefit.
        body_parts, attachments = self._walk_parts(msg)

        return {
            'headers': headers,
            'body_text': "\n".join(body_parts['plain']),
            'body_html': "\n".join(body_parts['html']),
            'attachments': attachments,
            # True count before truncation, so the analyzer can report honestly.
            'total_hop_count': header_counts.get('Received', len(headers['hops'])),
            # `msg_object` is deliberately NOT returned: nothing downstream read
            # it, and it pinned the entire parsed tree — every part's payload —
            # in memory for the life of the request.
        }

    def _parse_msg(self, data: bytes) -> Dict[str, Any]:
        """Parse MSG format email (Outlook)"""
        if self.extract_msg is None:
            return {
                'error': 'MSG support is not available on this server.'
            }

        with io.BytesIO(data) as bio:
            bio.name = "upload.msg"
            m = self.extract_msg.Message(bio)

            # extract-msg exposes `headerText` as the raw string. `header` is an
            # email.message.Message and `transportHeaders` does not exist —
            # feeding either to parsestr() raised TypeError, which made every
            # single .msg upload fail.
            raw_hdr = getattr(m, 'headerText', None) or ""
            if not isinstance(raw_hdr, str):
                raw_hdr = str(raw_hdr)

            # A .msg is an OLE container, so the raw-bytes guards in the API
            # layer do not apply to it — the RFC 5322 headers live inside a
            # stream, not at the front of the file. Apply the SAME limits here,
            # to the extracted header text, before any structured parse.
            #
            # Truncating to the block size alone was not enough: a single 256KB
            # `To:` header inside a 0.53MB .msg still cost 24.5 seconds, because
            # the expense is per-header, not per-block.
            from app.utils.validators import validate_header_block

            raw_hdr = raw_hdr[:int(self.limits.get('MAX_HEADER_BLOCK_BYTES', 256 * 1024))]
            encoded = (raw_hdr + '\r\n\r\n').encode('utf-8', 'replace')
            headers_ok, _ = validate_header_block(
                encoded,
                max_block_bytes=int(self.limits.get('MAX_HEADER_BLOCK_BYTES', 256 * 1024)),
                max_line_bytes=int(self.limits.get('MAX_HEADER_LINE_BYTES', 16 * 1024)),
                max_headers=int(self.limits.get('MAX_HEADER_COUNT', 500)),
            )
            if not headers_ok:
                logger.warning('[EmailParserService] MSG headers exceeded limits; ignoring them')
                raw_hdr = ""

            from email.parser import Parser
            try:
                hdr_msg = Parser(policy=policy.default).parsestr(raw_hdr) if raw_hdr else None
            except Exception as e:
                logger.debug(f"[EmailParserService] MSG header parse failed: {type(e).__name__}: {e}")
                hdr_msg = None

            def pick(name: str, fallback: str = "") -> str:
                if hdr_msg is not None:
                    try:
                        value = hdr_msg.get(name)
                    except Exception:
                        value = None
                    if value:
                        return self.decode_header(value)
                return fallback

            def as_text(value) -> str:
                """extract-msg returns Optional[str] for these, not a list."""
                if not value:
                    return ""
                if isinstance(value, (list, tuple)):
                    return ", ".join(str(v) for v in value)
                if isinstance(value, bytes):
                    return value.decode('utf-8', 'replace')
                return str(value)

            def as_body(value) -> str:
                """htmlBody comes back as Optional[bytes]."""
                if not value:
                    return ""
                if isinstance(value, bytes):
                    return value.decode('utf-8', 'replace')
                return str(value)

            recipients = ", ".join(
                part for part in [as_text(getattr(m, 'to', '')), as_text(getattr(m, 'cc', ''))] if part
            )

            max_hops = self._limit('MAX_ANALYZED_HOPS')
            max_hop_chars = self._limit('MAX_HOP_CHARS')
            try:
                raw_hops = (hdr_msg.get_all("Received") if hdr_msg else []) or []
            except Exception:
                raw_hops = []

            headers = {
                "sender": pick("From", as_text(getattr(m, 'sender', ''))),
                "recipients": pick("To", recipients),
                "reply_to": pick("Reply-To", ""),
                "date": pick("Date", as_text(getattr(m, 'date', ''))),
                "subject": pick("Subject", as_text(getattr(m, 'subject', ''))),
                "auth_results": pick("Authentication-Results", ""),
                "hops": [self.decode_header(x)[:max_hop_chars] for x in raw_hops[:max_hops]],
                "dkim_signature": pick("DKIM-Signature", ""),
                "return_path": pick("Return-Path", ""),
                # The attribute is `messageId`; `message_id` does not exist and
                # raised AttributeError as an eagerly-evaluated fallback.
                "message_id": pick("Message-ID", as_text(getattr(m, 'messageId', ''))),
            }

            body_html = as_body(getattr(m, 'htmlBody', None))[:self._limit('MAX_ANALYZED_HTML_CHARS')]
            body_text = as_body(getattr(m, 'body', None))[:self._limit('MAX_ANALYZED_BODY_CHARS')] if not body_html else ""

            return {
                'headers': headers,
                'body_text': body_text,
                'body_html': body_html,
                'attachments': self._extract_attachments_msg(m)
            }

    @staticmethod
    def _part_text(part, remaining: int) -> str:
        """
        Decode one text part, truncated to the remaining budget.

        Deliberately avoids `part.get_content()`. Under policy.default that
        routes through raw_data_manager, which internally re-derives
        get_content_type(), get_content_maintype() and get_param('charset') —
        and EmailPolicy.header_fetch_parse has no cache, so each of those
        re-parses the raw header from scratch. Profiling showed ~8.5 header
        parses per part, which multiplied the cost of an inflated Content-Type
        by the same factor. get_payload(decode=True) returns the bytes without
        consulting the header at all.
        """
        try:
            raw = part.get_payload(decode=True)
        except Exception as e:
            logger.debug(f"[EmailParserService] Failed to decode part: {type(e).__name__}: {e}")
            return ""

        if raw is None:
            return ""
        if isinstance(raw, str):
            return raw[:remaining]
        if not isinstance(raw, (bytes, bytearray)):
            return ""

        # Truncate BEFORE decoding: a multi-megabyte part that will be cut to
        # the budget anyway should not be decoded in full first. The slack
        # allows for multi-byte sequences straddling the cut.
        clipped = bytes(raw[:remaining * 4 + 8])
        charset = None
        try:
            charset = part.get_content_charset()
        except Exception:
            charset = None
        try:
            text = clipped.decode(charset or 'utf-8', 'replace')
        except (LookupError, TypeError):
            text = clipped.decode('utf-8', 'replace')
        return text[:remaining]

    # Magic numbers identifying what an attachment ACTUALLY is, regardless of
    # the name and Content-Type it was given. Only the first few bytes are
    # decoded, so this costs nothing next to decoding the whole payload.
    CONTENT_SIGNATURES = (
        (b'MZ', 'pe_executable'),
        (b'\x7fELF', 'elf_executable'),
        (b'\xca\xfe\xba\xbe', 'macho_executable'),
        (b'\xfe\xed\xfa\xce', 'macho_executable'),
        (b'\xfe\xed\xfa\xcf', 'macho_executable'),
        (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'ole_document'),
        (b'PK\x03\x04', 'zip_container'),
        (b'Rar!\x1a\x07', 'rar_archive'),
        (b'7z\xbc\xaf\x27\x1c', '7z_archive'),
        (b'\x1f\x8b', 'gzip_archive'),
        (b'L\x00\x00\x00\x01\x14\x02\x00', 'windows_shortcut'),
        (b'#!', 'script_shebang'),
    )

    # What each detected type is plausibly named. A mismatch means the file is
    # disguised, which is a stronger signal than either fact alone.
    SIGNATURE_EXPECTED_EXTENSIONS = {
        'pe_executable': {'exe', 'dll', 'scr', 'sys', 'com', 'msi', 'cpl', 'ocx', 'efi'},
        'elf_executable': {'so', 'elf', 'bin', 'run', 'o'},
        'macho_executable': {'dylib', 'bundle', 'app', 'o'},
        'ole_document': {'doc', 'xls', 'ppt', 'msg', 'msi', 'db', 'vsd'},
        'zip_container': {'zip', 'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'jar',
                          'apk', 'epub', 'vsdx', 'xpi', 'crx', 'appx', 'msix', 'whl'},
        'rar_archive': {'rar'},
        '7z_archive': {'7z'},
        'gzip_archive': {'gz', 'tgz', 'tar'},
        'windows_shortcut': {'lnk'},
        'script_shebang': {'sh', 'bash', 'py', 'pl', 'rb', 'run', 'txt'},
    }

    def _sniff_part(self, part, declared_extension: str) -> Optional[str]:
        """
        Identify an attachment from its leading bytes and report a disguise.

        The extension lists can only describe what a file is *called*. An
        `.exe` renamed `holiday.jpg`, or a `.docm` inside something named
        `report.pdf`, passes every name-based check — so the content is checked
        too, using a bounded prefix rather than the whole payload.
        """
        try:
            raw = part.get_payload(decode=False)
            if not isinstance(raw, str) or not raw:
                return None
            # Slice immediately. Everything below only needs the first few
            # dozen characters, and carrying a 23MB string through this
            # function to read 64 of them is pure waste.
            raw = raw[:512]
            # Take the bare mechanism token. An exact `== 'base64'` match was
            # defeated by `Content-Transfer-Encoding: base64;` or a trailing
            # RFC 5322 comment — both legal, both parsed as base64 by the
            # decoder, and both enough to make sniffing read the still-encoded
            # text and find no signature.
            encoding = _transfer_encoding(part.get('Content-Transfer-Encoding', ''))
            if encoding == 'base64':
                import base64
                # 64 base64 chars decode to 48 bytes — far more than any
                # signature needs, and a fixed cost regardless of file size.
                prefix = base64.b64decode(
                    ''.join(raw.split())[:64] + '==', validate=False)
            else:
                prefix = raw[:48].encode('latin-1', 'ignore')
        except Exception:
            return None

        return self._sniff_bytes(prefix, declared_extension)

    def _sniff_bytes(self, prefix: bytes, declared_extension: str) -> Optional[str]:
        """Match decoded leading bytes against the signature table."""
        # Signatures that are dangerous on their own, whatever the file is
        # called. Without this, an attachment with NO extension at all —
        # `filename="invoice"` — matched a PE signature and was cleared,
        # because the mismatch test requires a declared extension to disagree
        # with. No extension is not agreement.
        always_report = {
            'pe_executable', 'elf_executable', 'macho_executable',
            'windows_shortcut', 'script_shebang',
        }

        for signature, kind in self.CONTENT_SIGNATURES:
            if prefix.startswith(signature):
                expected = self.SIGNATURE_EXPECTED_EXTENSIONS.get(kind, set())
                if not declared_extension:
                    return kind if kind in always_report else None
                if declared_extension not in expected:
                    return kind
                return None
        return None

    @staticmethod
    def _estimate_part_size(part) -> int:
        """
        Estimate an attachment's decoded size WITHOUT decoding it.

        `get_payload(decode=True)` allocates the entire attachment just to call
        len() on it. For a part flood that is hundreds of megabytes of pure
        waste, per request, per worker.
        """
        try:
            raw = part.get_payload(decode=False)
        except Exception:
            return 0
        if not isinstance(raw, str):
            return 0
        if _transfer_encoding(part.get('Content-Transfer-Encoding', '')) == 'base64':
            # 4 base64 characters encode 3 bytes; whitespace inflates this
            # slightly, which is acceptable for a reported size.
            return len(raw) * 3 // 4
        return len(raw)

    def _walk_parts(self, msg):
        """
        Traverse the MIME tree once, collecting bodies and attachments together.

        Every cap is enforced inside the loop. The traversal itself is what a
        part flood attacks, so it stops at MAX_MIME_PARTS regardless of how
        much of the message is left.
        """
        parts: Dict[str, List[str]] = {"plain": [], "html": []}
        attachments: List[Dict[str, Any]] = []

        max_parts = self._limit('MAX_MIME_PARTS')
        max_attachments = self._limit('MAX_ANALYZED_ATTACHMENTS')
        text_budget = self._limit('MAX_ANALYZED_BODY_CHARS')
        html_budget = self._limit('MAX_ANALYZED_HTML_CHARS')

        if not msg.is_multipart():
            ctype = msg.get_content_type()
            if ctype in ("text/plain", "text/html"):
                # This used to be unguarded, so an unknown charset on a
                # single-part message aborted the whole analysis.
                try:
                    content = msg.get_content()
                except Exception as e:
                    logger.debug(f"[EmailParserService] Failed to decode body: {type(e).__name__}: {e}")
                    content = ""
                if content:
                    key = "plain" if ctype == "text/plain" else "html"
                    budget = text_budget if key == "plain" else html_budget
                    parts[key].append(content[:budget])
            return parts, attachments

        seen_parts = 0
        # Running totals rather than re-summing the list each iteration: with a
        # part flood the re-sum is itself quadratic.
        text_used = 0
        html_used = 0
        for part in msg.walk():
            seen_parts += 1
            if seen_parts > max_parts:
                logger.info("[EmailParserService] MIME part cap reached; traversal stopped")
                break

            try:
                filename = part.get_filename()
            except Exception:
                filename = None

            # A part is treated as an attachment whenever it carries a filename,
            # whatever its disposition says — including `inline`, and including
            # a bare `name=` parameter on Content-Type with no disposition at all
            # (get_filename() reads both).
            #
            # Requiring `Content-Disposition: attachment` meant an .exe sent as
            # `inline` was skipped entirely: never named, never sniffed, never
            # scored. Mail clients save both, and `inline` is what a payload uses
            # precisely to look unremarkable.
            if filename and not part.is_multipart():
                if len(attachments) >= max_attachments:
                    continue
                filename = str(filename)
                try:
                    content_type = part.get_content_type() or ''
                except Exception:
                    content_type = ''
                extension = attachment_extension(filename)
                attachments.append({
                    'filename': filename[:255],
                    'content_type': content_type,
                    'extension': extension,
                    'size': self._estimate_part_size(part),
                    # None unless the leading bytes contradict the name.
                    'content_mismatch': self._sniff_part(part, extension),
                })
                continue

            try:
                ctype = part.get_content_type()
            except Exception:
                continue

            if ctype == "text/plain" and text_budget > 0:
                remaining = text_budget - text_used
                if remaining <= 0:
                    continue
                chunk = self._part_text(part, remaining)
                if chunk:
                    parts["plain"].append(chunk)
                    text_used += len(chunk)
            elif ctype == "text/html" and html_budget > 0:
                remaining = html_budget - html_used
                if remaining <= 0:
                    continue
                chunk = self._part_text(part, remaining)
                if chunk:
                    parts["html"].append(chunk)
                    html_used += len(chunk)

        return parts, attachments

    def _extract_attachments_msg(self, m) -> List[Dict[str, Any]]:
        """Extract attachments from MSG message"""
        attachments: List[Dict[str, Any]] = []
        max_attachments = self._limit('MAX_ANALYZED_ATTACHMENTS')

        for a in (getattr(m, 'attachments', None) or []):
            if len(attachments) >= max_attachments:
                break
            try:
                fname = str(a.longFilename or a.shortFilename or "")
                kind = a.mimetype or mimetypes.guess_type(fname)[0] or ""
                # `a.data` materialises the whole attachment. Prefer a declared
                # size when the library exposes one.
                size = getattr(a, 'size', None)
                if not isinstance(size, int):
                    data_b = a.data or b""
                    size = len(data_b) if isinstance(data_b, (bytes, bytearray)) else 0

                extension = attachment_extension(fname)
                # .msg attachments were the one path with no content sniffing,
                # so a disguised payload delivered in an Outlook file was
                # judged on its name alone.
                mismatch = None
                try:
                    data_prefix = a.data
                    if isinstance(data_prefix, (bytes, bytearray)) and data_prefix:
                        mismatch = self._sniff_bytes(bytes(data_prefix[:48]), extension)
                except Exception:
                    mismatch = None

                attachments.append({
                    'filename': fname[:255],
                    'content_type': kind,
                    'extension': extension,
                    'size': size,
                    'content_mismatch': mismatch,
                })
            except Exception as e:
                logger.warning(f"[EmailParserService] Failed to extract MSG attachment: {type(e).__name__}")

        return attachments
