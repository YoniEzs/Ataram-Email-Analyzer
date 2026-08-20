"""
Email Parser Service
Handles parsing of EML and MSG files
"""

import logging
import mimetypes
import os
import codecs
import re
from datetime import datetime
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


def html_to_text(html: str) -> str:
    """Derive readable plain text from HTML for language analysis."""
    if not html:
        return ""
    if BS4_AVAILABLE:
        try:
            return BeautifulSoup(html, 'html.parser').get_text(separator=' ', strip=True)
        except Exception as e:
            logger.debug(f"[email_parser] HTML-to-text failed: {e}")
    # Crude fallback: strip tags
    return re.sub(r'<[^>]+>', ' ', html)


# Upper bound on parsed address entries per header, so a hostile To: line
# cannot amplify memory before the analyzer's own limits apply.
MAX_ADDRESSES = 200
# Upper bound on any single decoded header value reflected into the
# response. Real MTAs keep headers near 8 KB; a hostile file can carry a
# far larger one (a 100 KB subject bloats the JSON to ~500 KB). Bounding
# here caps every reflected header at once without touching body limits.
MAX_HEADER_CHARS = 16_384

# Headers a receiving MTA writes with the envelope recipient. An address here
# that appears in neither To: nor Cc: is how a Bcc delivery looks from outside.
ENVELOPE_TO_HEADERS = (
    ('Delivered-To', 'delivered_to'),
    ('X-Original-To', 'x_original_to'),
    ('X-Envelope-To', 'x_envelope_to'),
)

_HEADER_BLOCK_LIMIT = 128 * 1024
_UNFOLD_RE = re.compile(rb'\r?\n[ \t]+')


def raw_header_value(data: Optional[bytes], name: str) -> str:
    """Read a header straight from the raw bytes, before RFC2047 decoding.

    ``policy.default`` decodes encoded words on access, which destroys the
    charset information that makes a spoofed subject visible. The raw block is
    the only place that survives.
    """
    if not data:
        return ""
    try:
        block = data[:_HEADER_BLOCK_LIMIT].split(b'\r\n\r\n', 1)[0].split(b'\n\n', 1)[0]
        unfolded = _UNFOLD_RE.sub(b' ', block)
        match = re.search(
            rb'(?im)^' + re.escape(name.encode()) + rb'\s*:\s*([^\r\n]*)', unfolded
        )
        return match.group(1).decode('utf-8', 'replace').strip() if match else ""
    except Exception:
        return ""


class EmailParserService:
    """Service for parsing email files"""

    def __init__(
        self,
        *,
        max_mime_parts: int = 250,
        max_attachments: int = 100,
        max_attachment_bytes: int = 10 * 1024 * 1024,
        max_total_attachment_bytes: int = 20 * 1024 * 1024,
        max_text_chars: int = 2_000_000,
    ):
        self.oxmsg_message = self._import_oxmsg_message()
        self.max_mime_parts = max_mime_parts
        self.max_attachments = max_attachments
        self.max_attachment_bytes = max_attachment_bytes
        self.max_total_attachment_bytes = max_total_attachment_bytes
        self.max_text_chars = max_text_chars

    @staticmethod
    def _import_oxmsg_message():
        """Lazy import of the MIT-licensed python-oxmsg parser."""
        try:
            from oxmsg import Message
            return Message
        except ImportError:
            return None

    @staticmethod
    def decode_header(val: str) -> str:
        """Decode an email header value, bounded to MAX_HEADER_CHARS.

        Every reflected header string flows through here, so the length cap
        applied at this one point protects the subject, recipients, routing
        strings and the rest from a header-bomb file inflating the response.
        """
        if not val:
            return ""
        try:
            decoded = str(make_header(decode_header(val)))
        except Exception:
            decoded = val
        if len(decoded) > MAX_HEADER_CHARS:
            return decoded[:MAX_HEADER_CHARS] + "\u2026[truncated]"
        return decoded

    @staticmethod
    def _normalize_eml_bytes(data: bytes) -> bytes:
        """Strip wrappers that real-world exports add around a raw message.

        Both cases below make Python's parser fail to recognise the very first
        header line. When that happens it reports MissingHeaderBodySeparatorDefect
        and treats the *entire* message as a body, yielding zero headers -- so
        every artifact reads N/A and the message scores as though nothing were
        wrong. Observed on a genuine Outlook export.

        - UTF-8 BOM: prepends bytes to the first header name.
        - Whole message wrapped in double quotes: seen when a message is
          round-tripped through a spreadsheet cell or a quoting export. The
          leading quote corrupts the first Received header, losing the
          outermost hop, which is the one nearest the receiving MTA.

        UTF-16 is decoded rather than stripped: the BOM is not the only
        problem there, every character is two bytes and the parser sees
        interleaved NULs.
        """
        for bom, encoding in (
            (codecs.BOM_UTF32_LE, 'utf-32-le'), (codecs.BOM_UTF32_BE, 'utf-32-be'),
            (codecs.BOM_UTF16_LE, 'utf-16-le'), (codecs.BOM_UTF16_BE, 'utf-16-be'),
        ):
            if data.startswith(bom):
                try:
                    data = data[len(bom):].decode(encoding).encode('utf-8')
                except (UnicodeDecodeError, UnicodeEncodeError):
                    return data
                break
        else:
            if data.startswith(codecs.BOM_UTF8):
                data = data[len(codecs.BOM_UTF8):]

        stripped = data.strip()
        if len(stripped) > 1 and stripped.startswith(b'"') and stripped.endswith(b'"'):
            data = stripped[1:-1]
        return data

    @staticmethod
    def is_probably_msg(file_bytes: bytes, filename: str) -> bool:
        """Determine if file is MSG format"""
        if filename.lower().endswith(".msg"):
            return True
        # OLE magic header: D0 CF 11 E0
        return file_bytes.startswith(b"\xD0\xCF\x11\xE0")

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
            return self._parse_eml(self._normalize_eml_bytes(data))

        except Exception as e:
            return {
                'error': f'Failed to parse email: {str(e)}',
                'headers': {},
                'body_text': '',
                'body_html': '',
                'attachments': []
            }

    def _parse_eml(self, data: bytes) -> Dict[str, Any]:
        """Parse EML format email"""
        msg = BytesParser(policy=policy.default).parsebytes(data)

        # A message with no headers at all was not parsed, it was swallowed:
        # the parser could not find the header block and treated the whole
        # file as a body. Returning that as a normal result is the worst
        # failure this tool has -- every artifact reads N/A, nothing trips,
        # and the report says "no strong indicators detected" about a file it
        # never actually read. Real mail always has headers, so treat none as
        # an error and let the API return 400.
        if not msg.items():
            raise ValueError(
                'No headers found. The file does not look like a raw email '
                'message, or its header block is preceded by unexpected bytes.'
            )

        # Outlook can export an EML whose top-level entity is only a
        # message/rfc822 container. Analyze the enclosed message when the
        # wrapper itself has no useful message headers.
        if not msg.get('From') and not msg.get('Subject'):
            for part in msg.walk():
                if part.get_content_type() != 'message/rfc822':
                    continue
                payload = part.get_payload()
                if isinstance(payload, list) and payload:
                    msg = payload[0]  # type: ignore[assignment]
                    break

        part_count = sum(1 for _ in msg.walk())
        if part_count > self.max_mime_parts:
            raise ValueError(
                f'Email contains {part_count} MIME parts; maximum is '
                f'{self.max_mime_parts}'
            )

        def h(name: str) -> str:
            return self.decode_header(msg.get(name, ""))

        # Authentication-Results is useful context, but an uploaded EML is not
        # a trusted transport channel: every header (including the first one)
        # can be forged. The analyzer therefore exposes these as claims only.
        auth_headers = [self.decode_header(x) for x in (msg.get_all("Authentication-Results", []) or [])]

        def addr_list(name: str) -> List[Dict[str, str]]:
            """Structured addresses for one header.

            getaddresses runs on the *raw* values: decoding first can turn an
            encoded comma inside a display name into an address separator and
            split one recipient into two.
            """
            raw_values = [str(v) for v in (msg.get_all(name, []) or [])]
            entries: List[Dict[str, str]] = []
            for display, addr in getaddresses(raw_values)[:MAX_ADDRESSES]:
                display = self.decode_header(display).strip()
                addr = (addr or "").strip()
                if display or addr:
                    entries.append({"name": display, "address": addr.lower()})
            return entries

        def raw_list(name: str) -> List[str]:
            return [
                self.decode_header(str(v)).strip()
                for v in (msg.get_all(name, []) or [])[:MAX_ADDRESSES]
                if str(v).strip()
            ]

        headers = {
            "sender": h("From"),
            "recipients": ", ".join([x for x in [h("To"), h("Cc")] if x]),
            "reply_to": h("Reply-To"),
            "date": h("Date"),
            "subject": h("Subject"),
            "auth_results": " | ".join(auth_headers),
            "auth_results_top": auth_headers[0] if auth_headers else "",
            "hops": [self.decode_header(x) for x in (msg.get_all("Received", []) or [])],
            "dkim_signature": h("DKIM-Signature"),
            "return_path": h("Return-Path"),
            "message_id": h("Message-ID"),
            # Structured recipients and thread context for artifact extraction.
            "from_addresses": addr_list("From"),
            "to": addr_list("To"),
            "cc": addr_list("Cc"),
            "bcc": addr_list("Bcc"),
            "reply_to_addresses": addr_list("Reply-To"),
            "to_raw": h("To"),
            "cc_raw": h("Cc"),
            "in_reply_to": h("In-Reply-To"),
            "references": h("References"),
            "subject_raw": raw_header_value(data, "Subject") or h("Subject"),
            "received_spf": h("Received-SPF"),
            "x_originating_ip": h("X-Originating-IP"),
            "x_mailer": h("X-Mailer"),
        }
        for header_name, key in ENVELOPE_TO_HEADERS:
            headers[key] = raw_list(header_name)

        # Extract body parts
        body_parts = self._get_body_parts(msg)
        body_text = "\n".join(body_parts.get('plain', []))[:self.max_text_chars]
        body_html = "\n".join(body_parts.get('html', []))[:self.max_text_chars]
        if not body_text.strip() and body_html:
            body_text = html_to_text(body_html)

        # Extract attachments
        attachments = self._extract_attachments_eml(msg)

        return {
            'headers': headers,
            'body_text': body_text,
            'body_html': body_html,
            'attachments': attachments,
            # Raw message bytes for signature verification (DKIM). Internal
            # only — stripped by the analyzer, never serialized to JSON.
            'raw_bytes': data,
        }

    def _parse_msg(self, data: bytes) -> Dict[str, Any]:
        """Parse MSG format email (Outlook)"""
        if self.oxmsg_message is None:
            return {
                'error': 'python-oxmsg not installed. Install via: pip install python-oxmsg'
            }

        m = self.oxmsg_message.load(data)
        normalized_headers = {
            str(name).lower(): self.decode_header(str(value))
            for name, value in (m.message_headers or {}).items()
        }

        def pick(name: str, fallback: str = "") -> str:
            return normalized_headers.get(name.lower()) or fallback

        # python-oxmsg exposes no recipient_type attribute; the To/Cc/Bcc split
        # lives in the MAPI property. Defined locally rather than imported from
        # oxmsg.domain.constants, which is an internal module path.
        _PID_RECIPIENT_TYPE = 0x0C15  # PidTagRecipientType: 1=To 2=Cc 3=Bcc
        msg_recipients: Dict[int, List[Dict[str, str]]] = {1: [], 2: [], 3: []}
        for recipient in (m.recipients or ())[:MAX_ADDRESSES]:
            address = (getattr(recipient, 'email_address', '') or '').strip()
            name = (getattr(recipient, 'name', '') or '').strip()
            if not address and not name:
                continue
            try:
                rtype = recipient.properties.int_prop_value(_PID_RECIPIENT_TYPE)
            except Exception:
                rtype = None
            msg_recipients.setdefault(rtype if rtype in (1, 2, 3) else 1, []).append(
                {'name': name, 'address': address.lower()}
            )

        recipients = ", ".join(
            recipient.email_address or recipient.name
            for recipient in (m.recipients or ())
            if recipient.email_address or recipient.name
        )
        date_value = m.sent_date
        date_str = (
            date_value.isoformat()
            if isinstance(date_value, datetime)
            else str(date_value or "")
        )
        auth_claim = pick("Authentication-Results", "")

        def addr_list_msg(name: str, fallback: List[Dict[str, str]]) -> List[Dict[str, str]]:
            """Prefer the transport headers; fall back to the MAPI table.

            A .msg often carries no transport headers at all (a draft, or an
            item that never left the client), in which case the recipient table
            is the only source — and unlike an EML it records real Bcc entries.
            """
            raw = normalized_headers.get(name.lower(), '')
            if raw:
                return [
                    {'name': display.strip(), 'address': (addr or '').strip().lower()}
                    for display, addr in getaddresses([raw])[:MAX_ADDRESSES]
                    if display.strip() or (addr or '').strip()
                ]
            return fallback

        recipients_source = (
            'transport_headers'
            if normalized_headers.get('to') or normalized_headers.get('cc')
            else 'msg_recipient_table'
        )

        headers = {
            "sender": pick("From", m.sender or ""),
            "recipients": pick("To", recipients),
            "reply_to": pick("Reply-To", ""),
            "date": pick("Date", date_str),
            "subject": pick("Subject", m.subject or ""),
            "auth_results": auth_claim,
            "auth_results_top": auth_claim,
            "hops": [pick("Received")] if pick("Received") else [],
            "dkim_signature": pick("DKIM-Signature", ""),
            "return_path": pick("Return-Path", ""),
            "message_id": pick("Message-ID", ""),
            "from_addresses": addr_list_msg(
                "From",
                [{'name': '', 'address': (m.sender or '').strip().lower()}]
                if (m.sender or '').strip() else [],
            ),
            "to": addr_list_msg("To", msg_recipients[1]),
            "cc": addr_list_msg("Cc", msg_recipients[2]),
            "bcc": addr_list_msg("Bcc", msg_recipients[3]),
            "reply_to_addresses": addr_list_msg("Reply-To", []),
            "to_raw": pick("To", recipients),
            "cc_raw": pick("Cc", ""),
            "in_reply_to": pick("In-Reply-To", ""),
            "references": pick("References", ""),
            "subject_raw": pick("Subject", m.subject or ""),
            "received_spf": pick("Received-SPF", ""),
            "x_originating_ip": pick("X-Originating-IP", ""),
            "x_mailer": pick("X-Mailer", ""),
            "recipients_source": recipients_source,
        }
        for header_name, key in ENVELOPE_TO_HEADERS:
            value = pick(header_name, "")
            headers[key] = [value] if value else []

        body_html = str(m.html_body or "")[:self.max_text_chars]
        body_text = str(m.body or "")[:self.max_text_chars]
        if not body_text.strip() and body_html:
            body_text = html_to_text(body_html)[:self.max_text_chars]

        attachments = self._extract_attachments_msg(m)

        return {
            'headers': headers,
            'body_text': body_text,
            'body_html': body_html,
            'attachments': attachments,
        }

    def _get_body_parts(self, msg: Any) -> Dict[str, List[str]]:
        """Extract text and HTML parts from EML message"""
        parts: Dict[str, List[str]] = {"plain": [], "html": []}

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    try:
                        parts["plain"].append(part.get_content())
                    except Exception as e:
                        logger.debug(f"[EmailParserService] Failed to decode text/plain part: {e}")
                elif ctype == "text/html":
                    try:
                        parts["html"].append(part.get_content())
                    except Exception as e:
                        logger.debug(f"[EmailParserService] Failed to decode text/html part: {e}")
        else:
            ctype = msg.get_content_type()
            if ctype == "text/plain":
                parts["plain"].append(msg.get_content())
            elif ctype == "text/html":
                parts["html"].append(msg.get_content())

        return parts

    def _extract_attachments_eml(self, msg: Any) -> List[Dict[str, Any]]:
        """Extract attachments from EML message"""
        attachments: List[Dict[str, Any]] = []

        total_bytes = 0
        for part in msg.walk():
            disp = part.get('Content-Disposition', '') or ''
            if not disp or 'attachment' not in disp.lower():
                continue

            filename = part.get_filename()
            if not filename:
                continue

            content_type = part.get_content_type() or ''
            ext = os.path.splitext(filename.lower())[1].lstrip('.')
            payload = part.get_payload(decode=True) or b''

            if len(attachments) >= self.max_attachments:
                raise ValueError(
                    f'Email exceeds the maximum of {self.max_attachments} attachments'
                )
            if len(payload) > self.max_attachment_bytes:
                raise ValueError(
                    f'Attachment exceeds the {self.max_attachment_bytes // (1024 * 1024)}MB limit'
                )
            total_bytes += len(payload)
            if total_bytes > self.max_total_attachment_bytes:
                raise ValueError('Combined attachment data exceeds the configured limit')

            attachments.append({
                'filename': filename,
                'content_type': content_type,
                'extension': ext,
                'size': len(payload),
                # Raw bytes for content inspection — internal only, the
                # attachment analyzer strips this before results go to JSON.
                'data': payload,
            })

        return attachments

    def _extract_attachments_msg(self, m: Any) -> List[Dict[str, Any]]:
        """Extract attachments from MSG message"""
        attachments: List[Dict[str, Any]] = []

        if int(m.attachment_count or 0) > self.max_attachments:
            raise ValueError(
                f'Email exceeds the maximum of {self.max_attachments} attachments'
            )

        total_bytes = 0
        for a in (m.attachments or []):
            try:
                if not a.attached_by_value:
                    continue
                fname = a.file_name or "attachment.bin"
                data_b = a.file_bytes or b""
                kind = a.mime_type or mimetypes.guess_type(fname)[0] or ""
                ext = os.path.splitext(fname.lower())[1].lstrip('.')

                if len(attachments) >= self.max_attachments:
                    raise ValueError(
                        f'Email exceeds the maximum of {self.max_attachments} attachments'
                    )
                if len(data_b) > self.max_attachment_bytes:
                    raise ValueError(
                        f'Attachment exceeds the {self.max_attachment_bytes // (1024 * 1024)}MB limit'
                    )
                total_bytes += len(data_b)
                if total_bytes > self.max_total_attachment_bytes:
                    raise ValueError('Combined attachment data exceeds the configured limit')

                attachments.append({
                    'filename': fname,
                    'content_type': kind,
                    'extension': ext,
                    'size': len(data_b),
                    'data': data_b,
                })
            except ValueError:
                raise
            except Exception as e:
                logger.warning(f"[EmailParserService] Failed to extract MSG attachment: {e}")

        return attachments
