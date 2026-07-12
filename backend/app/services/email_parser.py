"""
Email Parser Service
Handles parsing of EML and MSG files
"""

import logging
import mimetypes
import os
import re
from datetime import datetime
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from typing import Dict, Any, List

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
        """Decode email header value"""
        if not val:
            return ""
        try:
            return str(make_header(decode_header(val)))
        except Exception:
            return val

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
            else:
                return self._parse_eml(data)

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
        }

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
        }

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
