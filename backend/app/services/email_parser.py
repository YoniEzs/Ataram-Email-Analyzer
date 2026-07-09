"""
Email Parser Service
Handles parsing of EML and MSG files
"""

import io
import logging
import mimetypes
import os
from datetime import datetime
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class EmailParserService:
    """Service for parsing email files"""

    def __init__(self):
        self.extract_msg = self._import_extract_msg()

    @staticmethod
    def _import_extract_msg():
        """Lazy import of extract_msg"""
        try:
            import extract_msg
            return extract_msg
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
                    msg = payload[0]
                    break

        def h(name: str) -> str:
            return self.decode_header(msg.get(name, ""))

        # Headers are prepended in transit, so the first Authentication-Results
        # is the one stamped by the final receiving server — the only one that
        # can be trusted. Later ones may be forged by the sender.
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
        body_text = "\n".join(body_parts.get('plain', []))
        body_html = "\n".join(body_parts.get('html', []))

        # Extract attachments
        attachments = self._extract_attachments_eml(msg)

        return {
            'headers': headers,
            'body_text': body_text,
            'body_html': body_html,
            'attachments': attachments,
            'msg_object': msg
        }

    def _parse_msg(self, data: bytes) -> Dict[str, Any]:
        """Parse MSG format email (Outlook)"""
        if self.extract_msg is None:
            return {
                'error': 'extract_msg not installed. Install via: pip install extract_msg olefile'
            }

        with io.BytesIO(data) as bio:
            bio.name = "upload.msg"
            m = self.extract_msg.Message(bio)

            # Try to get raw headers
            raw_hdr = ""
            for cand in ("header", "transportHeaders"):
                if hasattr(m, cand) and getattr(m, cand):
                    raw_hdr = getattr(m, cand)
                    break

            from email.parser import Parser
            hdr_msg = Parser(policy=policy.default).parsestr(raw_hdr) if raw_hdr else None

            def pick(name: str, fallback: str = "") -> str:
                if hdr_msg and hdr_msg.get(name):
                    return self.decode_header(hdr_msg.get(name))
                return fallback

            # extract_msg exposes .to/.cc as display strings and .date as a
            # datetime — normalise everything to plain strings.
            recipients = ", ".join(part for part in (m.to, m.cc) if part)
            date_str = m.date.isoformat() if isinstance(m.date, datetime) else str(m.date or "")

            headers = {
                "sender": pick("From", m.sender or ""),
                "recipients": pick("To", recipients),
                "reply_to": pick("Reply-To", ""),
                "date": pick("Date", date_str),
                "subject": pick("Subject", m.subject or ""),
                "auth_results": pick("Authentication-Results", ""),
                "auth_results_top": pick("Authentication-Results", ""),
                "hops": [self.decode_header(x) for x in ((hdr_msg.get_all("Received") if hdr_msg else []) or [])],
                "dkim_signature": pick("DKIM-Signature", ""),
                "return_path": pick("Return-Path", ""),
                "message_id": pick("Message-ID", getattr(m, "messageId", "") or ""),
            }

            # htmlBody is bytes in extract_msg — decode before analysis.
            body_html = m.htmlBody or ""
            if isinstance(body_html, bytes):
                body_html = body_html.decode('utf-8', errors='replace')
            body_text = (m.body or "") if not body_html else ""

            # Extract attachments
            attachments = self._extract_attachments_msg(m)

            return {
                'headers': headers,
                'body_text': body_text,
                'body_html': body_html,
                'attachments': attachments
            }

    def _get_body_parts(self, msg) -> Dict[str, List[str]]:
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

    def _extract_attachments_eml(self, msg) -> List[Dict[str, Any]]:
        """Extract attachments from EML message"""
        attachments: List[Dict[str, Any]] = []

        for part in msg.walk():
            disp = part.get('Content-Disposition', '') or ''
            if not disp or 'attachment' not in disp.lower():
                continue

            filename = part.get_filename()
            if not filename:
                continue

            content_type = part.get_content_type() or ''
            ext = os.path.splitext(filename.lower())[1].lstrip('.')

            attachments.append({
                'filename': filename,
                'content_type': content_type,
                'extension': ext,
                'size': len(part.get_payload(decode=True) or b'')
            })

        return attachments

    def _extract_attachments_msg(self, m) -> List[Dict[str, Any]]:
        """Extract attachments from MSG message"""
        attachments: List[Dict[str, Any]] = []

        for a in (m.attachments or []):
            try:
                fname = a.longFilename or a.shortFilename or ""
                data_b = a.data or b""
                kind = a.mimetype or mimetypes.guess_type(fname)[0] or ""
                ext = os.path.splitext(fname.lower())[1].lstrip('.')

                attachments.append({
                    'filename': fname,
                    'content_type': kind,
                    'extension': ext,
                    'size': len(data_b)
                })
            except Exception as e:
                logger.warning(f"[EmailParserService] Failed to extract MSG attachment: {e}")

        return attachments
