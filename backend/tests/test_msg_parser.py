"""
Regression tests for MSG parsing (extract_msg API contract).

extract_msg exposes .to/.cc as strings, .date as a datetime, .htmlBody as
bytes, and the Message-ID under .messageId — the parser used to assume
lists/str everywhere and crashed on every MSG file.
"""

from datetime import datetime, timezone

from app.services.email_parser import EmailParserService

OLE_MAGIC = b'\xD0\xCF\x11\xE0' + b'\x00' * 128


class FakeAttachment:
    longFilename = 'invoice.pdf.exe'
    shortFilename = 'INVOIC~1.EXE'
    data = b'MZ' + b'\x00' * 64
    mimetype = 'application/octet-stream'


class FakeMessage:
    def __init__(self, bio):
        pass

    header = None
    transportHeaders = None
    sender = 'Sender <sender@example.com>'
    to = 'victim@company.example'
    cc = 'boss@company.example'
    date = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    subject = 'Quarterly invoice'
    body = None
    htmlBody = b'<html><body>See attachment</body></html>'
    messageId = '<msg-id@example.com>'
    attachments = [FakeAttachment()]


class FakeExtractMsgModule:
    Message = FakeMessage


def make_parser():
    parser = EmailParserService()
    parser.extract_msg = FakeExtractMsgModule()
    return parser


def test_msg_parse_succeeds_and_normalizes_types():
    result = make_parser().parse_email(OLE_MAGIC, 'mail.msg')

    assert 'error' not in result
    headers = result['headers']
    assert headers['sender'] == 'Sender <sender@example.com>'
    assert headers['recipients'] == 'victim@company.example, boss@company.example'
    assert headers['message_id'] == '<msg-id@example.com>'
    assert isinstance(headers['date'], str) and headers['date']
    assert isinstance(result['body_html'], str)
    assert 'See attachment' in result['body_html']


def test_msg_parse_extracts_attachments():
    result = make_parser().parse_email(OLE_MAGIC, 'mail.msg')

    assert len(result['attachments']) == 1
    attachment = result['attachments'][0]
    assert attachment['filename'] == 'invoice.pdf.exe'
    assert attachment['extension'] == 'exe'
    assert attachment['size'] == len(FakeAttachment.data)


def test_msg_without_cc_joins_recipients_cleanly():
    class NoCcMessage(FakeMessage):
        cc = None

    parser = make_parser()
    parser.extract_msg = type('M', (), {'Message': NoCcMessage})

    result = parser.parse_email(OLE_MAGIC, 'mail.msg')
    assert result['headers']['recipients'] == 'victim@company.example'
