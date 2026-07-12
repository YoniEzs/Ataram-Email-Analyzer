"""Regression tests for the python-oxmsg MSG adapter."""

from datetime import datetime, timezone

from app.services.email_parser import EmailParserService

OLE_MAGIC = b'\xD0\xCF\x11\xE0' + b'\x00' * 128


class FakeRecipient:
    def __init__(self, email_address='', name=''):
        self.email_address = email_address
        self.name = name


class FakeAttachment:
    attached_by_value = True
    file_name = 'invoice.pdf.exe'
    file_bytes = b'MZ' + b'\x00' * 64
    mime_type = 'application/octet-stream'
    size = len(file_bytes)


class FakeMessage:
    message_headers = {
        'From': 'Sender <sender@example.com>',
        'To': 'victim@company.example, boss@company.example',
        'Message-ID': '<msg-id@example.com>',
    }
    sender = 'Sender <sender@example.com>'
    recipients = (
        FakeRecipient('victim@company.example'),
        FakeRecipient('boss@company.example'),
    )
    sent_date = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    subject = 'Quarterly invoice'
    body = None
    html_body = '<html><body>See attachment</body></html>'
    attachments = (FakeAttachment(),)
    attachment_count = 1

    @classmethod
    def load(cls, data):
        assert data.startswith(b'\xD0\xCF\x11\xE0')
        return cls()


def make_parser(message_class=FakeMessage):
    parser = EmailParserService()
    parser.oxmsg_message = message_class
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
    assert 'See attachment' in result['body_text']


def test_msg_parse_extracts_attachments():
    result = make_parser().parse_email(OLE_MAGIC, 'mail.msg')

    assert len(result['attachments']) == 1
    attachment = result['attachments'][0]
    assert attachment['filename'] == 'invoice.pdf.exe'
    assert attachment['extension'] == 'exe'
    assert attachment['size'] == len(FakeAttachment.file_bytes)


def test_msg_without_to_header_uses_recipient_collection():
    class NoToMessage(FakeMessage):
        message_headers = {'From': 'sender@example.com'}
        recipients = (FakeRecipient('victim@company.example'),)

    result = make_parser(NoToMessage).parse_email(OLE_MAGIC, 'mail.msg')
    assert result['headers']['recipients'] == 'victim@company.example'


def test_msg_attachment_limit_is_enforced_before_loading_all_attachments():
    class TooManyMessage(FakeMessage):
        attachment_count = 101

    parser = make_parser(TooManyMessage)
    parser.max_attachments = 100
    result = parser.parse_email(OLE_MAGIC, 'mail.msg')
    assert 'maximum of 100 attachments' in result['error']
