'''Regression tests for EML parsing.'''

from app.services.email_parser import EmailParserService


def test_unwraps_outlook_message_rfc822_container():
    wrapped_eml = (
        b'MIME-Version: 1.0\r\n'
        b'Content-Type: message/rfc822\r\n'
        b'\r\n'
        b'From: Sender <sender@example.com>\r\n'
        b'To: recipient@example.com\r\n'
        b'Subject: Wrapped message\r\n'
        b'Date: Mon, 09 Mar 2026 09:00:00 +0000\r\n'
        b'Message-ID: <wrapped@example.com>\r\n'
        b'Content-Type: text/plain; charset=utf-8\r\n'
        b'\r\n'
        b'Wrapped body\r\n'
    )

    result = EmailParserService().parse_email(wrapped_eml, 'wrapped.eml')

    assert 'error' not in result
    assert result['headers']['sender'] == 'Sender <sender@example.com>'
    assert result['headers']['subject'] == 'Wrapped message'
    assert result['headers']['message_id'] == '<wrapped@example.com>'
    assert result['body_text'].strip() == 'Wrapped body'


def test_preserves_normal_top_level_message():
    eml = (
        b'From: sender@example.com\r\n'
        b'To: recipient@example.com\r\n'
        b'Subject: Normal message\r\n'
        b'Content-Type: text/plain; charset=utf-8\r\n'
        b'\r\n'
        b'Normal body\r\n'
    )

    result = EmailParserService().parse_email(eml, 'normal.eml')

    assert result['headers']['subject'] == 'Normal message'
    assert result['body_text'].strip() == 'Normal body'
