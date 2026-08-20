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


def test_oversized_header_is_bounded_in_the_response():
    """A header-bomb file must not inflate the parsed output.

    A 100 KB Subject previously reflected verbatim, producing a ~500 KB
    response. decode_header now caps any single header at MAX_HEADER_CHARS.
    """
    from app.services.email_parser import MAX_HEADER_CHARS, EmailParserService

    raw = (
        b"From: qa@sender.com\r\nTo: v@company.example\r\n"
        b"Subject: " + b"A" * 100_000 + b"\r\n"
        b"Date: Mon, 06 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n"
    )
    parsed = EmailParserService().parse_email(raw, "bomb.eml")
    subject = parsed["headers"]["subject"]
    assert len(subject) <= MAX_HEADER_CHARS + 16
    assert subject.endswith("[truncated]")
