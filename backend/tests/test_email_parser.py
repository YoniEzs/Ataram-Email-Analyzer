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


# ---------------------------------------------------------------------------
# Export wrappers around a raw message
#
# Found by running a genuine Outlook export through the tool. The file began
# with a UTF-8 BOM and was wrapped in double quotes, and the parser silently
# produced zero headers: every artifact read N/A, and a real phishing message
# carrying five suspicious URLs and zero-width characters in its subject was
# reported as "no strong indicators detected".
# ---------------------------------------------------------------------------

PLAIN_EML = (
    b'Received: from relay.example.com (relay [93.184.216.34])\r\n'
    b' by mx.company.example with ESMTPS; Mon, 09 Mar 2026 09:00:01 +0000\r\n'
    b'From: Sender <sender@example.com>\r\n'
    b'To: recipient@example.com\r\n'
    b'Subject: Quarterly report\r\n'
    b'Date: Mon, 09 Mar 2026 09:00:00 +0000\r\n'
    b'Message-ID: <plain@example.com>\r\n'
    b'\r\n'
    b'Body text\r\n'
)


def parse_raw(raw):
    return EmailParserService().parse_email(raw, 'Message.eml')


def test_utf8_bom_does_not_swallow_the_headers():
    """A BOM prepends bytes to the first header name.

    Python then cannot find the header block, reports
    MissingHeaderBodySeparatorDefect, and treats the whole file as a body.
    """
    result = parse_raw(b'\xef\xbb\xbf' + PLAIN_EML)

    assert not result.get('error')
    assert result['headers']['sender'] == 'Sender <sender@example.com>'
    assert result['headers']['subject'] == 'Quarterly report'


def test_message_wrapped_in_double_quotes_keeps_its_first_hop():
    """A quoted export corrupts the first Received header into '"Received'.

    That hop is the outermost one, nearest the receiving MTA, so losing it
    costs the most trustworthy entry in the chain.
    """
    result = parse_raw(b'"' + PLAIN_EML + b'"')

    assert not result.get('error')
    assert result['headers']['sender'] == 'Sender <sender@example.com>'
    # Without the fix the quote makes the header name '"Received', the parser
    # drops it, and the chain is empty.
    assert len(result['headers']['hops']) == 1


def test_bom_and_quotes_together():
    """Exactly the shape of the file that exposed this."""
    result = parse_raw(b'\xef\xbb\xbf"' + PLAIN_EML + b'"')

    assert not result.get('error')
    assert result['headers']['sender'] == 'Sender <sender@example.com>'
    assert result['headers']['subject'] == 'Quarterly report'


def test_utf16_export_is_decoded_not_just_stripped():
    """UTF-16 needs decoding: every character is two bytes, not just the BOM."""
    result = parse_raw(PLAIN_EML.decode('ascii').encode('utf-16'))

    assert not result.get('error')
    assert result['headers']['sender'] == 'Sender <sender@example.com>'


def test_a_message_with_no_headers_is_an_error_not_a_low_risk_verdict():
    """The failure mode this whole section exists to prevent.

    Returning a parsed-looking result for a file that was never parsed means
    the report says "no strong indicators detected" about content it never
    read. An unreadable file must fail loudly.
    """
    result = parse_raw(b'this file has no header block at all\r\n\r\njust text\r\n')

    assert result.get('error')
    assert 'header' in result['error'].lower()


def test_normal_message_is_unaffected_by_normalisation():
    result = parse_raw(PLAIN_EML)

    assert not result.get('error')
    assert result['headers']['sender'] == 'Sender <sender@example.com>'
    assert result['body_text'].strip() == 'Body text'
