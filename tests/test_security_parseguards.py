"""
Regression tests for the six parse-guard bypasses found by the second audit.

These were the claims whose verification agents died on a session limit, so
each one was reproduced and fixed by hand. The timings in the comments are the
audit's own measurements against the code before these fixes.
"""
import io
import time

import pytest

from app import create_app
from app.config import TestingConfig
from app.services.email_parser import EmailParserService
from app.utils.validators import (
    OLE_MAGIC,
    validate_email_file,
    validate_header_block,
    validate_mime_headers,
    validate_mime_structure,
)

HEADER_LIMITS = dict(max_block_bytes=256 * 1024, max_line_bytes=16 * 1024, max_headers=500)


@pytest.fixture(scope='module')
def client():
    app = create_app(TestingConfig)
    with app.test_client() as c:
        # Warm the first-request import cost so timing assertions are honest.
        c.post('/api/analyze',
               data={'emailfile': (io.BytesIO(
                   b'From: a@b.com\r\nTo: c@d.com\r\nSubject: t\r\n'
                   b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nhi'), 'w.eml')},
               content_type='multipart/form-data')
        yield c


def _upload(client, payload, name='x.eml'):
    started = time.monotonic()
    response = client.post(
        '/api/analyze',
        data={'emailfile': (io.BytesIO(payload), name)},
        content_type='multipart/form-data',
    )
    return response, time.monotonic() - started


def _subpart_header_flood(params: int) -> bytes:
    return (
        b'From: a@b.com\r\nTo: c@d.com\r\nSubject: x\r\n'
        b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n'
        b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b'--B\r\nContent-Type: text/plain' + (b'; a=b' * params) + b'\r\n\r\nhi\r\n--B--\r\n'
    )


class TestSubPartHeaderFlood:
    """
    CLAIM 1 (critical). validate_header_block stops at the first blank line —
    which is exactly where the top-level headers end — so every nested part's
    headers were unbounded. The audit measured a 1MB .eml with one sub-part
    Content-Type carrying 200,000 parameters at **337 seconds of CPU and 698MB
    RSS**, passing every existing guard in under 5ms.
    """

    @pytest.mark.parametrize('params', [20_000, 200_000])
    def test_subpart_header_flood_is_rejected(self, client, params):
        response, elapsed = _upload(client, _subpart_header_flood(params))
        assert response.status_code == 400, response.status_code
        assert elapsed < 5, f'took {elapsed:.1f}s — the guard is not short-circuiting'

    def test_guard_catches_it_directly(self):
        ok, message = validate_mime_headers(_subpart_header_flood(200_000))
        assert not ok
        assert 'MIME part header' in message

    def test_folded_subpart_header_is_measured_unfolded(self):
        """A long value split across continuation lines must still be caught."""
        folded = b'Content-Type: text/plain' + b''.join(
            b';\r\n a=b' + b'c' * 500 for _ in range(60))
        payload = (
            b'From: a@b.com\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n'
            b'--B\r\n' + folded + b'\r\n\r\nhi\r\n--B--\r\n'
        )
        ok, _ = validate_mime_headers(payload)
        assert not ok

    def test_ordinary_multipart_passes(self):
        payload = (
            b'From: a@b.com\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n'
            b'--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n'
            b'--B\r\nContent-Type: application/pdf\r\n'
            b'Content-Disposition: attachment; filename="a.pdf"\r\n\r\nJVBE\r\n--B--\r\n'
        )
        ok, message = validate_mime_headers(payload)
        assert ok, message


class TestRealEmailsAreAccepted:
    """
    CLAIM 2 (high). MAX_FORM_MEMORY_SIZE was set to 64KB in the belief that it
    limited non-file form fields. Werkzeug applies it to the raw multipart
    decoder buffer, so it rejected every real line-structured email over
    roughly 100KB with a 413 reading "exceeds the 50MB limit" — the product's
    main function, broken by a security setting.

    An earlier check missed this because it used one unbroken line, which does
    not fill the decoder buffer the same way.
    """

    @staticmethod
    def _line_structured(kilobytes: int) -> bytes:
        header = (b'From: a@b.com\r\nTo: c@d.com\r\nSubject: t\r\n'
                  b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\n')
        line = b'This is a normal paragraph line of an ordinary business email body.\r\n'
        return header + line * ((kilobytes * 1024) // len(line))

    @pytest.mark.parametrize('kilobytes', [100, 300, 1000, 5000])
    def test_line_structured_email_is_accepted(self, client, kilobytes):
        response, _ = _upload(client, self._line_structured(kilobytes), 'real.eml')
        assert response.status_code == 200, (
            f'{kilobytes}KB real email rejected with {response.status_code}: '
            f'{response.get_data(as_text=True)[:200]}'
        )

    def test_form_memory_size_is_not_below_the_upload_limit(self):
        """The buffer limit must never fire before MAX_CONTENT_LENGTH does."""
        app = create_app(TestingConfig)
        assert app.config['MAX_FORM_MEMORY_SIZE'] >= app.config['MAX_CONTENT_LENGTH']


class TestPartCounterCannotBeDodged:
    """
    CLAIM 3 (high). The counter matched the literal bytes 'Content-Type:' and
    'content-type:'. MIME parts do not require a Content-Type at all, and two
    other spellings slipped past — 20,000 real parts were counted as 1.
    """

    @staticmethod
    def _flood(part: bytes, count: int = 20_000) -> bytes:
        return (
            b'From: a@b.com\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n'
            + part * count + b'--B--\r\n'
        )

    @pytest.mark.parametrize('part', [
        b'--B\r\n\r\nx\r\n',                                # no Content-Type at all
        b'--B\r\nContent-type: text/plain\r\n\r\nx\r\n',    # lowercase 't'
        b'--B\r\nCONTENT-TYPE: text/plain\r\n\r\nx\r\n',    # all caps
        b'--B\r\nContent-Type: text/plain\r\n\r\nx\r\n',    # the control
    ])
    def test_every_spelling_is_counted(self, part):
        ok, message = validate_mime_structure(self._flood(part), max_parts=1000)
        assert not ok, 'part flood counted as within limits'
        assert 'MIME parts' in message

    def test_flood_is_rejected_by_the_api(self, client):
        response, elapsed = _upload(client, self._flood(b'--B\r\n\r\nx\r\n'))
        assert response.status_code == 400
        assert elapsed < 5

    def test_ordinary_multipart_still_accepted(self, client):
        payload = (
            b'From: a@b.com\r\nTo: c@d.com\r\nSubject: t\r\n'
            b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n'
            b'Content-Type: multipart/alternative; boundary="B"\r\n\r\n'
            b'--B\r\nContent-Type: text/plain\r\n\r\nhello\r\n'
            b'--B\r\nContent-Type: text/html\r\n\r\n<b>hello</b>\r\n--B--\r\n'
        )
        response, _ = _upload(client, payload)
        assert response.status_code == 200


class TestMsgHeaderLimits:
    """
    CLAIM 4 (high). A .msg is an OLE container, so the raw-byte guards in the
    API layer do not apply — its RFC 5322 headers live inside a stream. The
    audit built a 0.53MB .msg whose To: header was 256KB and measured 24.6s.
    The parser now runs the same header guard over the extracted header text.
    """

    def test_oversized_msg_header_text_is_rejected_by_the_guard(self):
        header_text = (
            'From: a@b.com\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n'
            'To: ' + ('"a" (c) ' * 32768) + 'a@b.com\r\n'
        )
        encoded = (header_text + '\r\n\r\n').encode('utf-8', 'replace')
        started = time.monotonic()
        ok, _ = validate_header_block(encoded, **HEADER_LIMITS)
        elapsed = time.monotonic() - started
        assert not ok, 'a 256KB To: header inside a .msg passed the guard'
        assert elapsed < 0.5

    def test_parser_discards_oversized_msg_headers(self, monkeypatch):
        """
        The guard must actually take effect, not merely appear in the source.

        An earlier version asserted `'validate_header_block' in
        inspect.getsource(...)`, which stayed green when the call site was
        changed to `if False and not headers_ok:` — disabling the guard
        entirely. This drives a stub .msg through the real _parse_msg and
        asserts on the OUTCOME and the time taken.
        """
        class FakeAttachments(list):
            pass

        class FakeMessage:
            # A 256KB To: header — the payload that cost 24.6 seconds.
            headerText = (
                'From: a@b.com\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n'
                'To: ' + ('"a" (c) ' * 32768) + 'a@b.com\r\n'
            )
            sender = 'a@b.com'
            to = 'victim@example.com'
            cc = ''
            date = 'Mon, 1 Jan 2024 00:00:00 +0000'
            subject = 'hello'
            messageId = '<1@b.com>'
            htmlBody = None
            body = 'hi'
            attachments = FakeAttachments()

        class FakeExtractMsg:
            Message = staticmethod(lambda _stream: FakeMessage())

        parser = EmailParserService()
        parser.extract_msg = FakeExtractMsg

        started = time.monotonic()
        result = parser.parse_email(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 64, 'x.msg')
        elapsed = time.monotonic() - started

        assert elapsed < 5, f'oversized .msg headers took {elapsed:.1f}s — guard not applied'
        assert 'error' not in result
        # The header block was rejected, so nothing was parsed out of it: the
        # recipients fall back to the message property, not the giant To:.
        assert '"a" (c)' not in (result['headers']['recipients'] or '')


class TestOleMagicConsistency:
    """
    CLAIM 5 (low). is_probably_msg tested 4 bytes of OLE magic while
    validate_email_file tested 8, so a file starting D0 CF 11 E0 + anything,
    named .eml, was routed down the MSG path — skipping both raw-byte guards —
    while the validator judged it an EML.
    """

    def test_both_checks_use_the_same_signature(self):
        assert EmailParserService.OLE_MAGIC == OLE_MAGIC
        assert len(OLE_MAGIC) == 8

    def test_partial_magic_named_eml_does_not_skip_the_guards(self):
        payload = b'\xD0\xCF\x11\xE0ZZZZ' + b'subject: hi\r\n' + b'A' * 100
        # Not a real OLE file, so it must be handled as the EML it claims to be
        # — which means the raw-byte guards apply to it.
        assert EmailParserService.is_probably_msg(payload, 'x.eml') is False

    def test_genuine_ole_is_still_recognised(self):
        payload = OLE_MAGIC + b'\x00' * 200
        assert EmailParserService.is_probably_msg(payload, 'x.msg') is True
        assert EmailParserService.is_probably_msg(payload, 'x.eml') is True
        ok, message = validate_email_file(payload, 'x.eml')
        assert not ok and 'OLE' in message


class TestNestedCommentHeaders:
    """
    CLAIM 6 (info). Claimed RecursionError inside email._header_value_parser.
    Does not reproduce: at every depth the header guard permits, parsing
    completes in milliseconds. Kept as a regression test because a
    RecursionError here would be caught by _safe_get anyway (it derives from
    Exception), but a hang or crash would not.
    """

    @pytest.mark.parametrize('depth', [200, 3900, 7900])
    def test_nested_comments_do_not_hang_or_crash(self, client, depth):
        value = b'(' * depth + b')' * depth
        payload = (
            b'From: a@b.com\r\nTo: ' + value + b' <a@b.com>\r\n'
            b'Subject: t\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nbody'
        )
        response, elapsed = _upload(client, payload)
        assert response.status_code in (200, 400)
        assert elapsed < 5, f'depth {depth} took {elapsed:.1f}s'

    def test_deep_nesting_is_refused_by_the_line_cap(self):
        value = b'(' * 50_000 + b')' * 50_000
        payload = b'From: a@b.com\r\nTo: ' + value + b'\r\n\r\nbody'
        ok, _ = validate_header_block(payload, **HEADER_LIMITS)
        assert not ok


class TestGuardCostIsBounded:
    """The guards must not themselves become the denial of service."""

    def test_guards_are_fast_on_a_large_legitimate_email(self):
        chunk = b'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\r\n' * ((20 * 1024 * 1024) // (37 * 10))
        body = b''.join(
            b'--X\r\nContent-Type: application/pdf\r\n'
            b'Content-Transfer-Encoding: base64\r\n'
            b'Content-Disposition: attachment; filename="d%d.pdf"\r\n\r\n' % i + chunk
            for i in range(10)
        )
        payload = (
            b'From: a@b.com\r\nTo: c@d.com\r\nSubject: t\r\nDate: x\r\n'
            b'Content-Type: multipart/mixed; boundary="X"\r\n\r\n' + body + b'--X--\r\n'
        )

        started = time.monotonic()
        for guard in (
            lambda: validate_header_block(payload, **HEADER_LIMITS),
            lambda: validate_mime_structure(payload, max_parts=1000),
            lambda: validate_mime_headers(payload),
        ):
            ok, message = guard()
            assert ok, message
        elapsed = time.monotonic() - started
        assert elapsed < 3, f'guards cost {elapsed:.2f}s on a {len(payload)/1024/1024:.0f}MB email'
