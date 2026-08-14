"""
Regression tests for the fourth audit round.

Two of these were CRITICAL and were reproduced end-to-end before the fix: a
15.3MB upload costing 652 seconds of CPU, and a 20MB upload costing 142 seconds
and 882MB of RSS — both returning HTTP 200 after passing every guard in
milliseconds. Both were bypasses of guards added in round three, which is the
reason this file exists: a guard is not correct because it was written to be.
"""
import base64
import io
import time

import pytest

from app import create_app
from app.config import TestingConfig
from app.services.email_parser import EmailParserService
from app.utils.extractors import email_domain, extract_sender_domain
from app.utils.validators import validate_mime_headers, validate_mime_structure


HEAD = (b'From: a@b.com\r\nTo: c@d.com\r\nSubject: x\r\n'
        b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n')


@pytest.fixture(scope='module')
def client():
    app = create_app(TestingConfig)
    with app.test_client() as c:
        c.post('/api/analyze',
               data={'emailfile': (io.BytesIO(HEAD + b'\r\nhi'), 'w.eml')},
               content_type='multipart/form-data')
        yield c


def _upload(client, payload):
    started = time.monotonic()
    response = client.post(
        '/api/analyze',
        data={'emailfile': (io.BytesIO(payload), 'x.eml')},
        content_type='multipart/form-data',
    )
    return response, time.monotonic() - started


class TestAggregateHeaderBudget:
    """
    CRITICAL. validate_mime_headers capped each header individually at 16KB and
    allowed 5000 of them, with nothing bounding the SUM. 1000 parts each
    carrying a Content-Type just under the per-header cap passed all three
    guards in ~20ms and then cost 652 seconds in the parser — HTTP 200.
    """

    @staticmethod
    def _fat_content_type_flood(parts: int) -> bytes:
        fat = b'text/plain' + b';a=b' * 4000  # ~16KB, just under the old cap
        body = b''.join(b'--BB\r\nContent-Type: ' + fat + b'\r\n\r\nx\r\n' for _ in range(parts))
        return HEAD + b'Content-Type: multipart/mixed; boundary=BB\r\n\r\n' + body + b'--BB--\r\n'

    @pytest.mark.parametrize('parts', [100, 1000])
    def test_aggregate_flood_is_rejected(self, client, parts):
        response, elapsed = _upload(client, self._fat_content_type_flood(parts))
        assert response.status_code == 400
        assert elapsed < 5, f'{parts} parts took {elapsed:.1f}s'

    def test_guard_enforces_a_total_budget(self):
        ok, message = validate_mime_headers(self._fat_content_type_flood(1000))
        assert not ok
        assert 'total size' in message or 'maximum size' in message

    def test_per_header_cap_the_api_actually_uses_is_tight(self):
        """
        Asserting the function's DEFAULT proved nothing: the API passed
        MAX_HEADER_LINE_BYTES (16KB) explicitly, silently reinstating the very
        limit the default rejects, and 16 sub-parts at 16KB cost 133s. Assert
        the value the request path really uses.
        """
        app = create_app(TestingConfig)
        assert app.config['MAX_MIME_HEADER_BYTES'] <= 4096
        assert app.config['MAX_MIME_HEADER_TOTAL_BYTES'] <= 128 * 1024
        assert app.config['MAX_MIME_HEADER_PARAMS'] <= 128

    @pytest.mark.parametrize('filler', [b'; a=b', b';;', b';=', b'; '])
    def test_token_inflation_is_rejected_whatever_the_filler(self, client, filler):
        """
        Byte budgets alone were the wrong unit: the parser's cost is
        super-linear in TOKEN count, so the same 16KB of `;;` cost 133s where
        `; a=b` cost 8.8s.
        """
        content_type = b'text/plain' + filler * (16320 // len(filler))
        body = b''.join(
            b'--S\r\nContent-Type: ' + content_type + b'\r\n\r\nx\r\n' for _ in range(16))
        payload = (HEAD + b'MIME-Version: 1.0\r\n'
                   b'Content-Type: multipart/mixed; boundary=S\r\n\r\n' + body + b'--S--\r\n')
        response, elapsed = _upload(client, payload)
        assert response.status_code == 400
        assert elapsed < 5, f'filler {filler!r} took {elapsed:.1f}s'


class TestBoundaryCounting:
    """
    CRITICAL. The counter read the FIRST `boundary=` token anywhere in the
    top-level header block, counted that one delimiter, and returned early.
    """

    @staticmethod
    def _nested_flood(megabytes: int) -> bytes:
        inner = b'--INNER\r\n\r\n' * ((megabytes * 1024 * 1024) // 11)
        return (HEAD + b'Content-Type: multipart/mixed; boundary=OUTER\r\n\r\n'
                b'--OUTER\r\nContent-Type: multipart/mixed; boundary=INNER\r\n\r\n'
                + inner + b'--OUTER--\r\n')

    @staticmethod
    def _decoy_flood(megabytes: int) -> bytes:
        real = b'--REALREAL\r\n\r\n' * ((megabytes * 1024 * 1024) // 14)
        return (b'From: a@b.com\r\nTo: c@d.com\r\n'
                b'Subject: boundary=DECOYDECOY\r\n'
                b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n'
                b'Content-Type: multipart/mixed; boundary="REALREAL"\r\n\r\n'
                + real + b'--REALREAL--\r\n')

    def test_nested_boundary_flood_is_counted(self):
        """Only the top-level boundary was counted; the flood sat on the inner one."""
        ok, message = validate_mime_structure(self._nested_flood(4), max_parts=1000)
        assert not ok
        assert 'MIME parts' in message or 'boundaries' in message

    def test_decoy_boundary_header_does_not_disable_the_guard(self):
        """`Subject: boundary=DECOY` above the real Content-Type hijacked the count."""
        ok, _ = validate_mime_structure(self._decoy_flood(4), max_parts=1000)
        assert not ok

    @pytest.mark.parametrize('builder', ['_nested_flood', '_decoy_flood'])
    def test_floods_rejected_end_to_end_and_quickly(self, client, builder):
        payload = getattr(self, builder)(20)
        response, elapsed = _upload(client, payload)
        assert response.status_code == 400
        assert elapsed < 5, f'{builder} took {elapsed:.1f}s'

    def test_legitimate_nested_multipart_still_accepted(self, client):
        payload = (
            HEAD + b'Content-Type: multipart/mixed; boundary=OUT\r\n\r\n'
            b'--OUT\r\nContent-Type: multipart/alternative; boundary=IN\r\n\r\n'
            b'--IN\r\nContent-Type: text/plain\r\n\r\nhi\r\n'
            b'--IN\r\nContent-Type: text/html\r\n\r\n<b>hi</b>\r\n--IN--\r\n--OUT--\r\n'
        )
        response, _ = _upload(client, payload)
        assert response.status_code == 200


class TestAttachmentDiscovery:
    """
    HIGH. Attachment analysis ran only when Content-Disposition said
    'attachment', so a payload sent `inline`, or with nothing but a `name=`
    parameter on Content-Type, was never named, sniffed or scored.
    """

    @staticmethod
    def _with_disposition(disposition: bytes) -> bytes:
        payload = base64.b64encode(b'MZ\x90\x00\x03' + b'A' * 60)
        return (
            HEAD + b'Content-Type: multipart/mixed; boundary="X"\r\n\r\n--X\r\n'
            b'Content-Type: application/octet-stream; name="p.exe"\r\n'
            b'Content-Transfer-Encoding: base64\r\n' + disposition + b'\r\n'
            + payload + b'\r\n--X--\r\n'
        )

    @pytest.mark.parametrize('disposition', [
        b'Content-Disposition: attachment; filename="p.exe"\r\n',
        b'Content-Disposition: inline; filename="p.exe"\r\n',
        b'',  # no disposition at all, name= on Content-Type only
    ])
    def test_payload_is_found_whatever_the_disposition(self, disposition):
        parsed = EmailParserService().parse_email(self._with_disposition(disposition), 'x.eml')
        assert len(parsed['attachments']) == 1
        assert parsed['attachments'][0]['extension'] == 'exe'

    def test_inline_image_is_recorded_but_not_suspicious(self):
        """Counting inline parts must not turn ordinary HTML mail into a finding."""
        from app.services.attachment_analyzer import AttachmentAnalyzerService

        png = base64.b64encode(b'\x89PNG\r\n\x1a\n' + b'A' * 60)
        payload = (
            HEAD + b'Content-Type: multipart/related; boundary="R"\r\n\r\n'
            b'--R\r\nContent-Type: text/html\r\n\r\n<html><img src="cid:logo"></html>\r\n'
            b'--R\r\nContent-Type: image/png; name="logo.png"\r\n'
            b'Content-Transfer-Encoding: base64\r\n'
            b'Content-Disposition: inline; filename="logo.png"\r\n\r\n'
            + png + b'\r\n--R--\r\n'
        )
        parsed = EmailParserService().parse_email(payload, 'x.eml')
        result = AttachmentAnalyzerService().analyze_attachments(parsed['attachments'])
        assert result['total_count'] == 1
        assert result['suspicious_count'] == 0


class TestTransferEncodingParsing:
    """
    HIGH. Content sniffing tested `encoding == 'base64'`, which a legal
    `base64;` or `base64 (comment)` defeated — the sniffer then read
    still-encoded text and found no signature.
    """

    @pytest.mark.parametrize('cte', [b'base64', b'base64;', b'base64 (encoded)',
                                     b'BASE64', b' base64 '])
    def test_every_spelling_still_decodes_for_sniffing(self, cte):
        payload = base64.b64encode(b'MZ\x90\x00\x03' + b'A' * 60)
        eml = (
            HEAD + b'Content-Type: multipart/mixed; boundary="X"\r\n\r\n--X\r\n'
            b'Content-Type: image/jpeg; name="holiday.jpg"\r\n'
            b'Content-Transfer-Encoding: ' + cte + b'\r\n'
            b'Content-Disposition: attachment; filename="holiday.jpg"\r\n\r\n'
            + payload + b'\r\n--X--\r\n'
        )
        parsed = EmailParserService().parse_email(eml, 'x.eml')
        assert parsed['attachments'][0]['content_mismatch'] == 'pe_executable'


class TestFromHeaderAddressList:
    """
    HIGH. parseaddr returns ('', '') for a mailbox LIST, which RFC 5322 permits
    in From. One extra address therefore disabled every sender-domain check —
    SPF, DMARC, WHOIS, domain age and the Return-Path/Reply-To comparisons all
    key on it. A measured email fell from score 38 to 2.
    """

    @pytest.mark.parametrize('header,expected', [
        ('Alice <alice@example.com>', 'example.com'),
        ('Alice <alice@example.com>, Bob <bob@evil.tk>', 'example.com'),
        ('"Doe, Jane" <jane@example.com>', 'example.com'),
        ('alice@example.com', 'example.com'),
    ])
    def test_sender_domain_survives_a_list(self, header, expected):
        assert extract_sender_domain(header) == expected

    def test_email_domain_survives_a_list(self):
        assert email_domain('Alice <alice@example.com>, Bob <bob@evil.tk>') == 'example.com'

    def test_sender_checks_still_run_with_two_addresses(self, monkeypatch):
        from app.services.email_analyzer import EmailAnalyzerService

        looked_up = []
        monkeypatch.setattr('app.services.dns_checker.DNSCheckerService.check_spf',
                            lambda self, d: looked_up.append(d))
        monkeypatch.setattr('app.services.dns_checker.DNSCheckerService.check_dmarc',
                            lambda self, d: None)
        monkeypatch.setattr('app.services.whois_service.WhoisService.lookup',
                            lambda self, d: None)

        EmailAnalyzerService().analyze({
            'headers': {'sender': 'Alice <alice@example.com>, Bob <bob@evil.tk>',
                        'auth_results': '', 'hops': [], 'return_path': '',
                        'reply_to': '', 'dkim_signature': ''},
            'body_text': '', 'body_html': '', 'attachments': [],
        })
        assert looked_up == ['example.com']


class TestHopCountHonesty:
    """
    MEDIUM. The parser truncated the hop list before the analyzer saw it, so
    hop_count under-reported and hops_truncated was always False — a 300-hop
    email was reported as a 100-hop email with nothing dropped.
    """

    def test_truncation_is_reported(self):
        from app.services.email_analyzer import EmailAnalyzerService

        hops = b''.join(b'Received: from host%d.example.com\r\n' % i for i in range(300))
        parsed = EmailParserService(
            limits={'MAX_ANALYZED_HOPS': 100}
        ).parse_email(b'From: a@b.com\r\n' + hops + b'\r\nbody', 'x.eml')

        assert parsed['total_hop_count'] == 300
        result = EmailAnalyzerService(limits={'MAX_ANALYZED_HOPS': 100}).analyze(parsed)
        assert result['routing']['hop_count'] == 300
        assert result['routing']['hops_truncated'] is True
        assert len(result['routing']['hops']) == 100

    def test_untruncated_email_is_not_marked_truncated(self):
        from app.services.email_analyzer import EmailAnalyzerService

        hops = b''.join(b'Received: from host%d.example.com\r\n' % i for i in range(5))
        parsed = EmailParserService().parse_email(b'From: a@b.com\r\n' + hops + b'\r\nbody', 'x.eml')
        result = EmailAnalyzerService().analyze(parsed)
        assert result['routing']['hops_truncated'] is False
        assert result['routing']['hop_count'] == 5


class TestUploadLimitConsistency:
    """
    LOW. The frontend advertised and enforced 50MB against a 25MB server limit,
    so a user could wait out a long upload only to be rejected at the end.
    """

    def test_frontend_limit_matches_the_server(self):
        import re
        from pathlib import Path

        root = Path(__file__).resolve().parents[2]
        config_js = (root / 'ataram-frontend/src/js/config.js').read_text(encoding='utf-8')
        match = re.search(r'MAX_FILE_SIZE:\s*(\d+)\s*\*\s*1024\s*\*\s*1024', config_js)
        assert match, 'MAX_FILE_SIZE not found in config.js'
        frontend_mb = int(match.group(1))

        app = create_app(TestingConfig)
        server_mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
        assert frontend_mb == server_mb, f'frontend {frontend_mb}MB vs server {server_mb}MB'

    def test_nginx_body_size_matches_the_server(self):
        import re
        from pathlib import Path

        conf = (Path(__file__).resolve().parents[2]
                / 'deploy/nginx.conf').read_text(encoding='utf-8')
        match = re.search(r'client_max_body_size\s+(\d+)m', conf)
        assert match, 'client_max_body_size not found'
        app = create_app(TestingConfig)
        assert int(match.group(1)) == app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
