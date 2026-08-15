"""
Regression tests for the bug-fix pass.

Each test pins behaviour that was demonstrably wrong before the fix, so the
specific defect cannot silently come back.
"""

import io
from unittest.mock import patch

from app.services import auth_verifier as auth_verifier_module
from app.services.auth_verifier import AuthVerifierService
from app.services.content_analyzer import ContentAnalyzerService
from app.services.email_analyzer import EmailAnalyzerService
from app.services.email_parser import EmailParserService
from app.services.header_forensics import HeaderForensicsService


# ---------------------------------------------------------------------------
# Attachment extraction no longer requires Content-Disposition: attachment
# ---------------------------------------------------------------------------

def _multipart_eml(part_headers: bytes) -> bytes:
    """Build a multipart/mixed message whose second part is the payload.

    The base64 body decodes to b'MZ\\x90...' — a Windows PE header.
    """
    return (
        b'From: attacker@evil.example\r\n'
        b'To: victim@company.example\r\n'
        b'Subject: invoice\r\n'
        b'MIME-Version: 1.0\r\n'
        b'Content-Type: multipart/mixed; boundary="BOUND"\r\n'
        b'\r\n'
        b'--BOUND\r\n'
        b'Content-Type: text/plain; charset=utf-8\r\n'
        b'\r\n'
        b'See attached.\r\n'
        b'--BOUND\r\n'
        + part_headers +
        b'Content-Transfer-Encoding: base64\r\n'
        b'\r\n'
        b'TVqQAAMAAAAEAAAA\r\n'
        b'--BOUND--\r\n'
    )


def test_attachment_without_content_disposition_is_extracted():
    # Content-Disposition is optional (RFC 2183). Requiring it let an
    # attacker hide a payload from every downstream check by simply
    # omitting the header.
    eml = _multipart_eml(
        b'Content-Type: application/octet-stream; name="invoice.exe"\r\n'
    )

    result = EmailParserService().parse_email(eml, 'nodisposition.eml')

    assert [a['filename'] for a in result['attachments']] == ['invoice.exe']
    assert result['attachments'][0]['extension'] == 'exe'
    assert result['attachments'][0]['data'].startswith(b'MZ')


def test_inline_disposition_attachment_is_extracted():
    eml = _multipart_eml(
        b'Content-Type: application/octet-stream\r\n'
        b'Content-Disposition: inline; filename="payload.exe"\r\n'
    )

    result = EmailParserService().parse_email(eml, 'inline.eml')

    assert [a['filename'] for a in result['attachments']] == ['payload.exe']


def test_hidden_attachment_reaches_the_analyzer_as_suspicious():
    eml = _multipart_eml(
        b'Content-Type: application/octet-stream; name="invoice.exe"\r\n'
    )
    parsed = EmailParserService().parse_email(eml, 'nodisposition.eml')
    parsed['headers']['sender'] = ''
    parsed['headers']['hops'] = []

    service = EmailAnalyzerService(
        enable_whois=False,
        enable_abuseipdb=False,
        enable_auth_verification=False,
    )
    result = service.analyze(parsed)

    assert result['attachments']['total_count'] == 1
    assert result['attachments']['suspicious_count'] == 1
    assert 'executable_file' in result['attachments']['attachments'][0]['issues']


def test_plain_body_parts_are_not_treated_as_attachments():
    eml = (
        b'From: sender@example.com\r\n'
        b'To: recipient@example.com\r\n'
        b'Subject: Normal message\r\n'
        b'MIME-Version: 1.0\r\n'
        b'Content-Type: multipart/alternative; boundary="B"\r\n'
        b'\r\n'
        b'--B\r\n'
        b'Content-Type: text/plain; charset=utf-8\r\n'
        b'\r\n'
        b'Normal body\r\n'
        b'--B\r\n'
        b'Content-Type: text/html; charset=utf-8\r\n'
        b'\r\n'
        b'<p>Normal body</p>\r\n'
        b'--B--\r\n'
    )

    result = EmailParserService().parse_email(eml, 'normal.eml')

    assert result['attachments'] == []


# ---------------------------------------------------------------------------
# Content analysis keeps a stable shape
# ---------------------------------------------------------------------------

def test_content_analysis_keeps_full_shape_without_html_body():
    result = ContentAnalyzerService().analyze('plain text only', '')

    for key in (
        'urgent_phrases', 'generic_greetings', 'credential_requests',
        'exclamation_marks', 'uppercase_ratio',
        'forms', 'scripts', 'hidden_elements', 'anchor_mismatches',
        'yara_matches',
    ):
        assert key in result, f'missing key {key}'


def test_content_analysis_keeps_full_shape_for_empty_message():
    result = ContentAnalyzerService().analyze('', '')

    assert result['urgent_phrases'] == []
    assert result['forms'] == 0
    assert result['anchor_mismatches'] == []


# ---------------------------------------------------------------------------
# A DKIM verification error is not a cryptographic failure
# ---------------------------------------------------------------------------

SIGNED_RAW = (
    b'DKIM-Signature: v=1; d=example.com; s=s1\r\n'
    b'From: a@example.com\r\n'
    b'\r\n'
    b'body'
)


def test_dkim_transport_error_is_reported_as_error_not_fail():
    service = AuthVerifierService()

    with patch.object(
        auth_verifier_module.dkim, 'verify', side_effect=OSError('DNS unreachable')
    ):
        assert service._verify_dkim(SIGNED_RAW) == 'error'


def test_dkim_error_adds_no_suspicion_and_no_risk_score():
    service = EmailAnalyzerService(
        enable_whois=False,
        enable_abuseipdb=False,
        enable_auth_verification=False,
    )
    verification = {'available': True, 'spf': None, 'dkim': 'error'}
    empty = {
        'abuse_data': None,
        'url_analysis': {'suspicious_count': 0},
        'attachment_analysis': {'suspicious_count': 0, 'attachments': []},
    }

    suspicions = service._detect_suspicions(
        headers={'sender': 'a@example.com', 'return_path': '', 'reply_to': ''},
        auth_analysis={},
        whois_data=None,
        verification=verification,
        **empty,
    )
    assert not any(s['category'] == 'authentication' for s in suspicions)

    score, level, _ = service._calculate_risk_score(
        auth_analysis={},
        content_analysis={'urgent_phrases': []},
        suspicions=[],
        verification=verification,
        **empty,
    )
    assert score == 0
    assert level == 'low'


# ---------------------------------------------------------------------------
# Authentication-Results claims must not match on substrings
# ---------------------------------------------------------------------------

def test_auth_results_substrings_are_not_read_as_claims():
    service = object.__new__(EmailAnalyzerService)

    claims = service._analyze_authentication(
        'mx.company.example; nospf=pass; x-dkim=pass; policy.dmarc=pass'
    )

    assert claims['spf'] is None
    assert claims['dkim'] is None
    assert claims['dmarc'] is None


def test_auth_results_real_claims_still_parsed():
    service = object.__new__(EmailAnalyzerService)

    claims = service._analyze_authentication(
        'mx.company.example; spf=fail smtp.mailfrom=evil.example; '
        'dkim=none; dmarc=fail'
    )

    assert claims['spf'] == 'fail'
    assert claims['dkim'] == 'none'
    assert claims['dmarc'] == 'fail'
    assert claims['trusted'] is False


# ---------------------------------------------------------------------------
# Timezone offsets
# ---------------------------------------------------------------------------

def test_iso_8601_timezone_offset_is_extracted():
    # The MSG parser falls back to datetime.isoformat(), which writes "+03:00".
    result = HeaderForensicsService().analyze(
        hops=[], date_header='2026-08-15T12:00:00+03:00', sender_domain='example.com'
    )

    assert result['timezone_offset'] == '+0300'


def test_rfc5322_timezone_offset_still_extracted():
    result = HeaderForensicsService().analyze(
        hops=[], date_header='Mon, 09 Mar 2026 09:21:00 -0500',
        sender_domain='example.com',
    )

    assert result['timezone_offset'] == '-0500'


def test_date_without_offset_reports_none():
    result = HeaderForensicsService().analyze(
        hops=[], date_header='2026-08-15T12:00:00', sender_domain='example.com'
    )

    assert result['timezone_offset'] is None


# ---------------------------------------------------------------------------
# Upload filename sanitising must not skip content validation
# ---------------------------------------------------------------------------

def test_sanitised_filename_keeps_eml_content_validation(client):
    # secure_filename('....eml') collapses to 'eml' — no dot left, so
    # validate_email_file() used to skip the EML content check entirely.
    response = client.post(
        '/api/v1/analyze',
        data={'emailfile': (io.BytesIO(b'not an email, just junk bytes'), '....eml')},
        content_type='multipart/form-data',
    )

    assert response.status_code == 400
    assert response.get_json()['error'] == 'Invalid file'


# ---------------------------------------------------------------------------
# Upload-limit messages
# ---------------------------------------------------------------------------

def test_413_message_does_not_report_zero_megabytes(app, client):
    app.config['MAX_CONTENT_LENGTH'] = 1024

    response = client.post(
        '/api/analyze',
        data={'emailfile': (io.BytesIO(b'x' * 4096), 'big.eml')},
        content_type='multipart/form-data',
    )

    assert response.status_code == 413
    message = response.get_json()['message']
    assert '0MB' not in message
    assert '1KB' in message
