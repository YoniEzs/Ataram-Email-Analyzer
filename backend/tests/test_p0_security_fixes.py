"""
Regression tests for the P0 roadmap fixes (correctness & security).
"""

from unittest.mock import patch

from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.services.dns_checker import DNSCheckerService
from app.services.email_analyzer import EmailAnalyzerService
from app.services.email_parser import EmailParserService
from app.services.url_analyzer import URLAnalyzerService
from app.utils.extractors import extract_sender_ip
from app.utils.validators import validate_email_file


# ---------------------------------------------------------------------------
# Authentication-Results trust boundary
# ---------------------------------------------------------------------------

FORGED_AUTH_EML = (
    # Topmost header: stamped by the receiving server (trusted).
    b'Authentication-Results: mx.company.example; spf=fail smtp.mailfrom=evil.example; dkim=none; dmarc=fail\r\n'
    b'Received: from mail.evil.example (mail [203.0.113.55]) by mx.company.example\r\n'
    # Lower header: forged by the sender before submission (untrusted).
    b'Authentication-Results: mx.company.example; spf=pass; dkim=pass; dmarc=pass\r\n'
    b'From: attacker@evil.example\r\n'
    b'To: victim@company.example\r\n'
    b'Subject: forged auth headers\r\n'
    b'Date: Mon, 06 Jul 2026 09:00:00 +0000\r\n'
    b'\r\n'
    b'body\r\n'
)


def test_parser_exposes_topmost_auth_results():
    result = EmailParserService().parse_email(FORGED_AUTH_EML, 'forged.eml')

    assert 'spf=fail' in result['headers']['auth_results_top']
    assert 'spf=pass' not in result['headers']['auth_results_top']
    # Raw joined value still contains both, for display/forensics.
    assert 'spf=pass' in result['headers']['auth_results']


def test_analyzer_ignores_sender_forged_auth_results():
    parsed = EmailParserService().parse_email(FORGED_AUTH_EML, 'forged.eml')
    # Drop sender/hops so no network lookups run in the test.
    parsed['headers']['sender'] = ''
    parsed['headers']['hops'] = []

    service = EmailAnalyzerService(enable_whois=False, enable_abuseipdb=False)
    result = service.analyze(parsed)

    auth = result['authentication']['auth_analysis']
    assert auth == {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail'}


# ---------------------------------------------------------------------------
# EML validation window
# ---------------------------------------------------------------------------

def test_eml_with_long_received_preamble_is_accepted():
    # >1 KB of Received/ARC headers before From: — used to be rejected.
    received = b'X-ARC-Seal: ' + b'a' * 1500 + b'\r\n'
    eml = received + (
        b'From: sender@example.com\r\n'
        b'To: r@example.com\r\n'
        b'Subject: hi\r\n\r\nbody'
    )
    is_valid, error = validate_email_file(eml, 'mail.eml')
    assert is_valid, error


# ---------------------------------------------------------------------------
# PSL-aware registered domains
# ---------------------------------------------------------------------------

def test_cctld_registered_domain_is_correct():
    result = URLAnalyzerService().analyze_single_url('https://www.example.co.uk/login')
    assert result['domain'] == 'example.co.uk'


def test_subdomain_link_does_not_trip_sender_mismatch():
    result = URLAnalyzerService().analyze_single_url(
        'https://www.example.com/page', sender_domain='example.com'
    )
    assert 'domain_mismatch_with_sender' not in result['issues']


def test_different_registered_domain_still_flags_mismatch():
    result = URLAnalyzerService().analyze_single_url(
        'https://evil.example.ru/page', sender_domain='example.com'
    )
    assert 'domain_mismatch_with_sender' in result['issues']


def test_punycode_detected_in_any_label():
    result = URLAnalyzerService().analyze_single_url('https://login.xn--pypal-4ve.com/x')
    assert 'punycode_domain' in result['issues']


# ---------------------------------------------------------------------------
# DKIM d= domain and record validation
# ---------------------------------------------------------------------------

SIGNATURE = 'v=1; a=rsa-sha256; d=mailer.example; s=selector1; bh=abc; b=xyz'


def test_parse_dkim_domain_and_selector():
    checker = DNSCheckerService()
    assert checker.parse_dkim_domain(SIGNATURE) == 'mailer.example'
    assert checker.parse_dkim_selector(SIGNATURE) == 'selector1'


def test_check_dkim_requires_public_key_tag():
    checker = DNSCheckerService()

    with patch.object(checker, 'get_txt_records', return_value=['not a dkim record']):
        assert checker.check_dkim('example.com', 's1') is None

    key = 'v=DKIM1; k=rsa; p=MIGfMA0GCSq'
    with patch.object(checker, 'get_txt_records', return_value=['junk', key]):
        assert checker.check_dkim('example.com', 's1') == key


# ---------------------------------------------------------------------------
# IPv6 sender extraction
# ---------------------------------------------------------------------------

def test_extract_sender_ip_supports_ipv6():
    hops = [
        'from relay.example (relay [93.184.216.34]) by mx.example',
        'from sender.example ([IPv6:2607:f8b0:4864:20::52e]) by relay.example',
    ]
    assert extract_sender_ip(hops) == '2607:f8b0:4864:20::52e'


def test_extract_sender_ip_still_finds_ipv4_and_skips_private():
    hops = [
        'from relay.example (relay [93.184.216.34]) by mx.example',
        'from internal ([10.0.0.5]) by relay.example',
    ]
    assert extract_sender_ip(hops) == '93.184.216.34'


# ---------------------------------------------------------------------------
# Bidi / RTL-override filenames
# ---------------------------------------------------------------------------

def test_rtl_override_filename_flagged_critical():
    result = AttachmentAnalyzerService().analyze_single_attachment({
        'filename': 'annexe_‮fdp.exe',
        'extension': 'exe',
        'content_type': 'application/octet-stream',
        'size': 2048,
    })
    assert 'bidi_spoofed_filename' in result['issues']
    assert result['severity'] == 'critical'


def test_hebrew_filename_not_flagged_as_bidi_spoof():
    result = AttachmentAnalyzerService().analyze_single_attachment({
        'filename': 'דוח-רבעוני.pdf',
        'extension': 'pdf',
        'content_type': 'application/pdf',
        'size': 2048,
    })
    assert 'bidi_spoofed_filename' not in result['issues']
