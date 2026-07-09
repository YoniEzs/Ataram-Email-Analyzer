"""
Tests for the P2 detection features: content inspection, YARA,
VirusTotal, independent auth verification, homographs, multi-language
keywords, and smarter URL extraction.
"""

import io
import zipfile
from unittest.mock import MagicMock, patch

from app.services import auth_verifier as auth_verifier_module
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.services.auth_verifier import AuthVerifierService
from app.services.content_analyzer import ContentAnalyzerService
from app.services.email_analyzer import EmailAnalyzerService
from app.services.email_parser import EmailParserService
from app.services.url_analyzer import URLAnalyzerService, _is_homograph_label
from app.services.virustotal_service import VirusTotalService
from app.services.yara_scanner import YaraScanner
from app.utils.cache import _cache


def analyze_attachment(filename, extension, data, content_type=''):
    return AttachmentAnalyzerService().analyze_single_attachment({
        'filename': filename,
        'extension': extension,
        'content_type': content_type,
        'size': len(data),
        'data': data,
    })


# ---------------------------------------------------------------------------
# Attachment content inspection
# ---------------------------------------------------------------------------

def test_executable_content_behind_pdf_name_is_critical():
    result = analyze_attachment('invoice.pdf', 'pdf', b'MZ\x90\x00' + b'\x00' * 64)
    assert 'executable_content_mismatch' in result['issues']
    assert 'content_type_mismatch' in result['issues']
    assert result['severity'] == 'critical'


def test_real_pdf_content_is_clean():
    result = analyze_attachment('report-q3.pdf', 'pdf', b'%PDF-1.7 ' + b'x' * 64)
    assert result['issues'] == []


def test_zip_containing_executable_flagged():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        zf.writestr('docs/readme.txt', 'hello')
        zf.writestr('setup.exe', b'MZ' + b'\x00' * 32)
    result = analyze_attachment('bundle.zip', 'zip', buffer.getvalue())
    assert 'archive_contains_executable' in result['issues']
    assert result['severity'] == 'critical'


def test_sha256_exposed_but_raw_data_is_not():
    result = analyze_attachment('a.pdf', 'pdf', b'%PDF-1.7 data')
    assert result['sha256'] and len(result['sha256']) == 64
    assert 'data' not in result


# ---------------------------------------------------------------------------
# YARA scanner
# ---------------------------------------------------------------------------

def test_yara_scanner_compiles_and_matches(tmp_path):
    (tmp_path / 'test.yar').write_text(
        'rule MarkerRule { strings: $a = "PHISH_MARKER" condition: $a }'
    )
    scanner = YaraScanner(str(tmp_path))
    assert scanner.available
    assert scanner.scan(b'... PHISH_MARKER ...') == ['MarkerRule']
    assert scanner.scan(b'clean content') == []


def test_yara_scanner_unavailable_without_rules(tmp_path):
    scanner = YaraScanner(str(tmp_path / 'missing'))
    assert not scanner.available
    assert scanner.scan(b'anything') == []


def test_bundled_starter_rules_compile():
    import os
    rules_dir = os.path.join(os.path.dirname(__file__), '..', 'yara_rules')
    scanner = YaraScanner(rules_dir)
    assert scanner.available
    assert 'PEExecutableDroppedInMail' in scanner.scan(b'MZ' + b'\x00' * 64)


# ---------------------------------------------------------------------------
# VirusTotal service
# ---------------------------------------------------------------------------

SHA = 'a' * 64


def _vt_response(status=200, malicious=5):
    response = MagicMock()
    response.status_code = status
    response.json.return_value = {
        'data': {'attributes': {
            'last_analysis_stats': {
                'malicious': malicious, 'suspicious': 1,
                'harmless': 60, 'undetected': 10,
            },
            'reputation': -20,
            'type_description': 'Win32 EXE',
            'popular_threat_classification': {'suggested_threat_label': 'trojan.agent'},
        }}
    }
    return response


def test_virustotal_malicious_verdict(monkeypatch):
    _cache.clear()
    service = VirusTotalService('test-key', timeout=5)
    with patch('app.services.virustotal_service.requests.get', return_value=_vt_response()) as mock_get:
        verdict = service.check_hash(SHA)
    assert verdict['known'] is True
    assert verdict['malicious'] == 5
    assert verdict['popular_threat_label'] == 'trojan.agent'
    mock_get.assert_called_once()
    _cache.clear()


def test_virustotal_unknown_hash_cached(monkeypatch):
    _cache.clear()
    service = VirusTotalService('test-key', timeout=5)
    with patch('app.services.virustotal_service.requests.get', return_value=_vt_response(status=404)) as mock_get:
        first = service.check_hash(SHA)
        second = service.check_hash(SHA)
    assert first == {'known': False}
    assert second == {'known': False}
    mock_get.assert_called_once()  # second hit served from cache
    _cache.clear()


def test_virustotal_lookup_cap():
    service = VirusTotalService('test-key', timeout=5)
    hashes = [f'{i:064x}' for i in range(6)]
    with patch.object(service, 'check_hash', return_value={'known': False}) as mock_check:
        service.check_hashes(hashes)
    assert mock_check.call_count == 4


def test_virustotal_without_key_returns_nothing():
    service = VirusTotalService(None)
    assert service.check_hashes([SHA]) == {}


# ---------------------------------------------------------------------------
# Independent auth verification
# ---------------------------------------------------------------------------

def test_dkim_verification_pass_and_fail():
    service = AuthVerifierService()
    raw = b'DKIM-Signature: v=1; d=example.com; s=s1\r\nFrom: a@example.com\r\n\r\nbody'

    with patch.object(auth_verifier_module.dkim, 'verify', return_value=True):
        assert service._verify_dkim(raw) == 'pass'
    with patch.object(auth_verifier_module.dkim, 'verify', return_value=False):
        assert service._verify_dkim(raw) == 'fail'


def test_dkim_skipped_without_signature():
    service = AuthVerifierService()
    assert service._verify_dkim(b'From: a@example.com\r\n\r\nbody') is None


def test_spf_check_result_passthrough():
    service = AuthVerifierService()
    with patch.object(auth_verifier_module.spf, 'check2', return_value=('fail', 'not permitted')):
        assert service._check_spf('203.0.113.5', 'example.com') == 'fail'


def test_verified_failure_contradicting_claimed_pass_is_critical():
    service = EmailAnalyzerService(
        enable_whois=False, enable_abuseipdb=False, enable_auth_verification=False
    )
    suspicions = service._detect_suspicions(
        headers={'sender': 'a@example.com', 'return_path': '', 'reply_to': ''},
        abuse_data=None,
        auth_analysis={'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'},
        url_analysis={'suspicious_count': 0},
        attachment_analysis={'suspicious_count': 0, 'attachments': []},
        whois_data=None,
        verification={'available': True, 'spf': 'fail', 'dkim': 'pass'},
    )
    critical = [s for s in suspicions if s['severity'] == 'critical']
    assert any('forged' in s['message'] for s in critical)


def test_vt_malicious_forces_critical_score():
    service = EmailAnalyzerService(
        enable_whois=False, enable_abuseipdb=False, enable_auth_verification=False
    )
    attachment_analysis = {
        'suspicious_count': 1,
        'attachments': [{
            'filename': 'x.exe', 'issues': [], 'is_suspicious': True,
            'virustotal': {'known': True, 'malicious': 12},
        }],
    }
    score, level, _ = service._calculate_risk_score(
        auth_analysis={'spf': 'pass'},
        abuse_data=None,
        url_analysis={'suspicious_count': 0},
        attachment_analysis=attachment_analysis,
        content_analysis={'urgent_phrases': []},
        suspicions=[],
    )
    assert score >= 85
    assert level == 'critical'


# ---------------------------------------------------------------------------
# Homograph detection
# ---------------------------------------------------------------------------

def test_mixed_latin_cyrillic_label_is_homograph():
    assert _is_homograph_label('pаypal')  # Cyrillic а inside Latin word


def test_pure_hebrew_label_is_not_homograph():
    assert not _is_homograph_label('ישראל')


def test_ordinary_cyrillic_word_is_not_homograph():
    assert not _is_homograph_label('привет')


def test_homograph_url_flagged():
    result = URLAnalyzerService().analyze_single_url('https://pаypal.com/login')
    assert 'homograph_domain' in result['issues']


# ---------------------------------------------------------------------------
# Multi-language keywords
# ---------------------------------------------------------------------------

def test_hebrew_phishing_phrases_detected():
    result = ContentAnalyzerService().analyze_language(
        'לקוח יקר, זוהתה פעילות חריגה בחשבונך. אמת את חשבונך ומסור סיסמה תוך 24 שעות'
    )
    assert 'לקוח יקר' in result['generic_greetings']
    assert 'אמת את חשבונך' in result['urgent_phrases']
    assert 'סיסמה' in result['credential_requests']


def test_english_phrases_still_detected():
    result = ContentAnalyzerService().analyze_language(
        'Dear customer, urgent action required: verify your account password'
    )
    assert 'dear customer' in result['generic_greetings']
    assert 'urgent' in result['urgent_phrases']


# ---------------------------------------------------------------------------
# Smarter URL extraction
# ---------------------------------------------------------------------------

def test_urls_extracted_from_html_attributes():
    html = '<a href="https://hidden.example/login">click</a><img src="http://tracker.example/p.gif">'
    urls = URLAnalyzerService().extract_urls('no urls in text', html)
    assert 'https://hidden.example/login' in urls
    assert 'http://tracker.example/p.gif' in urls


def test_schemeless_www_urls_extracted():
    urls = URLAnalyzerService().extract_urls('Visit www.example.com/promo today')
    assert 'http://www.example.com/promo' in urls


def test_eml_with_html_only_body_gets_text_fallback():
    eml = (
        b'From: sender@example.com\r\n'
        b'To: r@example.com\r\n'
        b'Subject: html only\r\n'
        b'Content-Type: text/html; charset=utf-8\r\n'
        b'\r\n'
        b'<html><body><p>Hello <b>world</b></p></body></html>\r\n'
    )
    result = EmailParserService().parse_email(eml, 'htmlonly.eml')
    assert 'Hello' in result['body_text']
    assert '<' not in result['body_text']
