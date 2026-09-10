"""Privacy regression tests for ITgalya offline mode."""

from io import BytesIO
from unittest.mock import patch

from app import create_app
from app.config import (
    TestingConfig,
    _env_bool,
    _network_feature_enabled,
    _offline_requested,
)
from app.services.dns_checker import DNSCheckerService
from app.utils.cache import _cache


class OfflineTestingConfig(TestingConfig):
    OFFLINE_MODE = True
    ENABLE_WHOIS = False
    ENABLE_ABUSEIPDB = False
    ENABLE_VIRUSTOTAL = False
    ENABLE_AUTH_VERIFICATION = False
    ENABLE_REVERSE_DNS = False
    ENABLE_IP_RDAP = False
    ENABLE_ASN_LOOKUP = False
    ENABLE_MX_LOOKUP = False
    ENABLE_SPF_ADVISORY = False
    FORCE_HTTPS = False
    RATELIMIT_ENABLED = False


def test_env_bool_accepts_explicit_truthy_values(monkeypatch):
    for value in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("ITGALYA_TEST_BOOL", value)
        assert _env_bool("ITGALYA_TEST_BOOL") is True


def test_offline_mode_accepts_public_and_legacy_names(monkeypatch):
    monkeypatch.delenv("ITGALYA_OFFLINE_MODE", raising=False)
    monkeypatch.delenv("OFFLINE_MODE", raising=False)
    assert _offline_requested() is False

    monkeypatch.setenv("ITGALYA_OFFLINE_MODE", "true")
    assert _offline_requested() is True

    monkeypatch.delenv("ITGALYA_OFFLINE_MODE")
    monkeypatch.setenv("OFFLINE_MODE", "1")
    assert _offline_requested() is True


def test_offline_master_switch_overrides_enabled_network_feature(monkeypatch):
    monkeypatch.setenv("ITGALYA_OFFLINE_MODE", "true")
    monkeypatch.setenv("ENABLE_WHOIS", "true")
    monkeypatch.setenv("ENABLE_VIRUSTOTAL", "true")

    assert _network_feature_enabled("ENABLE_WHOIS", True) is False
    assert _network_feature_enabled("ENABLE_VIRUSTOTAL", True) is False


def test_dns_primitives_make_no_resolver_calls_in_offline_mode(monkeypatch):
    """Even a direct DNS service call must not bypass the privacy switch."""
    _cache.clear()
    monkeypatch.setenv("ITGALYA_OFFLINE_MODE", "true")
    service = DNSCheckerService(timeout=1)

    with patch("app.services.dns_checker.dns.resolver.resolve") as resolve:
        assert service.get_txt_records("example.com") is None
        assert service.check_spf("example.com") is None
        assert service.check_dmarc("example.com") is None
        assert service.check_dkim("example.com", "selector") is None
        assert service.get_mx_records("example.com") is None
        assert service.get_ptr_records("8.8.8.8") is None
        assert service.reverse_dns("8.8.8.8") is None

    resolve.assert_not_called()
    _cache.clear()


def test_network_only_endpoints_are_disabled_offline(monkeypatch):
    monkeypatch.setenv("ITGALYA_OFFLINE_MODE", "true")
    app = create_app(OfflineTestingConfig)
    client = app.test_client()

    domain_response = client.post('/api/v1/check/domain', json={'domain': 'google.com'})
    ip_response = client.post('/api/v1/check/ip', json={'ip': '8.8.8.8'})

    assert domain_response.status_code == 503
    assert domain_response.get_json()['error'] == 'Feature disabled'
    assert ip_response.status_code == 503
    assert ip_response.get_json()['error'] == 'Feature disabled'


def test_full_email_analysis_records_offline_context_without_http(monkeypatch):
    """A normal EML still analyzes locally and records that enrichment was off."""
    monkeypatch.setenv("ITGALYA_OFFLINE_MODE", "true")
    app = create_app(OfflineTestingConfig)
    client = app.test_client()

    eml = (
        b"From: Security Team <security@example.org>\r\n"
        b"To: analyst@example.net\r\n"
        b"Subject: Offline analysis regression\r\n"
        b"Date: Thu, 10 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <offline-test@example.org>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Local analysis only.\r\n"
    )

    with patch(
        "requests.sessions.Session.request",
        side_effect=AssertionError("offline analysis attempted an HTTP request"),
    ):
        response = client.post(
            '/api/v1/analyze',
            data={'emailfile': (BytesIO(eml), 'offline-test.eml')},
            content_type='multipart/form-data',
        )

    assert response.status_code == 200
    body = response.get_json()
    assert body['metadata']['offline_mode'] is True
    assert 'risk_assessment' in body
