"""Privacy regression tests for ITgalya offline mode."""

from unittest.mock import patch

from app.config import _env_bool, _network_feature_enabled, _offline_requested
from app.services.dns_checker import DNSCheckerService
from app.utils.cache import _cache


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
