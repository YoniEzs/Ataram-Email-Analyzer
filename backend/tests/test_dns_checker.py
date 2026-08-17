"""Tests for DNSCheckerService, focused on reverse DNS (PTR) lookups."""

from unittest.mock import MagicMock, patch

import dns.exception
import pytest

from app.services.dns_checker import DNSCheckerService
from app.utils.cache import _cache


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


def _ptr_answer(*hostnames):
    """Build a fake PTR answer set whose targets carry the trailing dot."""
    answers = []
    for hostname in hostnames:
        rdata = MagicMock()
        rdata.target = f"{hostname}."
        answers.append(rdata)
    return answers


def test_reverse_dns_returns_first_hostname_without_trailing_dot():
    service = DNSCheckerService(timeout=2)
    with patch(
        "app.services.dns_checker.dns.resolver.resolve",
        return_value=_ptr_answer("dns.google", "google-public-dns-a.google.com"),
    ) as mock_resolve:
        assert service.reverse_dns("8.8.8.8") == "dns.google"
    mock_resolve.assert_called_once()


def test_reverse_dns_negative_result_is_cached():
    service = DNSCheckerService(timeout=2)
    with patch(
        "app.services.dns_checker.dns.resolver.resolve",
        side_effect=dns.exception.DNSException(),
    ) as mock_resolve:
        assert service.reverse_dns("8.8.8.8") is None
        # Second lookup is served from the negative cache — no new query.
        assert service.reverse_dns("8.8.8.8") is None
    mock_resolve.assert_called_once()


def test_reverse_dns_positive_result_is_cached():
    service = DNSCheckerService(timeout=2)
    with patch(
        "app.services.dns_checker.dns.resolver.resolve",
        return_value=_ptr_answer("mail.example.com"),
    ) as mock_resolve:
        assert service.reverse_dns("203.0.113.10") == "mail.example.com"
        assert service.reverse_dns("203.0.113.10") == "mail.example.com"
    mock_resolve.assert_called_once()


def test_reverse_dns_empty_ip_returns_none_without_query():
    service = DNSCheckerService(timeout=2)
    with patch("app.services.dns_checker.dns.resolver.resolve") as mock_resolve:
        assert service.reverse_dns("") is None
    mock_resolve.assert_not_called()


def test_reverse_dns_swallows_unexpected_errors():
    service = DNSCheckerService(timeout=2)
    with patch(
        "app.services.dns_checker.dns.resolver.resolve",
        side_effect=RuntimeError("boom"),
    ):
        assert service.reverse_dns("8.8.8.8") is None
