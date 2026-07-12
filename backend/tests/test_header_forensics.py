"""
Tests for header forensics extraction.
"""

from app.services.header_forensics import HeaderForensicsService


def test_extracts_public_ips_originating_ip_and_timezone():
    service = HeaderForensicsService()
    hops = [
        "from relay-a.example (relay-a [93.184.216.34]) by mx.example",
        "from internal.example (internal [10.0.0.9]) by relay-a.example",
        "from sender.example (sender [1.1.1.1]) by internal.example",
    ]

    result = service.analyze(
        hops=hops,
        date_header="Mon, 09 Mar 2026 09:21:00 +0300",
        sender_domain="example.com",
    )

    assert result["public_ips"] == ["93.184.216.34", "1.1.1.1"]
    assert result["originating_ip"] == "1.1.1.1"
    assert result["hop_count"] == 3
    assert result["timezone_offset"] == "+0300"


def test_ignores_non_global_and_duplicate_ips():
    service = HeaderForensicsService()
    hops = [
        "from a.example (a [93.184.216.34]) by mx.example",
        "from b.example (b [192.168.1.20]) by a.example",
        "from c.example (c [93.184.216.34]) by b.example",
    ]

    result = service.analyze(hops=hops, date_header="", sender_domain="example.com")

    assert result["public_ips"] == ["93.184.216.34"]
    assert result["originating_ip"] == "93.184.216.34"
    assert result["hop_count"] == 3
    assert result["timezone_offset"] is None


def test_extracts_bracketed_ipv6_and_unbracketed_ipv4():
    service = HeaderForensicsService()
    hops = [
        "from ipv6-relay.example ([2001:4860:4860::8888]) by mx.example",
        "from sender.example (8.8.4.4) by ipv6-relay.example",
    ]

    result = service.analyze(hops=hops, date_header="", sender_domain="example.com")

    assert result["public_ips"] == ["2001:4860:4860::8888", "8.8.4.4"]
    assert result["originating_ip"] == "8.8.4.4"
    assert result["hop_count"] == 2


def test_extracts_ipv6_prefixed_literal():
    service = HeaderForensicsService()
    hops = [
        "from mail.example ([IPv6:2001:4860:4860::8844]) by mx.example",
    ]

    result = service.analyze(hops=hops, date_header="", sender_domain="example.com")

    assert result["public_ips"] == ["2001:4860:4860::8844"]
    assert result["originating_ip"] == "2001:4860:4860::8844"


def test_returns_safe_defaults_on_unexpected_input():
    service = HeaderForensicsService()
    result = service.analyze(hops=None, date_header=None, sender_domain="example.com")

    assert result == {
        "public_ips": [],
        "hop_count": 0,
        "originating_ip": None,
        "timezone_offset": None,
    }
