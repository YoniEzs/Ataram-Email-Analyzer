"""
Tests for input validators and API rejection of unsafe lookup targets.
"""

import pytest

from app.utils.validators import validate_domain, validate_email_file, validate_public_ip


def test_email_size_limit_is_configurable():
    payload = b'From: a@example.com\r\n\r\nbody' + b'x' * 100
    valid, error = validate_email_file(payload, 'mail.eml', max_bytes=32)
    assert valid is False
    assert 'maximum size' in error


@pytest.mark.parametrize(
    "domain",
    [
        "example.com",
        "sub.example.co.uk",
        "xn--bcher-kva.de",
    ],
)
def test_validate_domain_accepts_public_domain_names(domain):
    assert validate_domain(domain) is True


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "localhost",
        "localhost.example.com",
        "example.local",
        "example.internal",
        "example.test",
        "example.invalid",
        "127.0.0.1",
        "bad..example.com",
        "-bad.example.com",
    ],
)
def test_validate_domain_rejects_unsafe_or_invalid_names(domain):
    assert validate_domain(domain) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "2001:4860:4860::8888"])
def test_validate_public_ip_accepts_global_addresses(ip):
    assert validate_public_ip(ip) is True


@pytest.mark.parametrize(
    "ip",
    [
        "",
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "not-an-ip",
    ],
)
def test_validate_public_ip_rejects_private_or_invalid_addresses(ip):
    assert validate_public_ip(ip) is False


@pytest.mark.parametrize(
    "domain",
    [
        "localhost",
        "localhost.example.com",
        "example.local",
        "127.0.0.1",
        "bad..example.com",
    ],
)
def test_check_domain_api_rejects_invalid_domains(client, domain):
    response = client.post("/api/check/domain", json={"domain": domain})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "Invalid domain"


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "::1",
        "not-an-ip",
    ],
)
def test_check_ip_api_rejects_invalid_or_non_public_ips(client, ip):
    response = client.post("/api/check/ip", json={"ip": ip})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "Invalid IP"


def test_analyze_url_rejects_invalid_sender_domain(client):
    response = client.post(
        '/api/analyze/url',
        json={'url': 'https://example.com', 'sender_domain': 'localhost'},
    )
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Invalid sender domain'


def test_analyze_url_rejects_overlong_url(client):
    response = client.post(
        '/api/analyze/url',
        json={'url': 'https://example.com/' + 'x' * 5000},
    )
    assert response.status_code == 400
    assert response.get_json()['error'] == 'URL too long'
