"""Tests for the bounded RDAP registration lookup."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from app.services.whois_service import WhoisService
from app.utils.cache import _cache


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


def _response(status=200, payload=None, location=None):
    response = MagicMock()
    response.status_code = status
    response.headers = {'Location': location} if location else {}
    import json
    response.iter_content.return_value = [json.dumps(payload or {}).encode()]
    return response


RDAP_PAYLOAD = {
    'status': ['client transfer prohibited'],
    'events': [
        {'eventAction': 'registration', 'eventDate': '2001-05-20T00:00:00Z'},
        {'eventAction': 'expiration', 'eventDate': '2030-05-20T00:00:00Z'},
        {'eventAction': 'last changed', 'eventDate': '2025-01-01T00:00:00Z'},
    ],
    'entities': [{
        'roles': ['registrar'],
        'vcardArray': ['vcard', [['fn', {}, 'text', 'Example Registrar Inc.']]],
    }],
    'nameservers': [
        {'ldhName': 'NS1.EXAMPLE.COM'},
        {'ldhName': 'NS2.EXAMPLE.COM'},
    ],
}


def test_lookup_parses_rdap_and_uses_bounded_https_request():
    service = WhoisService(timeout=5)
    response = _response(payload=RDAP_PAYLOAD)

    with patch(
        'app.services.whois_service._is_public_https_url', return_value=True
    ), patch(
        'app.services.whois_service.requests.get', return_value=response
    ) as mock_get:
        result = service.lookup('example.com')

    mock_get.assert_called_once()
    assert mock_get.call_args.kwargs['allow_redirects'] is False
    assert mock_get.call_args.kwargs['timeout'] == (3, 5)
    assert result is not None
    assert result['registrar'] == 'Example Registrar Inc.'
    assert result['creation_date'] == '2001-05-20T00:00:00Z'
    assert result['name_servers'] == ['NS1.EXAMPLE.COM', 'NS2.EXAMPLE.COM']
    assert result['source'] == 'rdap'


def test_lookup_timeout_returns_none_without_worker_leak():
    service = WhoisService(timeout=1)
    with patch(
        'app.services.whois_service._is_public_https_url', return_value=True
    ), patch(
        'app.services.whois_service.requests.get',
        side_effect=requests.Timeout('timed out'),
    ):
        assert service.lookup('example.com') is None


def test_redirect_to_non_public_target_is_blocked():
    service = WhoisService(timeout=5)
    redirect = _response(status=302, location='https://127.0.0.1/private')
    with patch(
        'app.services.whois_service._is_public_https_url',
        side_effect=[True, False],
    ), patch(
        'app.services.whois_service.requests.get', return_value=redirect
    ) as mock_get:
        assert service.lookup('example.com') is None
    assert mock_get.call_count == 1


def test_oversized_rdap_response_is_rejected():
    service = WhoisService(timeout=5)
    response = _response(payload=RDAP_PAYLOAD)
    response.iter_content.return_value = [b'x' * (1024 * 1024 + 1)]
    with patch(
        'app.services.whois_service._is_public_https_url', return_value=True
    ), patch(
        'app.services.whois_service.requests.get', return_value=response
    ):
        assert service.lookup('example.com') is None
    response.close.assert_called_once()


def test_lookup_rejects_invalid_domain_without_network():
    service = WhoisService(timeout=5)
    with patch('app.services.whois_service.requests.get') as mock_get:
        assert service.lookup('localhost') is None
        assert service.lookup('') is None
    mock_get.assert_not_called()
