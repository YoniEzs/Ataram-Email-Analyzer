"""Tests for the bounded RDAP registration lookup."""

from unittest.mock import patch

import pytest

from app.services.whois_service import WhoisService
from app.utils.cache import _cache


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


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


def test_lookup_parses_rdap_payload_into_registration_fields():
    service = WhoisService(timeout=5)
    with patch(
        'app.services.whois_service.get_json', return_value=RDAP_PAYLOAD
    ) as mock_get_json:
        result = service.lookup('example.com')

    mock_get_json.assert_called_once()
    assert mock_get_json.call_args.kwargs['timeout'] == 5
    assert 'rdap+json' in mock_get_json.call_args.kwargs['accept']
    assert result is not None
    assert result['registrar'] == 'Example Registrar Inc.'
    assert result['creation_date'] == '2001-05-20T00:00:00Z'
    assert result['expiration_date'] == '2030-05-20T00:00:00Z'
    assert result['updated_date'] == '2025-01-01T00:00:00Z'
    assert result['name_servers'] == ['NS1.EXAMPLE.COM', 'NS2.EXAMPLE.COM']
    assert result['status'] == ['client transfer prohibited']
    assert result['source'] == 'rdap'


def test_lookup_returns_none_when_transport_yields_nothing():
    service = WhoisService(timeout=5)
    with patch('app.services.whois_service.get_json', return_value=None):
        assert service.lookup('example.com') is None


def test_lookup_returns_none_for_non_object_payload():
    service = WhoisService(timeout=5)
    with patch('app.services.whois_service.get_json', return_value=['unexpected']):
        assert service.lookup('example.com') is None


def test_lookup_rejects_invalid_domain_without_network():
    service = WhoisService(timeout=5)
    with patch('app.services.whois_service.get_json') as mock_get_json:
        assert service.lookup('localhost') is None
        assert service.lookup('') is None
    mock_get_json.assert_not_called()


def test_second_lookup_is_served_from_cache():
    service = WhoisService(timeout=5)
    with patch(
        'app.services.whois_service.get_json', return_value=RDAP_PAYLOAD
    ) as mock_get_json:
        first = service.lookup('example.com')
        second = service.lookup('example.com')
    assert first == second
    mock_get_json.assert_called_once()
