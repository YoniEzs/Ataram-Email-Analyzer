"""Direct tests for the AbuseIPDB reputation lookup.

This module was previously exercised only through
``tests/test_lookup_api_contract.py``, which monkeypatches the whole class
away — so the request construction, response mapping, caching and failure
handling had no coverage at all. It is also a live QA path: the UI lets an
analyst paste their own AbuseIPDB key.

Every test here stubs the transport. Nothing performs real network I/O.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from app.services.ip_reputation import IPReputationService
from app.utils.cache import _cache

IP = '198.51.100.7'

ABUSEIPDB_PAYLOAD = {
    'data': {
        'ipAddress': IP,
        'abuseConfidenceScore': 87,
        'totalReports': 42,
        'numDistinctUsers': 12,
        'lastReportedAt': '2026-08-01T10:00:00+00:00',
        'usageType': 'Data Center/Web Hosting/Transit',
        'isp': 'Example Hosting',
        'domain': 'example-hosting.test',
        'hostnames': ['host.example-hosting.test'],
        'countryCode': 'NL',
        'countryName': 'Netherlands',
        # A field the mapper deliberately drops.
        'isWhitelisted': False,
    }
}


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


def fake_response(payload, status=200):
    response = MagicMock()
    response.json.return_value = payload
    response.status_code = status
    response.raise_for_status.return_value = None
    return response


# --- guard clauses ----------------------------------------------------------

def test_no_key_returns_none_without_calling_out():
    with patch('app.services.ip_reputation.requests.get') as get:
        assert IPReputationService(None).check_ip(IP) is None
    get.assert_not_called()


def test_empty_ip_returns_none_without_calling_out():
    with patch('app.services.ip_reputation.requests.get') as get:
        assert IPReputationService('key').check_ip('') is None
    get.assert_not_called()


# --- request construction ---------------------------------------------------

def test_request_carries_key_in_header_not_query():
    """The API key must travel in the Key header, never in the URL.

    Query strings land in proxy and server access logs; the header does not.
    """
    with patch(
        'app.services.ip_reputation.requests.get',
        return_value=fake_response(ABUSEIPDB_PAYLOAD),
    ) as get:
        IPReputationService('secret-key').check_ip(IP)

    _, kwargs = get.call_args
    assert kwargs['headers']['Key'] == 'secret-key'
    assert 'secret-key' not in str(kwargs['params'])
    assert kwargs['params']['ipAddress'] == IP


def test_request_is_bounded_by_the_configured_timeout():
    """An unbounded lookup would hang the whole analysis."""
    with patch(
        'app.services.ip_reputation.requests.get',
        return_value=fake_response(ABUSEIPDB_PAYLOAD),
    ) as get:
        IPReputationService('key', timeout=3).check_ip(IP)

    assert get.call_args.kwargs['timeout'] == 3


# --- response mapping -------------------------------------------------------

def test_maps_every_documented_field():
    with patch(
        'app.services.ip_reputation.requests.get',
        return_value=fake_response(ABUSEIPDB_PAYLOAD),
    ):
        result = IPReputationService('key').check_ip(IP)

    assert result['abuseConfidenceScore'] == 87
    assert result['totalReports'] == 42
    assert result['isp'] == 'Example Hosting'
    assert result['countryCode'] == 'NL'
    assert result['hostnames'] == ['host.example-hosting.test']


def test_unmapped_upstream_fields_are_dropped():
    """The response shape is a fixed contract, not a passthrough."""
    with patch(
        'app.services.ip_reputation.requests.get',
        return_value=fake_response(ABUSEIPDB_PAYLOAD),
    ):
        result = IPReputationService('key').check_ip(IP)

    assert 'isWhitelisted' not in result


def test_missing_fields_become_none_rather_than_raising():
    with patch(
        'app.services.ip_reputation.requests.get',
        return_value=fake_response({'data': {'ipAddress': IP}}),
    ):
        result = IPReputationService('key').check_ip(IP)

    assert result['ipAddress'] == IP
    assert result['abuseConfidenceScore'] is None
    assert result['isp'] is None


def test_empty_payload_does_not_raise():
    with patch(
        'app.services.ip_reputation.requests.get',
        return_value=fake_response({}),
    ):
        assert IPReputationService('key').check_ip(IP)['ipAddress'] is None


# --- caching ----------------------------------------------------------------

def test_second_lookup_is_served_from_cache():
    """Quota is limited; an unchanged IP must not be re-queried."""
    with patch(
        'app.services.ip_reputation.requests.get',
        return_value=fake_response(ABUSEIPDB_PAYLOAD),
    ) as get:
        service = IPReputationService('key')
        first = service.check_ip(IP)
        second = service.check_ip(IP)

    assert get.call_count == 1
    assert first == second


def test_cache_is_keyed_per_ip():
    other = '203.0.113.9'
    with patch(
        'app.services.ip_reputation.requests.get',
        return_value=fake_response(ABUSEIPDB_PAYLOAD),
    ) as get:
        service = IPReputationService('key')
        service.check_ip(IP)
        service.check_ip(other)

    assert get.call_count == 2


# --- failure handling -------------------------------------------------------

@pytest.mark.parametrize('failure', [
    requests.RequestException('network down'),
    ValueError('not json'),
])
def test_transport_failure_degrades_to_none(failure):
    """A dead or rate-limited provider must never break an analysis."""
    with patch('app.services.ip_reputation.requests.get', side_effect=failure):
        assert IPReputationService('key').check_ip(IP) is None


def test_http_error_status_degrades_to_none():
    response = fake_response({}, status=429)
    response.raise_for_status.side_effect = requests.HTTPError('429')
    with patch('app.services.ip_reputation.requests.get', return_value=response):
        assert IPReputationService('key').check_ip(IP) is None


def test_failures_are_not_cached():
    """A transient outage must not poison the cache for six hours."""
    ok = fake_response(ABUSEIPDB_PAYLOAD)
    with patch(
        'app.services.ip_reputation.requests.get',
        side_effect=[requests.RequestException('boom'), ok],
    ):
        service = IPReputationService('key')
        assert service.check_ip(IP) is None
        assert service.check_ip(IP)['abuseConfidenceScore'] == 87


def test_api_key_is_never_logged(caplog):
    """A key pasted into the UI must not end up in the server log."""
    with patch(
        'app.services.ip_reputation.requests.get',
        side_effect=requests.RequestException('boom'),
    ):
        IPReputationService('super-secret-key').check_ip(IP)

    assert 'super-secret-key' not in caplog.text
