"""
Tests for the WHOIS service wrapper.
"""

from datetime import datetime
from unittest.mock import patch

import pytest

from app.services.whois_service import WhoisService
from app.utils.cache import _cache


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


class FakeEntry:
    registrar = ['Example Registrar Inc.']
    creation_date = [datetime(2001, 5, 20), datetime(2001, 5, 20)]
    expiration_date = datetime(2030, 5, 20)
    updated_date = datetime(2025, 1, 1)
    status = 'clientTransferProhibited'
    name_servers = ['NS1.EXAMPLE.COM', 'NS2.EXAMPLE.COM']


def test_lookup_calls_whois_without_timeout_kwarg():
    # python-whois has no timeout parameter; passing one used to raise
    # TypeError on every lookup, silently disabling domain-age analysis.
    service = WhoisService(timeout=5)
    if service.whois_module is None:
        pytest.skip('python-whois not installed')

    with patch.object(service.whois_module, 'whois', return_value=FakeEntry()) as mock_whois:
        result = service.lookup('example.com')
        mock_whois.assert_called_once_with('example.com')

    assert result is not None
    assert result['registrar'] == 'Example Registrar Inc.'
    assert result['creation_date'] == '2001-05-20T00:00:00'
    assert result['name_servers'] == ['NS1.EXAMPLE.COM', 'NS2.EXAMPLE.COM']


def test_lookup_times_out_instead_of_hanging():
    import time

    service = WhoisService(timeout=1)
    if service.whois_module is None:
        pytest.skip('python-whois not installed')

    def slow_whois(domain):
        time.sleep(5)

    with patch.object(service.whois_module, 'whois', side_effect=slow_whois):
        start = time.monotonic()
        result = service.lookup('example.com')
        elapsed = time.monotonic() - start

    assert result is None
    assert elapsed < 3


def test_lookup_rejects_invalid_domain():
    service = WhoisService(timeout=5)
    assert service.lookup('localhost') is None
    assert service.lookup('') is None
