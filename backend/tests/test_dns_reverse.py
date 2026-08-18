"""Tests for reverse DNS and forward-confirmed reverse DNS."""

from unittest.mock import patch

import pytest

import dns.exception

from app.services.dns_checker import DNSCheckerService
from app.utils.cache import _cache

PUBLIC_IP = '93.184.216.34'
OTHER_IP = '198.18.0.1'
PUBLIC_IPV6 = '2606:2800:220:1:248:1893:25c8:1946'


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


class _Rdata:
    """Stand-in for a dnspython rdata object."""

    def __init__(self, value):
        self.target = value
        self.address = value
        self.exchange = value

    def __str__(self):
        return str(self.target)


def fake_resolver(mapping):
    """Resolve from a {(name_suffix, rdtype): [values]} mapping.

    A missing entry raises NoAnswer — an *authoritative* empty answer. Tests
    for resolver outages raise a generic DNSException explicitly.
    """
    def _resolve(name, rdtype, lifetime=None):
        key = (str(name).rstrip('.').lower(), rdtype)
        if key not in mapping:
            raise dns.resolver.NoAnswer()
        return [_Rdata(v) for v in mapping[key]]
    return _resolve


def test_forward_confirmed_reverse_dns_passes():
    mapping = {
        ('34.216.184.93.in-addr.arpa', 'PTR'): ['mail.sender.example.'],
        ('mail.sender.example', 'A'): [PUBLIC_IP],
    }
    with patch('app.services.dns_checker.dns.resolver.resolve', fake_resolver(mapping)):
        result = DNSCheckerService(timeout=1).reverse_dns_details(PUBLIC_IP)
    assert result['ptr_name'] == 'mail.sender.example'
    assert result['fcrdns'] == 'pass'
    assert result['forward_ips']['mail.sender.example'] == [PUBLIC_IP]


def test_fcrdns_fails_when_forward_lookup_points_elsewhere():
    mapping = {
        ('34.216.184.93.in-addr.arpa', 'PTR'): ['mail.sender.example.'],
        ('mail.sender.example', 'A'): [OTHER_IP],
    }
    with patch('app.services.dns_checker.dns.resolver.resolve', fake_resolver(mapping)):
        result = DNSCheckerService(timeout=1).reverse_dns_details(PUBLIC_IP)
    assert result['fcrdns'] == 'fail'


def test_authoritative_absent_ptr_yields_no_ptr():
    """NoAnswer/NXDOMAIN mean the address genuinely has no PTR record."""
    with patch('app.services.dns_checker.dns.resolver.resolve', fake_resolver({})):
        result = DNSCheckerService(timeout=1).reverse_dns_details(PUBLIC_IP)
    assert result['fcrdns'] == 'no_ptr'
    assert result['ptr_name'] is None


def test_resolver_outage_yields_lookup_failed_not_evidence():
    """A timeout must never masquerade as a fact about the sender.

    no_ptr is a (low) observation; lookup_failed is an infrastructure state.
    Conflating them would let a resolver outage add observations to a report.
    """
    with patch(
        'app.services.dns_checker.dns.resolver.resolve',
        side_effect=dns.exception.Timeout(),
    ):
        result = DNSCheckerService(timeout=1).reverse_dns_details(PUBLIC_IP)
    assert result['fcrdns'] == 'lookup_failed'
    assert result['ptr_name'] is None


def test_ipv6_reverse_lookup_uses_nibble_form():
    seen = {}

    def _resolve(name, rdtype, lifetime=None):
        seen[rdtype] = str(name)
        if rdtype == 'PTR':
            return [_Rdata('ipv6.sender.example.')]
        if rdtype == 'AAAA':
            return [_Rdata(PUBLIC_IPV6)]
        raise dns.exception.DNSException('no answer')

    with patch('app.services.dns_checker.dns.resolver.resolve', _resolve):
        result = DNSCheckerService(timeout=1).reverse_dns_details(PUBLIC_IPV6)
    assert seen['PTR'].endswith('.ip6.arpa.')
    assert result['fcrdns'] == 'pass'


@pytest.mark.parametrize('ip', ['192.168.1.1', '127.0.0.1', '10.0.0.1', 'not-an-ip', ''])
def test_non_public_addresses_are_never_queried(ip):
    """An internal Received chain must not leak RFC1918 space to a resolver."""
    with patch('app.services.dns_checker.dns.resolver.resolve') as mock_resolve:
        assert DNSCheckerService(timeout=1).reverse_dns_details(ip) is None
        assert DNSCheckerService(timeout=1).get_ptr_records(ip) is None
    mock_resolve.assert_not_called()


def test_repeat_lookup_is_served_from_cache():
    mapping = {
        ('34.216.184.93.in-addr.arpa', 'PTR'): ['mail.sender.example.'],
        ('mail.sender.example', 'A'): [PUBLIC_IP],
    }
    calls = []

    def _counting(name, rdtype, lifetime=None):
        calls.append((str(name), rdtype))
        return fake_resolver(mapping)(name, rdtype, lifetime)

    service = DNSCheckerService(timeout=1)
    with patch('app.services.dns_checker.dns.resolver.resolve', _counting):
        first = service.reverse_dns_details(PUBLIC_IP)
        before = len(calls)
        second = service.reverse_dns_details(PUBLIC_IP)
    assert first == second
    assert len(calls) == before


def test_forward_confirmation_only_checks_the_primary_ptr_name():
    """FCrDNS is conventionally about *the* PTR name, and this bounds cost."""
    mapping = {
        ('34.216.184.93.in-addr.arpa', 'PTR'): [
            'a.example.', 'b.example.', 'c.example.', 'd.example.',
        ],
    }
    looked_up = []

    def _resolve(name, rdtype, lifetime=None):
        if rdtype in ('A', 'AAAA'):
            looked_up.append(str(name))
        return fake_resolver(mapping)(name, rdtype, lifetime)

    with patch('app.services.dns_checker.dns.resolver.resolve', _resolve):
        DNSCheckerService(timeout=1).reverse_dns_details(PUBLIC_IP)
    assert {n for n in looked_up} == {'a.example'}


def test_mx_records_are_returned_as_hostnames():
    mapping = {('sender.example', 'MX'): ['mx1.sender.example.', 'mx2.sender.example.']}
    with patch('app.services.dns_checker.dns.resolver.resolve', fake_resolver(mapping)):
        result = DNSCheckerService(timeout=1).get_mx_records('sender.example')
    assert result == ['mx1.sender.example', 'mx2.sender.example']


def test_authoritative_missing_mx_returns_empty_list():
    """No MX records is evidence ([]); only a resolver failure is None.

    The analyzer scores sender_domain_has_no_mx from [], so the distinction is
    what keeps a DNS outage from fabricating +4 points on a clean message.
    """
    with patch('app.services.dns_checker.dns.resolver.resolve', fake_resolver({})):
        assert DNSCheckerService(timeout=1).get_mx_records('sender.example') == []


def test_mx_resolver_failure_returns_none():
    with patch(
        'app.services.dns_checker.dns.resolver.resolve',
        side_effect=dns.exception.Timeout(),
    ):
        assert DNSCheckerService(timeout=1).get_mx_records('sender.example') is None


def test_txt_lookup_cache_key_does_not_collide_with_new_types():
    """TXT uses dns:<name>; the new record types use distinct prefixes."""
    mapping = {
        ('sender.example', 'MX'): ['mx1.sender.example.'],
    }
    service = DNSCheckerService(timeout=1)
    with patch('app.services.dns_checker.dns.resolver.resolve', fake_resolver(mapping)):
        service.get_mx_records('sender.example')
        # A TXT query for the same name must not be served the MX answer.
        assert service.get_txt_records('sender.example') is None
