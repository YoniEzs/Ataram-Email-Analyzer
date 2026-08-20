"""Tests for Team Cymru ASN and IP RDAP enrichment.

The Cymru query names and field orders asserted here were verified against the
live service; the tests themselves never touch the network.
"""

from unittest.mock import patch

import pytest

from app.services.dns_checker import DNSCheckerService
from app.services.ip_intel import IPIntelService, cymru_origin_name
from app.utils.cache import _cache


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


def build(txt_map, *, enable_rdap=False, enable_asn=True):
    """IPIntelService whose TXT lookups come from a fixed mapping."""
    dns_checker = DNSCheckerService(timeout=1)
    dns_checker.get_txt_records = lambda name: txt_map.get(name)  # type: ignore[method-assign]
    return IPIntelService(
        dns_checker=dns_checker, enable_rdap=enable_rdap, enable_asn=enable_asn
    )


# --- query-name construction ------------------------------------------------

def test_ipv4_origin_name_reverses_the_octets():
    assert cymru_origin_name('208.67.222.222') == (
        '222.222.67.208.origin.asn.cymru.com'
    )


def test_ipv6_origin_name_uses_reversed_nibbles():
    name = cymru_origin_name('2001:4860:4860::8888')
    assert name.endswith('.origin6.asn.cymru.com')
    nibbles = name[: -len('.origin6.asn.cymru.com')].split('.')
    assert len(nibbles) == 32
    assert ''.join(reversed(nibbles)) == '20014860486000000000000000008888'


def test_origin_name_rejects_garbage():
    assert cymru_origin_name('not-an-ip') is None


# --- record parsing ---------------------------------------------------------

ORIGIN = '15169 | 8.8.8.0/24 | US | arin | 2023-12-28'
AS_RECORD = '15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US'


def test_parses_origin_and_asn_records():
    svc = build({
        '8.8.8.8.origin.asn.cymru.com': [ORIGIN],
        'AS15169.asn.cymru.com': [AS_RECORD],
    })
    result = svc.lookup('8.8.8.8')
    assert result['asn'] == '15169'
    assert result['bgp_prefix'] == '8.8.8.0/24'
    assert result['country'] == 'US'
    assert result['registry'] == 'arin'
    assert result['allocated'] == '2023-12-28'
    # The AS name legitimately contains a comma, so it is taken whole.
    assert result['as_name'] == 'GOOGLE - Google LLC, US'
    assert result['trust'] == 'observed'
    assert 'team_cymru_dns' in result['source']


def test_multi_origin_prefix_yields_every_asn():
    svc = build({
        '8.8.8.8.origin.asn.cymru.com': ['15169 64500 | 8.8.8.0/24 | US | arin | 2023-12-28'],
        'AS15169.asn.cymru.com': [AS_RECORD],
    })
    result = svc.lookup('8.8.8.8')
    assert result['asns'] == ['15169', '64500']
    assert result['asn'] == '15169'


def test_longest_prefix_wins_among_overlapping_announcements():
    svc = build({
        '8.8.8.8.origin.asn.cymru.com': [
            '111 | 8.0.0.0/8 | US | arin | 1992-12-01',
            '15169 | 8.8.8.0/24 | US | arin | 2023-12-28',
        ],
        'AS15169.asn.cymru.com': [AS_RECORD],
    })
    result = svc.lookup('8.8.8.8')
    assert result['bgp_prefix'] == '8.8.8.0/24'
    assert result['asn'] == '15169'


def test_empty_fields_become_none():
    svc = build({'8.8.8.8.origin.asn.cymru.com': ['15169 |  | US | arin | ']})
    result = svc.lookup('8.8.8.8')
    assert result['bgp_prefix'] is None
    assert result['allocated'] is None
    assert result['country'] == 'US'


def test_short_record_does_not_raise():
    svc = build({'8.8.8.8.origin.asn.cymru.com': ['15169 | 8.8.8.0/24']})
    result = svc.lookup('8.8.8.8')
    assert result['asn'] == '15169'
    assert result['country'] is None


@pytest.mark.parametrize('record', [
    'total garbage',
    '| | | |',
    'AS15169 | 8.8.8.0/24 | US | arin | 2023-12-28',   # non-numeric ASN
    '99999999999 | 8.8.8.0/24 | US | arin | 2023',      # ASN out of range
    '0 | 8.8.8.0/24 | US | arin | 2023',                # ASN zero
])
def test_unusable_origin_records_yield_no_result(record):
    svc = build({'8.8.8.8.origin.asn.cymru.com': [record]})
    assert svc.lookup('8.8.8.8') is None


def test_missing_dns_answer_yields_no_result():
    assert build({}).lookup('8.8.8.8') is None


@pytest.mark.parametrize('ip', ['192.168.1.1', '127.0.0.1', 'not-an-ip', ''])
def test_non_public_addresses_are_rejected(ip):
    assert build({'x': ['y']}).lookup(ip) is None


# --- RDAP -------------------------------------------------------------------

RDAP_IP_PAYLOAD = {
    'handle': 'NET-8-8-8-0-1',
    'name': 'GOGL',
    'startAddress': '8.8.8.0',
    'endAddress': '8.8.8.255',
    'cidr0_cidrs': [{'v4prefix': '8.8.8.0', 'length': 24}],
    'ipVersion': 'v4',
    'type': 'ALLOCATION',
    'country': 'US',
    'status': ['active'],
    'events': [{'eventAction': 'registration', 'eventDate': '2023-12-28T00:00:00Z'}],
    'entities': [{
        'roles': ['abuse'],
        'vcardArray': ['vcard', [
            ['fn', {}, 'text', 'Abuse Desk'],
            ['email', {}, 'text', 'abuse@example.net'],
        ]],
    }],
}


def test_rdap_extracts_network_and_abuse_contact():
    svc = build({}, enable_rdap=True, enable_asn=False)
    with patch('app.services.ip_intel.get_json', return_value=RDAP_IP_PAYLOAD):
        result = svc.lookup('8.8.8.8')
    rdap = result['rdap']
    assert rdap['name'] == 'GOGL'
    assert rdap['cidr'] == '8.8.8.0/24'
    assert rdap['type'] == 'ALLOCATION'
    assert rdap['abuse_email'] == 'abuse@example.net'
    assert rdap['abuse_name'] == 'Abuse Desk'
    assert rdap['registration_date'] == '2023-12-28T00:00:00Z'
    assert result['source'] == 'rdap_ip'


def test_abuse_contact_is_found_in_nested_entities():
    payload = {
        'handle': 'NET-1',
        'entities': [{
            'roles': ['registrant'],
            'entities': [{
                'roles': ['abuse'],
                'vcardArray': ['vcard', [['email', {}, 'text', 'nested@example.net']]],
            }],
        }],
    }
    svc = build({}, enable_rdap=True, enable_asn=False)
    with patch('app.services.ip_intel.get_json', return_value=payload):
        result = svc.lookup('8.8.8.8')
    assert result['rdap']['abuse_email'] == 'nested@example.net'


def test_asn_survives_when_rdap_is_unreachable():
    """Cymru is DNS-only, so it still answers where outbound HTTPS is blocked."""
    svc = build(
        {
            '8.8.8.8.origin.asn.cymru.com': [ORIGIN],
            'AS15169.asn.cymru.com': [AS_RECORD],
        },
        enable_rdap=True,
    )
    with patch('app.services.ip_intel.get_json', return_value=None):
        result = svc.lookup('8.8.8.8')
    assert result['asn'] == '15169'
    assert result['rdap'] is None
    assert result['source'] == 'team_cymru_dns'


def test_both_sources_failing_yields_none():
    svc = build({}, enable_rdap=True)
    with patch('app.services.ip_intel.get_json', return_value=None):
        assert svc.lookup('8.8.8.8') is None


def test_disabled_sources_are_not_consulted():
    svc = build({'8.8.8.8.origin.asn.cymru.com': [ORIGIN]},
                enable_rdap=False, enable_asn=False)
    with patch('app.services.ip_intel.get_json') as mock_get:
        assert svc.lookup('8.8.8.8') is None
    mock_get.assert_not_called()
