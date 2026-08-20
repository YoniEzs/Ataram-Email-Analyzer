"""Tests for structured Received: hop parsing.

Note on addresses: RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) are *not* globally routable, so
``is_global_ip`` rejects them. Tests that need a public sender IP use real
allocated addresses, matching the convention in the existing suite.
"""

from app.services.received_parser import (
    parse_received,
    parse_received_chain,
)

PUBLIC_IP = '93.184.216.34'
PUBLIC_IPV6 = '2001:4860:4860::8844'

POSTFIX_HOP = (
    'from mail.sender.example (mail.sender.example [93.184.216.34])\r\n'
    '\tby mx.company.example (Postfix) with ESMTPS id 4ABCDE\r\n'
    '\tfor <victim@company.example>; Mon, 06 Jul 2026 09:00:42 +0000 (UTC)'
)


def test_parses_postfix_hop_fields():
    hop = parse_received(POSTFIX_HOP)
    assert hop['from_name'] == 'mail.sender.example'
    assert hop['from_ip'] == PUBLIC_IP
    assert hop['by_name'] == 'mx.company.example'
    assert hop['with_protocol'] == 'ESMTPS'
    assert hop['id'] == '4ABCDE'
    assert hop['for_address'] == 'victim@company.example'
    assert hop['timestamp'] == '2026-07-06T09:00:42+00:00'
    assert hop['tls'] is True
    assert hop['is_public_from_ip'] is True
    assert hop['parse_error'] is False


def test_folded_header_is_unfolded_before_matching():
    folded = 'from a.example\r\n\t(a.example [93.184.216.34])\r\n by b.example; Mon, 06 Jul 2026 09:00:00 +0000'
    hop = parse_received(folded)
    assert hop['from_name'] == 'a.example'
    assert hop['by_name'] == 'b.example'
    assert hop['from_ip'] == PUBLIC_IP


def test_ipv6_literal_is_an_address_not_a_helo_name():
    hop = parse_received(
        f'from [IPv6:{PUBLIC_IPV6}] by relay.example; Mon, 06 Jul 2026 09:00:00 +0000'
    )
    assert hop['from_ip'] == PUBLIC_IPV6
    # A bracketed literal announces an address, not a HELO name; letting it
    # through as from_name would produce a bogus PTR comparison later.
    assert hop['from_name'] is None


def test_bare_ipv4_literal_is_not_a_helo_name():
    hop = parse_received(
        f'from [{PUBLIC_IP}] by relay.example; Mon, 06 Jul 2026 09:00:00 +0000'
    )
    assert hop['from_ip'] == PUBLIC_IP
    assert hop['from_name'] is None


def test_private_hop_ip_is_not_treated_as_public():
    hop = parse_received(
        'from localhost (localhost [127.0.0.1]) by relay.example;'
        ' Mon, 06 Jul 2026 09:00:00 +0000'
    )
    assert hop['from_ip'] is None
    assert hop['is_public_from_ip'] is False


def test_malformed_hop_yields_empty_fields_without_raising():
    hop = parse_received('complete garbage, not a Received header at all')
    assert hop['from_name'] is None
    assert hop['timestamp'] is None
    assert hop['parse_error'] is False


def test_missing_and_garbage_timestamps_are_tolerated():
    assert parse_received('from a.example by b.example')['timestamp'] is None
    assert parse_received('from a.example by b.example; not-a-date')['timestamp'] is None


def test_timestamp_without_offset_is_assumed_utc():
    hop = parse_received('from a.example by b.example; Mon, 06 Jul 2026 09:00:00')
    assert hop['timestamp'] == '2026-07-06T09:00:00+00:00'


def test_chain_is_indexed_newest_first_with_transit_delays():
    chain = parse_received_chain([
        'from b.example by c.example; Mon, 06 Jul 2026 09:00:42 +0000',
        'from a.example by b.example; Mon, 06 Jul 2026 09:00:00 +0000',
    ])
    assert [hop['index'] for hop in chain] == [0, 1]
    assert chain[0]['delay_seconds'] == 42
    # The oldest hop has nothing older to compare against.
    assert chain[1]['delay_seconds'] is None


def test_chain_is_bounded():
    chain = parse_received_chain(['from a.example by b.example'] * 500, max_hops=10)
    assert len(chain) == 10


def test_empty_and_none_chains_are_empty():
    assert parse_received_chain(None) == []
    assert parse_received_chain([]) == []
