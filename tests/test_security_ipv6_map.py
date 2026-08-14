"""
Verifies the IPv6 aggregation map in deploy/nginx.conf.

nginx has no IP arithmetic, so its rate-limit key is produced by regex
truncation over the address text. That makes it silently fragile: a pattern
that looks right can fail on the one form that matters and fall through to
`default`, which is the full address — i.e. no aggregation at all, and no
error anywhere to notice.

That is exactly what happened. The first version required a hex digit after
the fourth group and so did not match `2001:db8:dead:beef::5`, the shape a
/64-delegated host actually uses. 199 addresses in one /64 produced 199
distinct keys.

These tests read the patterns OUT OF the deployed config and re-run them, so
the config and the test cannot drift apart.
"""
import re
from pathlib import Path

import pytest


NGINX_CONF = Path(__file__).resolve().parents[2] / 'deploy' / 'nginx.conf'


def _limit_key_patterns():
    """Extract the $limit_key map's regex alternatives, in order."""
    text = NGINX_CONF.read_text(encoding='utf-8')
    block = re.search(
        r'map \$http_cf_connecting_ip \$limit_key \{(.*?)\n\}', text, re.DOTALL)
    assert block, 'the $limit_key map is missing from deploy/nginx.conf'

    patterns = []
    for line in block.group(1).splitlines():
        line = line.strip()
        if not line.startswith('~'):
            continue
        # `~^(?<name>...)rest   $name;`  -> take the regex up to the whitespace
        # separating it from the value.
        raw = line[1:].split(None, 1)[0]
        # Python spells named groups (?P<name>...) rather than (?<name>...).
        patterns.append(re.compile(raw.replace('(?<', '(?P<')))
    assert patterns, 'no regex alternatives found in the $limit_key map'
    return patterns


def nginx_limit_key(address: str) -> str:
    """Reproduce what nginx would assign as $limit_key."""
    for pattern in _limit_key_patterns():
        match = pattern.match(address)
        if match:
            return match.group(1)
    return address  # nginx `default`


class TestIPv6Aggregation:
    @pytest.mark.parametrize('address,expected', [
        # Full eight-group form.
        ('2600:1700:1234:5678:abcd:ef01:2345:6789', '2600:1700:1234:5678'),
        # The shape a /64-delegated host uses — the case the first version missed.
        ('2001:db8:dead:beef::5', '2001:db8:dead:beef'),
        ('2001:db8:dead:beef:ffff:ffff:ffff:ffff', '2001:db8:dead:beef'),
        ('2a01:4f8:c17:abcd::1', '2a01:4f8:c17:abcd'),
        # Compressed earlier: the elided groups are zeros, so the surviving
        # prefix still identifies the allocation.
        ('2001:db8:dead::beef', '2001:db8:dead'),
        ('2001:db8::1', '2001:db8'),
        ('2a01:4f8::5', '2a01:4f8'),
        ('fd00::1', 'fd00'),
    ])
    def test_address_is_truncated_to_its_allocation(self, address, expected):
        assert nginx_limit_key(address) == expected

    def test_many_addresses_in_one_slash_64_share_one_key(self):
        """The whole point: an attacker's /64 must not be 2^64 buckets."""
        addresses = [f'2001:db8:dead:beef::{i:x}' for i in range(1, 300)]
        keys = {nginx_limit_key(a) for a in addresses}
        assert len(keys) == 1, f'{len(keys)} distinct keys for one /64'

    def test_a_compressed_allocation_also_collapses(self):
        addresses = [f'2a01:4f8::{i:x}' for i in range(1, 300)]
        assert len({nginx_limit_key(a) for a in addresses}) == 1

    def test_distinct_allocations_stay_distinct(self):
        """Over-aggregation would 429 unrelated users; under-aggregation is a bypass."""
        assert nginx_limit_key('2001:db8:dead:beef::1') != nginx_limit_key('2001:db8:dead:cafe::1')
        assert nginx_limit_key('2600:1700:1:2:3:4:5:6') != nginx_limit_key('2600:1700:9:9:9:9:9:9')

    @pytest.mark.parametrize('address', [
        '203.0.113.9',
        '198.51.100.42',
        '8.8.8.8',
    ])
    def test_ipv4_is_never_truncated(self, address):
        """An IPv4 address is a meaningful unit of identity on its own."""
        assert nginx_limit_key(address) == address

    def test_no_alternative_matches_an_ipv4_address(self):
        for pattern in _limit_key_patterns():
            assert not pattern.match('203.0.113.9'), pattern.pattern


class TestBackendAgreesWithNginx:
    def test_both_layers_group_the_same_slash_64(self):
        """
        nginx truncates text; the app uses real IP arithmetic. They need not
        produce identical strings, but they must agree on what belongs together.
        """
        from app import create_app, rate_limit_key
        from app.config import TestingConfig

        app = create_app(TestingConfig)
        addresses = ['2001:db8:dead:beef::1', '2001:db8:dead:beef::ffff',
                     '2001:db8:dead:beef:1:2:3:4']

        app_keys = set()
        for address in addresses:
            with app.test_request_context(environ_base={'REMOTE_ADDR': address}):
                app_keys.add(rate_limit_key())
        nginx_keys = {nginx_limit_key(a) for a in addresses}

        assert len(app_keys) == 1, f'app split one /64 into {app_keys}'
        assert len(nginx_keys) == 1, f'nginx split one /64 into {nginx_keys}'
