"""
Tests for the P1 production-hardening changes: parallel lookups,
cache backend selection, and logging configuration.
"""

import logging
import time

import pytest

from app import create_app
from app.config import TestingConfig
from app.services.email_analyzer import EmailAnalyzerService
from app.utils.cache import RedisCache, TTLCache, _create_cache


# ---------------------------------------------------------------------------
# Parallel external lookups
# ---------------------------------------------------------------------------

class SlowDNS:
    def __init__(self, delay):
        self.delay = delay

    def check_spf(self, domain):
        time.sleep(self.delay)
        return 'v=spf1 ~all'

    def check_dmarc(self, domain):
        time.sleep(self.delay)
        return 'v=DMARC1; p=none'

    def check_dkim(self, domain, selector):
        time.sleep(self.delay)
        return 'v=DKIM1; p=key'


class SlowWhois:
    def __init__(self, delay):
        self.delay = delay

    def lookup(self, domain):
        time.sleep(self.delay)
        return {'domain': domain}


def make_service():
    service = EmailAnalyzerService(enable_whois=False, enable_abuseipdb=False)
    return service


def test_lookups_run_concurrently():
    service = make_service()
    service.dns_checker = SlowDNS(0.25)
    service.whois_service = SlowWhois(0.25)

    start = time.monotonic()
    results = service._run_external_lookups('example.com', None, 'example.com', 's1')
    elapsed = time.monotonic() - start

    assert results['spf'] == 'v=spf1 ~all'
    assert results['dmarc'] == 'v=DMARC1; p=none'
    assert results['dkim'] == 'v=DKIM1; p=key'
    assert results['whois'] == {'domain': 'example.com'}
    # Four 0.25s lookups sequentially would take ~1s.
    assert elapsed < 0.8


def test_single_lookup_failure_does_not_break_the_batch():
    class ExplodingWhois:
        def lookup(self, domain):
            raise RuntimeError('boom')

    service = make_service()
    service.dns_checker = SlowDNS(0)
    service.whois_service = ExplodingWhois()

    results = service._run_external_lookups('example.com', None, None, None)

    assert results['whois'] is None
    assert results['spf'] == 'v=spf1 ~all'


def test_global_deadline_bounds_a_hung_lookup():
    service = make_service()
    service.dns_checker = SlowDNS(0)
    service.whois_service = SlowWhois(10)
    service.lookup_deadline = 0.5

    start = time.monotonic()
    results = service._run_external_lookups('example.com', None, None, None)
    elapsed = time.monotonic() - start

    assert results['whois'] is None
    assert elapsed < 3


def test_no_jobs_returns_empty_dict():
    service = make_service()
    assert service._run_external_lookups(None, None, None, None) == {}


# ---------------------------------------------------------------------------
# Cache backend selection
# ---------------------------------------------------------------------------

def test_cache_defaults_to_in_memory(monkeypatch):
    monkeypatch.delenv('CACHE_REDIS_URL', raising=False)
    monkeypatch.delenv('REDIS_URL', raising=False)
    assert isinstance(_create_cache(), TTLCache)


def test_cache_uses_redis_when_url_set(monkeypatch):
    monkeypatch.setenv('CACHE_REDIS_URL', 'redis://localhost:1/0')
    assert isinstance(_create_cache(), RedisCache)


def test_redis_cache_degrades_to_miss_on_connection_error():
    # Port 1 is never a live Redis — operations must not raise.
    cache = RedisCache('redis://localhost:1/0')
    cache.set('k', {'a': 1}, 60)
    assert cache.get('k') is None


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

class ProdLikeConfig(TestingConfig):
    TESTING = False
    DEBUG = False
    SECRET_KEY = 'prod-like-key-for-tests'


class ProdLikeFileLogConfig(ProdLikeConfig):
    LOG_TO_FILE = True


@pytest.fixture
def in_tmp_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _handler_types(app):
    return [type(h).__name__ for h in app.logger.handlers]


def test_production_logs_to_stdout_by_default(in_tmp_dir):
    app = create_app(ProdLikeConfig)
    assert 'StreamHandler' in _handler_types(app)
    assert 'RotatingFileHandler' not in _handler_types(app)
    assert not (in_tmp_dir / 'logs').exists()


def test_file_logging_is_opt_in(in_tmp_dir):
    app = create_app(ProdLikeFileLogConfig)
    assert 'StreamHandler' in _handler_types(app)
    assert 'RotatingFileHandler' in _handler_types(app)
    assert (in_tmp_dir / 'logs' / 'email_analyzer.log').exists()


def test_log_level_config_is_respected(in_tmp_dir):
    class WarnConfig(ProdLikeConfig):
        LOG_LEVEL = 'WARNING'

    app = create_app(WarnConfig)
    assert app.logger.level == logging.WARNING
