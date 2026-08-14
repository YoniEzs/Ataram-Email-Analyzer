"""
Security regression tests.

Each test here corresponds to a specific weakness found while hardening the
service for public exposure. They are regression tests in the strict sense: the
assertions below fail against the code as it stood before that work.
"""
import io
import json

import pytest

from app import create_app, limiter
from app.config import TestingConfig
from app.utils.cache import TTLCache, MISS
from app.utils.net_guard import (
    is_public_domain,
    is_public_ip,
    is_safe_dns_query_name,
    is_safe_dkim_selector,
    validate_domain_input,
    validate_ip_input,
    validate_url_input,
)
from app.utils.validators import allowed_file, validate_email_file, safe_display_filename


MINIMAL_EML = (
    b"From: sender@example.com\r\n"
    b"To: recipient@example.com\r\n"
    b"Subject: Test\r\n"
    b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    b"\r\n"
    b"Body text\r\n"
)


@pytest.fixture
def rate_limited_app():
    """An app with rate limiting on, and a limiter reset so counts start clean."""
    class RateLimitedConfig(TestingConfig):
        RATELIMIT_ENABLED = True

    app = create_app(RateLimitedConfig)
    with app.app_context():
        limiter.reset()
    yield app
    with app.app_context():
        limiter.reset()


# ---------------------------------------------------------------------------
# Rate limiting
#
# Before hardening, @limiter.limit sat ABOVE @bp.route. Flask's route decorator
# registers the function it is handed and returns it, so the registered view was
# the undecorated one and every limit was silently inert: 14 requests against a
# "10 per minute" endpoint all returned 200.
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_analyze_limit_is_actually_enforced(self, rate_limited_app):
        client = rate_limited_app.test_client()
        statuses = [client.post('/api/analyze').status_code for _ in range(14)]
        assert 429 in statuses, (
            'No 429 in 14 requests against a 10/minute limit — the limit is not '
            'being applied (check that @bp.route is the outermost decorator).'
        )
        assert statuses.count(429) >= 4

    def test_rate_limit_response_is_json_with_retry_after(self, rate_limited_app):
        client = rate_limited_app.test_client()
        response = None
        for _ in range(14):
            response = client.post('/api/analyze')
            if response.status_code == 429:
                break
        assert response.status_code == 429
        assert response.headers['Retry-After'] == '60'
        assert response.get_json()['error'] == 'Rate limit exceeded'

    def test_health_endpoint_is_exempt(self, rate_limited_app):
        client = rate_limited_app.test_client()
        statuses = [client.get('/health').status_code for _ in range(40)]
        assert set(statuses) == {200}

    def test_separate_clients_get_separate_buckets(self, rate_limited_app):
        """
        Behind a proxy every request arrives from the proxy's address. Without
        ProxyFix the limiter keys on that one address, so a single busy client
        locks out everybody else.
        """
        client = rate_limited_app.test_client()

        for _ in range(14):
            client.post('/api/analyze', headers={'X-Forwarded-For': '203.0.113.10'})

        other = client.post('/api/analyze', headers={'X-Forwarded-For': '203.0.113.99'})
        assert other.status_code != 429, 'One client exhausting its quota blocked another'

    def test_client_cannot_escape_its_bucket_by_spoofing_forwarded_for(self, rate_limited_app):
        """
        ProxyFix must trust exactly the number of hops that exist. Trusting more
        would let a client prepend addresses and mint a fresh bucket per request.
        """
        client = rate_limited_app.test_client()

        for _ in range(14):
            client.post('/api/analyze', headers={'X-Forwarded-For': '203.0.113.10'})

        spoofed = client.post(
            '/api/analyze',
            headers={'X-Forwarded-For': '198.51.100.7, 203.0.113.10'},
        )
        assert spoofed.status_code == 429, 'Prepending a hop to X-Forwarded-For evaded the limit'


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    def test_csp_present_and_blocks_inline_script(self, client):
        csp = client.get('/health').headers.get('Content-Security-Policy')
        assert csp, 'No Content-Security-Policy header'
        assert "script-src 'self'" in csp
        # The results renderer builds HTML from untrusted email content, so an
        # inline-script escape hatch would defeat the point of the policy.
        assert "'unsafe-inline'" not in csp.split('script-src')[1].split(';')[0]
        assert "'unsafe-eval'" not in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'none'" in csp

    def test_core_headers_present(self, client):
        headers = client.get('/health').headers
        assert headers['X-Frame-Options'] == 'DENY'
        assert headers['X-Content-Type-Options'] == 'nosniff'
        assert headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
        assert headers['Cross-Origin-Opener-Policy'] == 'same-origin'
        assert 'geolocation=()' in headers['Permissions-Policy']

    def test_analysis_responses_are_not_cacheable(self, client):
        """Results are derived from a user's private email."""
        assert client.get('/health').headers['Cache-Control'] == 'no-store'

    def test_deprecated_xss_filter_is_disabled(self, client):
        assert client.get('/health').headers['X-XSS-Protection'] == '0'

    def test_hsts_absent_without_https(self, client):
        assert 'Strict-Transport-Security' not in client.get('/health').headers

    def test_hsts_present_when_enabled(self):
        class HstsConfig(TestingConfig):
            ENABLE_HSTS = True

        app = create_app(HstsConfig)
        headers = app.test_client().get('/health').headers
        assert 'max-age=31536000' in headers['Strict-Transport-Security']
        assert 'includeSubDomains' in headers['Strict-Transport-Security']


# ---------------------------------------------------------------------------
# Attack surface reduction
# ---------------------------------------------------------------------------

class TestUtilityEndpointGate:
    def test_utility_endpoints_hidden_by_default(self):
        """
        These endpoints turn a cheap request into DNS/WHOIS/third-party traffic
        from this server, and the frontend never calls them.
        """
        class DefaultConfig(TestingConfig):
            ENABLE_UTILITY_ENDPOINTS = False

        client = create_app(DefaultConfig).test_client()
        for path, payload in [
            ('/api/check/domain', {'domain': 'example.com'}),
            ('/api/check/ip', {'ip': '8.8.8.8'}),
            ('/api/analyze/url', {'url': 'https://example.com'}),
        ]:
            response = client.post(path, json=payload)
            assert response.status_code == 404, f'{path} reachable while disabled'

    def test_analyze_endpoint_stays_available(self):
        class DefaultConfig(TestingConfig):
            ENABLE_UTILITY_ENDPOINTS = False

        client = create_app(DefaultConfig).test_client()
        assert client.post('/api/analyze').status_code == 400


# ---------------------------------------------------------------------------
# SSRF / internal-recon protection
# ---------------------------------------------------------------------------

class TestInternalTargetRejection:
    @pytest.mark.parametrize('domain', [
        'localhost',
        'router.local',
        'backup.corp',
        'db.internal',
        'host.home.arpa',
        'service.lan',
        '127.0.0.1',
        '192.168.1.1',
        '169.254.169.254',
        'metadata.google.internal',
        'sketchy.onion',
    ])
    def test_internal_domains_rejected_by_api(self, client, domain):
        response = client.post('/api/check/domain', json={'domain': domain})
        assert response.status_code == 400, f'{domain} accepted for lookup'

    @pytest.mark.parametrize('ip', [
        '127.0.0.1',
        '169.254.169.254',   # cloud instance metadata
        '10.0.0.5',
        '172.16.0.1',
        '192.168.1.1',
        '0.0.0.0',
        '::1',
        'fd00::1',
    ])
    def test_non_public_ips_rejected_by_api(self, client, ip):
        response = client.post('/api/check/ip', json={'ip': ip})
        assert response.status_code == 400, f'{ip} accepted for lookup'

    def test_public_domain_accepted(self):
        assert is_public_domain('example.com')
        assert is_public_domain('mail.sub.example.co.uk')

    def test_public_ip_accepted(self):
        assert is_public_ip('8.8.8.8')
        assert is_public_ip('2001:4860:4860::8888')

    @pytest.mark.parametrize('value', [None, 123, {'a': 1}, ['x'], True])
    def test_non_string_inputs_rejected(self, client, value):
        """A non-string body value must be a 400, never a 500."""
        assert client.post('/api/check/domain', json={'domain': value}).status_code == 400
        assert client.post('/api/check/ip', json={'ip': value}).status_code == 400
        assert client.post('/api/analyze/url', json={'url': value}).status_code == 400

    def test_oversized_field_rejected(self, client):
        response = client.post('/api/check/domain', json={'domain': 'a' * 5000})
        assert response.status_code == 400

    def test_oversized_json_body_rejected(self, client):
        response = client.post(
            '/api/analyze/url',
            data=json.dumps({'url': 'https://example.com', 'pad': 'x' * 20000}),
            content_type='application/json',
        )
        assert response.status_code == 413


class TestDnsQueryNameGuard:
    def test_authentication_record_names_are_queryable(self):
        """
        The hostname pattern rejects underscore labels, so validating these with
        it made every DMARC and DKIM lookup silently return nothing.
        """
        assert is_safe_dns_query_name('_dmarc.example.com')
        assert is_safe_dns_query_name('selector1._domainkey.example.com')

    def test_internal_names_still_rejected(self):
        assert not is_safe_dns_query_name('_dmarc.internal')
        assert not is_safe_dns_query_name('_dmarc.router.local')
        assert not is_safe_dns_query_name('localhost')

    @pytest.mark.parametrize('selector', [
        'evil.attacker.com',      # would splice extra labels into the query
        'a' * 64,                 # over the label length limit
        '-leading-hyphen',
        'has space',
        '',
    ])
    def test_hostile_dkim_selectors_rejected(self, selector):
        assert not is_safe_dkim_selector(selector)

    def test_ordinary_dkim_selector_accepted(self):
        assert is_safe_dkim_selector('selector1')
        assert is_safe_dkim_selector('s20230601')

    def test_selector_parsed_from_header_is_validated(self):
        from app.services.dns_checker import DNSCheckerService

        checker = DNSCheckerService()
        assert checker.parse_dkim_selector('v=1; s=selector1; d=example.com') == 'selector1'
        # A selector carrying extra labels must be discarded, not queried.
        assert checker.parse_dkim_selector('v=1; s=evil.attacker.com; d=x.com') is None


class TestInputValidators:
    def test_validate_domain_normalises(self):
        ok, value, _ = validate_domain_input('  ExAmPle.CoM.  ')
        assert ok and value == 'example.com'

    def test_validate_ip_normalises(self):
        ok, value, _ = validate_ip_input(' 8.8.8.8 ')
        assert ok and value == '8.8.8.8'

    @pytest.mark.parametrize('url', [
        'javascript:alert(1)',
        'file:///etc/passwd',
        'data:text/html,<script>alert(1)</script>',
        'ftp://example.com',
        'https://example.com/\x00evil',
        'https://example.com/' + 'a' * 5000,
    ])
    def test_hostile_urls_rejected(self, url):
        ok, _, _ = validate_url_input(url)
        assert not ok, f'{url[:40]!r} accepted'

    def test_ordinary_url_accepted(self):
        ok, value, _ = validate_url_input('https://example.com/path?q=1')
        assert ok and value == 'https://example.com/path?q=1'


# ---------------------------------------------------------------------------
# Upload handling
# ---------------------------------------------------------------------------

class TestUploadValidation:
    @pytest.mark.parametrize('filename', [
        'evil.exe\x00.eml',          # NUL truncation
        '../../../etc/passwd.eml',   # traversal
        '..\\..\\windows\\x.eml',
        'bad\nname.eml',             # control character
        'a' * 300 + '.eml',          # overlong
        'noextension',
        'archive.zip',
        '.eml',
    ])
    def test_hostile_filenames_rejected(self, filename):
        assert not allowed_file(filename), f'{filename!r} accepted'

    def test_ordinary_filenames_accepted(self):
        assert allowed_file('message.eml')
        assert allowed_file('Outlook Item.MSG')

    def test_display_filename_never_empty(self):
        """secure_filename returns '' for all-non-ASCII names."""
        assert safe_display_filename('דואר.eml')
        assert safe_display_filename('') == 'upload.eml'
        assert '/' not in safe_display_filename('../../etc/passwd')

    def test_content_must_match_claimed_extension(self):
        ole = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 64
        ok, message = validate_email_file(ole, 'disguised.eml')
        assert not ok and 'OLE' in message

        ok, _ = validate_email_file(MINIMAL_EML, 'notreally.msg')
        assert not ok

    def test_valid_eml_accepted(self):
        ok, message = validate_email_file(MINIMAL_EML, 'message.eml')
        assert ok, message

    def test_oversized_upload_is_413_and_json_not_a_500(self):
        """
        The route wraps everything in `except Exception`, which used to swallow
        Werkzeug's RequestEntityTooLarge and report an honest 413 as a 500.
        """
        class SmallUploadConfig(TestingConfig):
            MAX_CONTENT_LENGTH = 1024

        client = create_app(SmallUploadConfig).test_client()
        response = client.post(
            '/api/analyze',
            data={'emailfile': (io.BytesIO(b'x' * 5000), 'big.eml')},
            content_type='multipart/form-data',
        )
        assert response.status_code == 413
        assert response.is_json
        assert 'error' in response.get_json()

    def test_upload_within_limit_is_accepted(self, client):
        """The size guard must not reject ordinary uploads."""
        response = client.post(
            '/api/analyze',
            data={'emailfile': (io.BytesIO(MINIMAL_EML), 'message.eml')},
            content_type='multipart/form-data',
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Error handling — nothing internal may reach the client
# ---------------------------------------------------------------------------

class TestErrorDisclosure:
    def test_unknown_route_returns_json_not_html(self, client):
        response = client.get('/api/does-not-exist')
        assert response.status_code == 404
        assert response.is_json
        assert response.get_json()['error'] == 'Not found'

    def test_wrong_method_returns_json(self, client):
        response = client.get('/api/analyze')
        assert response.status_code == 405
        assert response.is_json

    def test_server_error_hides_internals(self, client, monkeypatch):
        def explode(*_args, **_kwargs):
            raise RuntimeError('secret internal detail /srv/app/config.py line 42')

        monkeypatch.setattr(
            'app.services.email_parser.EmailParserService.parse_email', explode
        )
        response = client.post(
            '/api/analyze',
            data={'emailfile': (io.BytesIO(MINIMAL_EML), 'message.eml')},
            content_type='multipart/form-data',
        )
        assert response.status_code == 500
        body = response.get_data(as_text=True)
        assert 'secret internal detail' not in body
        assert 'Traceback' not in body
        assert 'RuntimeError' not in body


# ---------------------------------------------------------------------------
# Resource exhaustion
# ---------------------------------------------------------------------------

class TestCacheBounds:
    def test_cache_evicts_instead_of_growing(self):
        """
        The lookup cache is keyed by attacker-supplied domains. Unbounded, a
        stream of unique names grows it until the worker is OOM-killed.
        """
        cache = TTLCache(max_entries=100)
        for i in range(1000):
            cache.set(f'dns:host{i}.example.com', ['v=spf1'], 3600)
        assert len(cache) == 100

    def test_eviction_is_least_recently_used(self):
        cache = TTLCache(max_entries=3)
        cache.set('a', 1, 3600)
        cache.set('b', 2, 3600)
        cache.set('c', 3, 3600)
        cache.get('a')            # 'a' becomes most recently used
        cache.set('d', 4, 3600)   # evicts 'b', not 'a'
        assert cache.get('a') == 1
        assert cache.get('b') is None
        assert cache.get('d') == 4

    def test_cached_none_is_distinguishable_from_a_miss(self):
        """
        Negative caching only works if a stored None can be told apart from an
        absent key — otherwise every failed lookup is retried on every request.
        """
        cache = TTLCache(max_entries=10)
        assert cache.get('absent', MISS) is MISS
        cache.set('present', None, 3600)
        assert cache.get('present', MISS) is None


class TestAnalysisLimits:
    def test_url_extraction_is_capped(self):
        from app.services.url_analyzer import URLAnalyzerService

        analyzer = URLAnalyzerService()
        body = ' '.join(f'https://example{i}.com/path' for i in range(5000))
        assert len(analyzer.extract_urls(body, max_urls=100)) == 100

    def test_malformed_url_does_not_raise(self):
        """
        `parsed` was read outside the try block that produced it, so a URL that
        made urlparse raise turned into an unhandled 500.
        """
        from app.services.url_analyzer import URLAnalyzerService

        analyzer = URLAnalyzerService()
        for url in ['http://[invalid', 'https://', 'http://]:80', '']:
            result = analyzer.analyze_single_url(url)
            assert 'issues' in result

    def test_body_is_truncated_before_analysis(self):
        from app.services.email_analyzer import EmailAnalyzerService

        analyzer = EmailAnalyzerService(limits={'MAX_ANALYZED_BODY_CHARS': 1000})
        result = analyzer.analyze({
            'headers': {'sender': '', 'hops': []},
            'body_text': 'urgent ' * 500_000,
            'body_html': '',
            'attachments': [],
        })
        assert 'error' not in result

    def test_hop_list_is_capped(self):
        from app.services.email_analyzer import EmailAnalyzerService

        analyzer = EmailAnalyzerService(limits={'MAX_ANALYZED_HOPS': 10})
        result = analyzer.analyze({
            'headers': {'sender': '', 'hops': [f'from host{i}' for i in range(500)]},
            'body_text': '',
            'body_html': '',
            'attachments': [],
        })
        assert len(result['routing']['hops']) == 10
        assert result['routing']['hops_truncated'] is True

    def test_attachment_list_is_capped(self):
        from app.services.email_analyzer import EmailAnalyzerService

        analyzer = EmailAnalyzerService(limits={'MAX_ANALYZED_ATTACHMENTS': 5})
        result = analyzer.analyze({
            'headers': {'sender': '', 'hops': []},
            'body_text': '',
            'body_html': '',
            'attachments': [
                {'filename': f'f{i}.pdf', 'extension': 'pdf', 'content_type': '', 'size': 1}
                for i in range(200)
            ],
        })
        assert result['attachments']['total_count'] == 5


# ---------------------------------------------------------------------------
# Configuration safety
# ---------------------------------------------------------------------------

class TestConfigSafety:
    def test_cors_wildcard_is_impossible(self, monkeypatch):
        monkeypatch.setenv('CORS_ORIGINS', 'https://analyzer.itgalya.com,*')
        import importlib
        import app.config as config_module
        with pytest.raises(ValueError, match="must not contain"):
            importlib.reload(config_module)
        monkeypatch.delenv('CORS_ORIGINS')
        importlib.reload(config_module)

    def test_client_supplied_api_key_is_ignored_on_analyze(self, monkeypatch):
        """
        The upload endpoint must never honour a key from the request body —
        otherwise a caller can spend someone else's quota, or harvest keys.

        This asserts the OUTBOUND request, not the response. An earlier version
        checked only `status_code in (200, 400, 500)` and that the key was not
        echoed back; nothing ever echoes form fields, so it passed even with
        the fix reverted while the attacker's key was really being sent to
        AbuseIPDB.
        """
        sent_keys = []

        class FakeResponse:
            status_code = 200
            content = b'{"data": {}}'

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {'data': {}}

        def fake_get(url, params=None, headers=None, **kwargs):
            sent_keys.append((headers or {}).get('Key'))
            return FakeResponse()

        monkeypatch.setattr('app.services.ip_reputation.requests.get', fake_get)
        monkeypatch.setattr(
            'app.services.dns_checker.DNSCheckerService.check_spf', lambda *a, **k: None)
        monkeypatch.setattr(
            'app.services.dns_checker.DNSCheckerService.check_dmarc', lambda *a, **k: None)
        monkeypatch.setattr(
            'app.services.whois_service.WhoisService.lookup', lambda *a, **k: None)

        class KeyedConfig(TestingConfig):
            ABUSEIPDB_KEY = 'server-configured-key'

        app = create_app(KeyedConfig)
        # 8.8.8.8 is genuinely globally routable. A TEST-NET address such as
        # 203.0.113.9 is NOT (`ipaddress.is_global` is False), so the IP
        # reputation lookup would be skipped and every assertion below would
        # pass against an empty list — vacuous in exactly the way this rewrite
        # exists to prevent.
        eml = MINIMAL_EML.replace(
            b'\r\n\r\n',
            b'\r\nReceived: from mail.example.com (mail.example.com [8.8.8.8])\r\n\r\n',
            1,
        )
        response = app.test_client().post(
            '/api/analyze',
            data={
                'emailfile': (io.BytesIO(eml), 'message.eml'),
                'abuseipdb_key': 'ATTACKER-KEY-123',
            },
            content_type='multipart/form-data',
        )

        assert response.status_code == 200, response.get_data(as_text=True)[:200]
        assert 'ATTACKER-KEY-123' not in response.get_data(as_text=True)
        # The lookup MUST have happened, or the rest proves nothing.
        assert sent_keys, 'no AbuseIPDB call was made — the assertions below would be vacuous'
        assert sent_keys == ['server-configured-key'], (
            f'the outbound key was {sent_keys!r}; a client-supplied key must never be used'
        )
