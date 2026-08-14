"""
Tests for /api/analyze/url, /api/check/domain, /api/check/ip
covering both success paths and error/edge-case scenarios.
"""
import json
import pytest
from unittest.mock import patch, MagicMock
from app import create_app
from app.config import TestingConfig


# ---------------------------------------------------------------------------
# /api/analyze/url
# ---------------------------------------------------------------------------

class TestAnalyzeUrl:
    def test_missing_body_returns_400(self, client):
        """No body at all → 400, not 500."""
        response = client.post('/api/analyze/url', content_type='application/json')
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == 'Missing URL'

    def test_wrong_content_type_returns_400(self, client):
        """Non-JSON Content-Type must not leak a 415→500; must return 400."""
        response = client.post(
            '/api/analyze/url',
            data='url=http://example.com',
            content_type='application/x-www-form-urlencoded'
        )
        assert response.status_code == 400

    def test_missing_url_key_returns_400(self, client):
        response = client.post(
            '/api/analyze/url',
            data=json.dumps({'sender_domain': 'example.com'}),
            content_type='application/json'
        )
        assert response.status_code == 400
        assert response.get_json()['error'] == 'Missing URL'

    def test_valid_url_returns_200(self, client):
        mock_result = {'url': 'http://example.com', 'risk': 'low'}
        with patch('app.services.url_analyzer.URLAnalyzerService.analyze_single_url',
                   return_value=mock_result):
            response = client.post(
                '/api/analyze/url',
                data=json.dumps({'url': 'http://example.com'}),
                content_type='application/json'
            )
        assert response.status_code == 200
        assert response.get_json()['url'] == 'http://example.com'


# ---------------------------------------------------------------------------
# /api/check/domain
# ---------------------------------------------------------------------------

class TestCheckDomain:
    def test_missing_body_returns_400(self, client):
        response = client.post('/api/check/domain', content_type='application/json')
        assert response.status_code == 400
        assert response.get_json()['error'] == 'Missing domain'

    def test_wrong_content_type_returns_400(self, client):
        response = client.post(
            '/api/check/domain',
            data='domain=example.com',
            content_type='application/x-www-form-urlencoded'
        )
        assert response.status_code == 400

    def test_missing_domain_key_returns_400(self, client):
        response = client.post(
            '/api/check/domain',
            data=json.dumps({'other': 'value'}),
            content_type='application/json'
        )
        assert response.status_code == 400
        assert response.get_json()['error'] == 'Missing domain'

    def test_valid_domain_returns_200(self, client):
        spf_mock = {'result': 'pass', 'record': 'v=spf1 include:_spf.google.com ~all'}
        dmarc_mock = {'result': 'pass', 'record': 'v=DMARC1; p=reject'}
        whois_mock = {'registrar': 'Example Registrar', 'creation_date': '2000-01-01'}

        with patch('app.services.dns_checker.DNSCheckerService.check_spf', return_value=spf_mock), \
             patch('app.services.dns_checker.DNSCheckerService.check_dmarc', return_value=dmarc_mock), \
             patch('app.services.whois_service.WhoisService.lookup', return_value=whois_mock):
            response = client.post(
                '/api/check/domain',
                data=json.dumps({'domain': 'example.com'}),
                content_type='application/json'
            )

        assert response.status_code == 200
        data = response.get_json()
        assert data['domain'] == 'example.com'
        assert 'spf' in data
        assert 'dmarc' in data


# ---------------------------------------------------------------------------
# /api/check/ip
# ---------------------------------------------------------------------------

class TestCheckIp:
    def test_missing_body_returns_400(self, client):
        response = client.post('/api/check/ip', content_type='application/json')
        assert response.status_code == 400
        assert response.get_json()['error'] == 'Missing IP'

    def test_wrong_content_type_returns_400(self, client):
        response = client.post(
            '/api/check/ip',
            data='ip=1.2.3.4',
            content_type='application/x-www-form-urlencoded'
        )
        assert response.status_code == 400

    def test_missing_ip_key_returns_400(self, client):
        response = client.post(
            '/api/check/ip',
            data=json.dumps({'other': 'value'}),
            content_type='application/json'
        )
        assert response.status_code == 400
        assert response.get_json()['error'] == 'Missing IP'

    def test_no_api_key_returns_400(self):
        """When no AbuseIPDB key is configured or provided → 400, not 500."""
        app = create_app(TestingConfig)
        app.config['ABUSEIPDB_KEY'] = None
        with app.test_client() as c:
            response = c.post(
                '/api/check/ip',
                data=json.dumps({'ip': '1.2.3.4'}),
                content_type='application/json'
            )
        assert response.status_code == 400
        assert response.get_json()['error'] == 'No API key'

    def test_valid_ip_with_key_returns_200(self):
        """The key is read from server config, so it must be set on the app."""
        mock_result = {'ip': '1.2.3.4', 'abuseConfidenceScore': 0}
        app = create_app(TestingConfig)
        app.config['ABUSEIPDB_KEY'] = 'test-key'
        with patch('app.services.ip_reputation.IPReputationService.check_ip',
                   return_value=mock_result):
            with app.test_client() as c:
                response = c.post(
                    '/api/check/ip',
                    data=json.dumps({'ip': '1.2.3.4'}),
                    content_type='application/json'
                )
        assert response.status_code == 200
        assert response.get_json()['ip'] == '1.2.3.4'

    def test_client_supplied_key_is_ignored(self):
        """A key in the request body must never be honoured — server config only."""
        app = create_app(TestingConfig)
        app.config['ABUSEIPDB_KEY'] = None
        with app.test_client() as c:
            response = c.post(
                '/api/check/ip',
                data=json.dumps({'ip': '1.2.3.4', 'abuseipdb_key': 'attacker-key'}),
                content_type='application/json'
            )
        assert response.status_code == 400
        assert response.get_json()['error'] == 'No API key'


# ---------------------------------------------------------------------------
# /api/analyze  — error scenarios not covered by test_app.py
# ---------------------------------------------------------------------------

class TestAnalyzeEmailErrors:
    def test_no_file_returns_400(self, client):
        response = client.post('/api/analyze')
        assert response.status_code == 400
        assert response.get_json()['error'] == 'No file provided'

    def test_wrong_extension_returns_400(self, client):
        from io import BytesIO
        response = client.post(
            '/api/analyze',
            data={'emailfile': (BytesIO(b'dummy content'), 'test.txt')},
            content_type='multipart/form-data'
        )
        assert response.status_code == 400
        assert response.get_json()['error'] == 'Invalid file type'

    def test_empty_filename_returns_400(self, client):
        from io import BytesIO
        response = client.post(
            '/api/analyze',
            data={'emailfile': (BytesIO(b''), '')},
            content_type='multipart/form-data'
        )
        assert response.status_code == 400
