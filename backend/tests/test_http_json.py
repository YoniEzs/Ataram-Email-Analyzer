"""Transport tests for the shared SSRF-resistant JSON fetcher.

These moved here from ``test_whois_service.py`` when the bounded HTTPS GET was
extracted out of ``WhoisService`` so the RDAP domain and RDAP IP lookups could
share one hardened transport.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from app.utils.cache import _cache
from app.utils.http_json import get_json, is_public_https_url


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


def _response(status=200, payload=None, location=None):
    response = MagicMock()
    response.status_code = status
    response.headers = {'Location': location} if location else {}
    response.iter_content.return_value = [json.dumps(payload or {}).encode()]
    return response


URL = 'https://rdap.example/domain/example.com'


def test_get_json_uses_bounded_https_request():
    response = _response(payload={'ok': True})
    with patch(
        'app.utils.http_json.is_public_https_url', return_value=True
    ), patch(
        'app.utils.http_json.requests.get', return_value=response
    ) as mock_get:
        result = get_json(URL, timeout=5)

    mock_get.assert_called_once()
    assert mock_get.call_args.kwargs['allow_redirects'] is False
    assert mock_get.call_args.kwargs['stream'] is True
    assert mock_get.call_args.kwargs['timeout'] == (3, 5)
    assert result == {'ok': True}


def test_timeout_returns_none_without_worker_leak():
    with patch(
        'app.utils.http_json.is_public_https_url', return_value=True
    ), patch(
        'app.utils.http_json.requests.get',
        side_effect=requests.Timeout('timed out'),
    ):
        assert get_json(URL, timeout=1) is None


def test_redirect_to_non_public_target_is_blocked():
    redirect = _response(status=302, location='https://127.0.0.1/private')
    with patch(
        'app.utils.http_json.is_public_https_url', side_effect=[True, False]
    ), patch(
        'app.utils.http_json.requests.get', return_value=redirect
    ) as mock_get:
        assert get_json(URL, timeout=5) is None
    assert mock_get.call_count == 1


def test_oversized_response_is_rejected_and_closed():
    response = _response()
    response.iter_content.return_value = [b'x' * (1024 * 1024 + 1)]
    with patch(
        'app.utils.http_json.is_public_https_url', return_value=True
    ), patch(
        'app.utils.http_json.requests.get', return_value=response
    ):
        assert get_json(URL, timeout=5) is None
    response.close.assert_called_once()


def test_404_is_treated_as_no_data():
    response = _response(status=404)
    with patch(
        'app.utils.http_json.is_public_https_url', return_value=True
    ), patch(
        'app.utils.http_json.requests.get', return_value=response
    ):
        assert get_json(URL, timeout=5) is None
    response.close.assert_called_once()


def test_redirect_loop_is_bounded():
    redirect = _response(status=302, location='https://rdap.example/next')
    with patch(
        'app.utils.http_json.is_public_https_url', return_value=True
    ), patch(
        'app.utils.http_json.requests.get', return_value=redirect
    ) as mock_get:
        assert get_json(URL, timeout=5, max_redirects=3) is None
    assert mock_get.call_count == 4


def test_unsafe_target_is_never_requested():
    with patch(
        'app.utils.http_json.is_public_https_url', return_value=False
    ), patch('app.utils.http_json.requests.get') as mock_get:
        assert get_json(URL, timeout=5) is None
    mock_get.assert_not_called()


@pytest.mark.parametrize('url', [
    'http://rdap.example/domain/x',          # not HTTPS
    'https://user:pw@rdap.example/domain/x',  # credentials
    'https://rdap.example:8443/domain/x',     # unusual port
    'https://127.0.0.1/domain/x',             # loopback
    'not-a-url',
])
def test_is_public_https_url_rejects_unsafe_targets(url):
    assert is_public_https_url(url) is False
