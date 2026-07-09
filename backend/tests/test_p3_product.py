"""
Tests for the P3 product layer: OpenAPI + /api/v1, frontend resilience
markers, i18n, and print support.

Frontend checks are static contract tests over the shipped JS/CSS/HTML —
they pin behavior-critical markers without a browser runtime.
"""

import json
import re
from pathlib import Path

FRONTEND_SRC = Path(__file__).resolve().parents[2] / "frontend" / "src"


# ---------------------------------------------------------------------------
# OpenAPI + versioned API
# ---------------------------------------------------------------------------

def test_openapi_document_is_served_and_valid(client):
    response = client.get('/api/openapi.json')
    assert response.status_code == 200
    spec = response.get_json()
    assert spec['openapi'].startswith('3.')
    assert set(spec['paths']) == {'/analyze', '/analyze/url', '/check/domain', '/check/ip'}
    assert {s['url'] for s in spec['servers']} == {'/api/v1', '/api'}


def test_v1_alias_serves_same_endpoints(client):
    assert client.get('/api/v1/openapi.json').status_code == 200

    response = client.post('/api/v1/check/domain', json={'domain': 'localhost'})
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Invalid domain'

    response = client.post('/api/v1/analyze', data={}, content_type='multipart/form-data')
    assert response.status_code == 400
    assert response.get_json()['error'] == 'No file provided'


# ---------------------------------------------------------------------------
# Frontend resilience contract
# ---------------------------------------------------------------------------

def test_api_js_has_timeout_and_progress_support():
    api_js = (FRONTEND_SRC / "js" / "api.js").read_text(encoding="utf-8")
    assert 'xhr.timeout = CONFIG.REQUEST_TIMEOUT_MS' in api_js
    assert 'upload.onprogress' in api_js
    assert 'AbortController' in api_js
    assert 'xhr.status === 429' in api_js


def test_config_js_defines_request_bounds():
    config_js = (FRONTEND_SRC / "js" / "config.js").read_text(encoding="utf-8")
    assert 'REQUEST_TIMEOUT_MS' in config_js
    assert 'HEALTH_TIMEOUT_MS' in config_js


# ---------------------------------------------------------------------------
# i18n contract
# ---------------------------------------------------------------------------

def test_i18n_translations_cover_data_i18n_keys():
    html = (FRONTEND_SRC / "index.html").read_text(encoding="utf-8")
    i18n_js = (FRONTEND_SRC / "js" / "i18n.js").read_text(encoding="utf-8")

    keys = set(re.findall(r'data-i18n(?:-placeholder)?="([^"]+)"', html))
    assert keys, 'index.html must declare data-i18n attributes'

    # Every static key declared in the HTML must have a Hebrew translation
    missing = {key for key in keys if f"'{key}'" not in i18n_js and f'"{key}"' not in i18n_js}
    assert not missing, f'Missing Hebrew translations for: {sorted(missing)}'


def test_i18n_covers_risk_levels_and_verdicts():
    i18n_js = (FRONTEND_SRC / "js" / "i18n.js").read_text(encoding="utf-8")
    for key in ('low', 'medium', 'high', 'critical'):
        assert f"'{key}'" in i18n_js
    # Verdict strings must match the backend exactly
    from app.services.email_analyzer import EmailAnalyzerService
    service = object.__new__(EmailAnalyzerService)
    for level in ('low', 'medium', 'high', 'critical'):
        verdict = service._get_verdict(level)
        assert verdict in i18n_js, f'Verdict not translated: {verdict}'


def test_results_js_uses_translation_helper():
    results_js = (FRONTEND_SRC / "js" / "results.js").read_text(encoding="utf-8")
    for marker in ("${t('Email Headers')}", "${t('Authentication')}", "${t('Suspicious Indicators')}"):
        assert marker in results_js


def test_keyword_data_files_are_valid_json():
    data_dir = Path(__file__).resolve().parents[1] / "app" / "data" / "phishing_keywords"
    files = list(data_dir.glob('*.json'))
    assert {f.name for f in files} >= {'en.json', 'he.json'}
    for path in files:
        data = json.loads(path.read_text(encoding='utf-8'))
        assert set(data) == {'urgent_phrases', 'generic_greetings', 'credential_keywords'}


# ---------------------------------------------------------------------------
# Print support contract
# ---------------------------------------------------------------------------

def test_styles_include_print_rules():
    styles = (FRONTEND_SRC / "css" / "styles.css").read_text(encoding="utf-8")
    assert '@media print' in styles
    assert 'break-inside: avoid' in styles


def test_ui_js_wires_print_button():
    ui_js = (FRONTEND_SRC / "js" / "ui.js").read_text(encoding="utf-8")
    assert 'initPrintButton' in ui_js
    assert 'window.print()' in ui_js
