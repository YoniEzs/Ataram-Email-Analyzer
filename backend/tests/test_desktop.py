"""Tests for the desktop entry point (single-process UI + API)."""


import pytest

from app import desktop


@pytest.fixture()
def webui(tmp_path):
    (tmp_path / 'index.html').write_text('<!DOCTYPE html><title>Ataram</title>')
    (tmp_path / 'js').mkdir()
    (tmp_path / 'js' / 'theme-init.js').write_text('// theme')
    return tmp_path


def test_desktop_app_serves_ui_and_api(webui, monkeypatch):
    monkeypatch.setenv('FORCE_HTTPS', 'false')
    app = desktop.create_desktop_app(webui)
    client = app.test_client()

    assert client.get('/health').status_code == 200
    index = client.get('/')
    assert index.status_code == 200
    assert b'Ataram' in index.data
    assert client.get('/js/theme-init.js').status_code == 200
    # API routes registered before the static catch-all keep precedence.
    assert client.post('/api/analyze').status_code in (400, 429)


def test_desktop_csp_permits_inline_styles_but_not_inline_scripts(webui):
    app = desktop.create_desktop_app(webui)
    response = app.test_client().get('/')
    csp = response.headers.get('Content-Security-Policy', '')
    if not csp:  # header set only when flask-talisman is installed
        pytest.skip('flask-talisman not installed')
    directives = {
        part.strip().split(' ', 1)[0]: part.strip()
        for part in csp.split(';') if part.strip()
    }
    # The UI uses inline style attributes; scripts must stay external.
    assert "'unsafe-inline'" in directives['style-src']
    assert directives['script-src'] == "script-src 'self'"


def test_desktop_never_binds_beyond_loopback(webui):
    app = desktop.create_desktop_app(webui)
    assert app.config['FORCE_HTTPS'] is False
    assert app.config['RATELIMIT_ENABLED'] is False


def test_find_webui_prefers_bundled_copy(tmp_path, monkeypatch):
    bundled = tmp_path / 'app' / 'webui'
    bundled.mkdir(parents=True)
    (bundled / 'index.html').write_text('x')
    monkeypatch.setattr(desktop.sys, '_MEIPASS', str(tmp_path), raising=False)
    assert desktop.find_webui() == bundled


def test_find_webui_survives_a_shallow_path(monkeypatch):
    """A frozen build unzipped to a drive root has very few path parents.

    The repo-checkout candidate used to be built eagerly with ``parents[2]``,
    which raised IndexError before the bundled candidate could be consulted --
    so 'Extract Here' onto D:\\ or a USB stick crashed the app at startup.
    """
    monkeypatch.setattr(desktop, '__file__', '/desktop.py')
    monkeypatch.delattr(desktop.sys, '_MEIPASS', raising=False)
    assert desktop.find_webui() is None


def test_missing_webui_returns_error_not_crash(monkeypatch):
    monkeypatch.setattr(desktop, 'find_webui', lambda: None)
    assert desktop.main() == 1
