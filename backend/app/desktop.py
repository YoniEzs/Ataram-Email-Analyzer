"""Desktop entry point: one process, one port, browser opens itself.

Serves the bundled web UI and the analysis API from a single local process so
the packaged app (PyInstaller) and the pipx install behave like a normal
desktop tool: run it, a browser tab opens, drag an .eml in.

Differences from the server deployment, all deliberate:
- Binds 127.0.0.1 only. This build is a local tool, never a shared service.
- waitress instead of gunicorn, because gunicorn does not run on Windows.
- Rate limiting off and HTTPS redirection off: meaningless on loopback.
- CSP admits inline style attributes, which the UI uses; in server
  deployments nginx serves the UI and Flask's CSP never applies to it.
"""

import os
import socket
import sys
import threading
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from flask import Flask

DEFAULT_PORT = 8321


def _configure_environment() -> None:
    """Desktop defaults. Note: the app package is already imported by the
    time this runs (importing app.desktop imports the app package first), so
    only settings read lazily — env vars consumed at request/serve time and
    config read via os.environ in create_app — belong here. Anything Config
    evaluates at class-body time must be handled in app.config itself."""
    os.environ.setdefault('FLASK_ENV', 'production')
    os.environ.setdefault('FORCE_HTTPS', 'false')
    os.environ.setdefault('RATELIMIT_ENABLED', 'false')
    os.environ.setdefault('HOST', '127.0.0.1')
    os.environ.setdefault('LOG_LEVEL', 'WARNING')


def find_webui() -> Optional[Path]:
    """Locate the static UI: bundled copy first, repo checkout second."""
    here = Path(__file__).resolve()
    candidates = [here.parent / 'webui']
    if len(here.parents) > 2:
        candidates.append(here.parents[2] / 'frontend' / 'src')
    bundle_root = getattr(sys, '_MEIPASS', None)
    if bundle_root:
        candidates.insert(0, Path(bundle_root) / 'app' / 'webui')
    for candidate in candidates:
        if (candidate / 'index.html').is_file():
            return candidate
    return None


def _free_port(preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(('127.0.0.1', preferred))
            return preferred
        except OSError:
            probe.bind(('127.0.0.1', 0))
            return probe.getsockname()[1]


def create_desktop_app(webui: Path) -> 'Flask':
    from flask import send_from_directory

    from app import create_app
    from app.config import ProductionConfig

    class DesktopConfig(ProductionConfig):
        FORCE_HTTPS = False
        RATELIMIT_ENABLED = False
        CSP_ALLOW_INLINE_STYLE = True

    app = create_app(DesktopConfig)

    @app.route('/')
    def _index():  # pragma: no cover - trivial
        return send_from_directory(webui, 'index.html')

    @app.route('/<path:filename>')
    def _static_file(filename: str):  # type: ignore[no-untyped-def]
        return send_from_directory(webui, filename)

    return app


def main() -> int:
    _configure_environment()

    webui = find_webui()
    if webui is None:
        print(
            'Could not find the web UI files. Reinstall the application, or '
            'run scripts/sync_webui.py in a source checkout.',
            file=sys.stderr,
        )
        return 1

    app = create_desktop_app(webui)
    # Keep legacy ATARAM_* environment variables working for RC1 while adding
    # the new public ITGALYA_* names. Existing users/scripts do not break.
    configured_port = os.environ.get('ITGALYA_PORT') or os.environ.get('ATARAM_PORT')
    port = _free_port(int(configured_port or DEFAULT_PORT))
    url = f'http://127.0.0.1:{port}'

    print(f'ITgalya Email Analyzer running at {url}  (Ctrl+C to quit)', flush=True)
    no_browser = os.environ.get('ITGALYA_NO_BROWSER') or os.environ.get('ATARAM_NO_BROWSER', '')
    if no_browser.lower() not in ('1', 'true'):
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()

    from waitress import serve  # type: ignore[import-untyped]
    serve(app, host='127.0.0.1', port=port, threads=8)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
