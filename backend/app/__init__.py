"""
Email Analyzer Backend Application
Ataram Email Security Platform
"""

import logging
import os
import secrets
import sys
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import Config

limiter = Limiter(key_func=get_remote_address)


def create_app(config_class=Config):
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Trust forwarded client/protocol headers only when the deployment states
    # exactly how many controlled reverse proxies sit in front of the app.
    proxy_count = int(app.config.get('TRUST_PROXY_COUNT', 0) or 0)
    if proxy_count > 0:
        app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
            app.wsgi_app,
            x_for=proxy_count,
            x_proto=proxy_count,
            x_host=proxy_count,
        )

    # SECRET_KEY: nothing in this API uses sessions, cookies, or CSRF tokens,
    # so a missing key is not a security problem — generate an ephemeral one
    # rather than hard-failing deployment. If session-based features are ever
    # added, set SECRET_KEY explicitly so signed values survive restarts and
    # are shared across workers.
    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = secrets.token_hex(32)
        if not app.config.get('TESTING'):
            logging.getLogger(__name__).info(
                "SECRET_KEY not set — generated an ephemeral key. This API is "
                "stateless (no sessions/CSRF), so this is safe; set SECRET_KEY "
                "explicitly if session features are added."
            )

    # HTTP security headers (Talisman if installed, manual fallback otherwise)
    _apply_security_headers(app)

    # CORS — explicit origins only; no wildcard
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type"],
        },
        r"/health": {
            "origins": app.config['CORS_ORIGINS'],
            "methods": ["GET", "OPTIONS"],
            "allow_headers": ["Content-Type"],
        },
    })

    # Production logging: stdout by default (survives redeploys on PaaS
    # platforms with ephemeral filesystems); rotating file log is opt-in.
    if not app.debug and not app.testing:
        log_level = getattr(
            logging, str(app.config.get('LOG_LEVEL', 'INFO')).upper(), logging.INFO
        )
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        )

        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(log_level)
        app.logger.addHandler(stream_handler)

        if app.config.get('LOG_TO_FILE'):
            os.makedirs('logs', exist_ok=True)
            file_handler = RotatingFileHandler(
                'logs/email_analyzer.log',
                maxBytes=10_240_000,
                backupCount=10,
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            app.logger.addHandler(file_handler)

        app.logger.setLevel(log_level)
        app.logger.info('Email Analyzer startup')

    limiter.init_app(app)

    from app.api import analysis
    app.register_blueprint(analysis.bp)
    # Versioned alias — same handlers, stable contract for API consumers.
    # /api/* stays for backward compatibility; /api/v1/* is the documented path.
    app.register_blueprint(analysis.bp, url_prefix='/api/v1', name='analysis_v1')

    @app.route('/health')
    def health():
        return {'status': 'healthy', 'service': 'Email Analyzer API'}, 200

    # This is a JSON API — errors raised outside the blueprint (404, 405,
    # oversized uploads, unhandled exceptions) must not return HTML pages.
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({
            'error': 'Not found',
            'message': 'The requested resource does not exist.',
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({
            'error': 'Method not allowed',
            'message': 'This HTTP method is not supported for this endpoint.',
        }), 405

    @app.errorhandler(413)
    def payload_too_large(e):
        max_mb = app.config.get('MAX_CONTENT_LENGTH', 0) // (1024 * 1024)
        return jsonify({
            'error': 'File too large',
            'message': f'Upload exceeds the maximum size of {max_mb}MB.',
        }), 413

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({
            'error': 'Internal server error',
            'message': 'An unexpected error occurred. Please try again.',
        }), 500

    return app


def _apply_security_headers(app: Flask) -> None:
    """Set HTTP security headers.  Uses flask-talisman when available,
    falls back to a manual after_request hook so the app still hardens
    itself even if the package isn't installed yet."""
    try:
        from flask_talisman import Talisman

        csp = {
            'default-src': ["'self'"],
            'script-src': ["'self'"],
            'style-src': ["'self'", 'https://fonts.googleapis.com'],
            'font-src': ["'self'", 'https://fonts.gstatic.com'],
            'img-src': ["'self'", 'data:'],
            'connect-src': ["'self'"],
            'object-src': ["'none'"],
            'frame-ancestors': ["'none'"],
        }
        secure_transport = bool(
            app.config.get('FORCE_HTTPS', True)
            and not (app.debug or app.testing)
        )
        Talisman(
            app,
            force_https=secure_transport,
            strict_transport_security=secure_transport,
            strict_transport_security_max_age=31_536_000,
            content_security_policy=csp,
            referrer_policy='strict-origin-when-cross-origin',
        )
    except ImportError:
        @app.after_request
        def _manual_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            if app.config.get('FORCE_HTTPS', True) and not (app.debug or app.testing):
                response.headers['Strict-Transport-Security'] = (
                    'max-age=31536000; includeSubDomains'
                )
            return response
