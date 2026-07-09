"""
Email Analyzer Backend Application
Ataram Email Security Platform
"""

import logging
import os
import secrets
from logging.handlers import RotatingFileHandler

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.config import Config

limiter = Limiter(key_func=get_remote_address)


def create_app(config_class=Config):
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Fail-fast: SECRET_KEY must be set before production traffic arrives.
    # In dev/debug mode we generate an ephemeral key so the app still starts.
    if not app.config.get('SECRET_KEY'):
        if not app.config.get('TESTING'):
            if not app.debug:
                raise RuntimeError(
                    "SECRET_KEY is not set. "
                    "Generate one with: "
                    "python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            app.config['SECRET_KEY'] = secrets.token_hex(32)
            logging.getLogger(__name__).warning(
                "Using an ephemeral SECRET_KEY — sessions will not survive restarts. "
                "Set the SECRET_KEY environment variable."
            )

    # HTTP security headers (Talisman if installed, manual fallback otherwise)
    talisman = _apply_security_headers(app)

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

    # File logging (production only)
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler(
            'logs/email_analyzer.log',
            maxBytes=10_240_000,
            backupCount=10,
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Email Analyzer startup')

    limiter.init_app(app)

    from app.api import analysis
    app.register_blueprint(analysis.bp)

    def health():
        return {'status': 'healthy', 'service': 'Email Analyzer API'}, 200

    # /health must answer plain-HTTP probes (Docker HEALTHCHECK, load
    # balancers) without a force-HTTPS redirect.
    if talisman is not None:
        health = talisman(force_https=False)(health)
    app.add_url_rule('/health', 'health', health)

    return app


def _apply_security_headers(app: Flask):
    """Set HTTP security headers.  Uses flask-talisman when available,
    falls back to a manual after_request hook so the app still hardens
    itself even if the package isn't installed yet.

    Returns the Talisman instance (for per-view overrides) or None."""
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
        https_on = (
            app.config.get('FORCE_HTTPS', True)
            and not (app.debug or app.testing)
        )
        return Talisman(
            app,
            force_https=https_on,
            strict_transport_security=https_on,
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
            if not app.debug:
                response.headers['Strict-Transport-Security'] = (
                    'max-age=31536000; includeSubDomains'
                )
            return response

        return None
