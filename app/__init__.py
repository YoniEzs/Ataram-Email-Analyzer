"""
Email Analyzer Backend Application
Itgalya Email Security Platform
"""

from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from app.config import Config
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import os
import sys

def rate_limit_key() -> str:
    """
    The identity a rate limit is charged against.

    Keying on the full client address is correct for IPv4 but useless for IPv6:
    a single host is routinely delegated a /64 (every major VPS provider and
    most consumer ISPs do this), which is 2^64 source addresses it genuinely
    owns. Measured against this app before aggregation: 60 uploads from
    distinct addresses inside one /64 produced zero 429s against a
    "10 per minute" limit — a complete bypass requiring no spoofing at all,
    so no amount of header validation or JWT checking would have caught it.

    IPv6 is therefore aggregated to its /64. IPv4 keeps full-address
    granularity, where an address is a meaningful unit of identity.
    """
    address = get_remote_address()
    if not address:
        return 'anonymous'
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address
    if parsed.version == 6:
        return str(ipaddress.ip_network(f'{parsed}/64', strict=False))
    return address


limiter = Limiter(key_func=rate_limit_key)


def _configure_logging(app):
    """Send application logs to stdout (containers) or a rotating file."""
    if app.debug or app.testing:
        return

    level = getattr(logging, str(app.config.get('LOG_LEVEL', 'INFO')).upper(), logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )

    if app.config.get('LOG_TO_STDOUT'):
        handler = logging.StreamHandler(sys.stdout)
    else:
        os.makedirs('logs', exist_ok=True)
        handler = RotatingFileHandler(
            'logs/email_analyzer.log',
            maxBytes=10240000,
            backupCount=10
        )

    handler.setFormatter(formatter)
    handler.setLevel(level)
    app.logger.addHandler(handler)
    app.logger.setLevel(level)
    app.logger.info('Email Analyzer startup')


def _register_error_handlers(app):
    """Return JSON for every error class, and never leak internals."""

    def json_error(status, error, message):
        response = jsonify({'error': error, 'message': message})
        response.status_code = status
        return response

    @app.errorhandler(400)
    def bad_request(_e):
        return json_error(400, 'Bad request', 'The request could not be understood.')

    @app.errorhandler(404)
    def not_found(_e):
        return json_error(404, 'Not found', 'The requested resource does not exist.')

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return json_error(405, 'Method not allowed', 'That method is not supported for this endpoint.')

    @app.errorhandler(413)
    def payload_too_large(_e):
        limit_mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
        return json_error(413, 'File too large', f'The upload exceeds the {limit_mb}MB limit.')

    @app.errorhandler(429)
    def ratelimit_handler(_e):
        response = json_error(
            429, 'Rate limit exceeded',
            'Too many requests. Please wait before analyzing another email.'
        )
        response.headers['Retry-After'] = '60'
        return response

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.error(f'Unhandled error: {type(e).__name__}')
        return json_error(500, 'Internal server error', 'An unexpected error occurred.')

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        # Let Werkzeug's own HTTP exceptions (404, 405, ...) keep their status;
        # anything else is an unexpected failure and must not reach the client
        # as a traceback.
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return e
        app.logger.exception('Unhandled exception')
        return json_error(500, 'Internal server error', 'An unexpected error occurred.')


def _build_csp(app):
    """
    Content-Security-Policy for the analyzer.

    script-src is the part that matters: the results renderer builds HTML from
    values taken out of an attacker-supplied email, so 'self' with no
    'unsafe-inline' turns any escaping mistake from a stored XSS into a blocked
    console message. Inline *styles* are still allowed because the markup uses
    style attributes throughout, and they are a far weaker vector.
    """
    return '; '.join([
        "default-src 'self'",
        "script-src 'self'",
        f"style-src {app.config['CSP_STYLE_SRC']}",
        f"font-src {app.config['CSP_FONT_SRC']}",
        "img-src 'self' data:",
        # The page talks only to its own origin; blobs are used for the JSON export.
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "frame-src 'none'",
        "worker-src 'none'",
        "manifest-src 'self'",
        "upgrade-insecure-requests",
    ])


def create_app(config_class=Config):
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Trust exactly as many proxy hops as are actually deployed. Without this the
    # limiter keys every request on the nginx container's address, so the whole
    # internet shares a single bucket. Trusting more hops than exist is worse:
    # a client could then supply its own X-Forwarded-For and rotate its key at will.
    proxy_hops = app.config.get('TRUSTED_PROXY_COUNT', 0)
    if proxy_hops > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=proxy_hops,
            x_proto=proxy_hops,
            x_host=0,
            x_port=0,
            x_prefix=0,
        )

    # Enable CORS for frontend. Credentials are deliberately not allowed: the
    # API is unauthenticated and same-origin in production.
    cors_origins = app.config.get('CORS_ORIGINS') or []
    if cors_origins:
        CORS(app, resources={
            r"/api/*": {
                "origins": cors_origins,
                "methods": ["GET", "POST", "OPTIONS"],
                "allow_headers": ["Content-Type", "X-Requested-With"],
                "supports_credentials": False,
                "max_age": 600,
            },
            r"/health": {
                "origins": cors_origins,
                "methods": ["GET", "OPTIONS"],
                "allow_headers": ["Content-Type", "X-Requested-With"],
                "supports_credentials": False,
                "max_age": 600,
            }
        })

    _configure_logging(app)

    # Bound the shared lookup cache so a stream of unique domains cannot grow it
    # without limit.
    from app.utils.cache import cache_configure
    cache_configure(
        app.config.get('CACHE_MAX_ENTRIES', 5000),
        app.config.get('CACHE_MAX_BYTES', 32 * 1024 * 1024),
    )

    # Initialize rate limiter.
    #
    # Redis is shared storage, not a dependency the API should die with. Left
    # at defaults, an unreachable Redis makes every limited endpoint raise and
    # the whole API returns 500 — a rate limiter that converts a cache blip
    # into a total outage is worse than the looseness it fixes. Short socket
    # timeouts stop a hung Redis from holding a sync worker, and the in-memory
    # fallback keeps limits enforced (per-worker) while Redis is away.
    if app.config.get('RATELIMIT_STORAGE_URI', 'memory://').startswith('redis'):
        app.config.setdefault('RATELIMIT_STORAGE_OPTIONS', {
            'socket_timeout': 1,
            'socket_connect_timeout': 1,
        })
        app.config.setdefault('RATELIMIT_IN_MEMORY_FALLBACK_ENABLED', True)
    app.config.setdefault('RATELIMIT_SWALLOW_ERRORS', True)

    limiter.init_app(app)

    # Register blueprints
    from app.api import analysis
    app.register_blueprint(analysis.bp)

    _register_error_handlers(app)

    csp = _build_csp(app)

    # Security response headers
    @app.after_request
    def set_security_headers(response):
        response.headers['Content-Security-Policy'] = csp
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = (
            'geolocation=(), camera=(), microphone=(), payment=(), usb=(), '
            'interest-cohort=()'
        )
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        # Cross-Origin-Embedder-Policy is deliberately not set: require-corp
        # would block the cross-origin webfont, and nothing here needs
        # cross-origin isolation.
        # Analysis results are derived from a user's private email. They must not
        # sit in a shared cache, and there is nothing here worth revalidating.
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'

        if app.config.get('ENABLE_HSTS'):
            response.headers['Strict-Transport-Security'] = (
                f"max-age={app.config['HSTS_MAX_AGE']}; includeSubDomains"
            )

        # X-XSS-Protection is deprecated and its filter has itself been a source
        # of vulnerabilities; 0 is the value modern guidance recommends.
        response.headers['X-XSS-Protection'] = '0'
        # Don't advertise the server stack.
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)
        return response

    # Health check endpoint. Deliberately says nothing about versions, config or
    # dependency state — it is reachable by anyone who can reach the app.
    @app.route('/health')
    @limiter.exempt
    def health():
        return {'status': 'healthy', 'service': 'Email Analyzer API'}, 200

    return app
