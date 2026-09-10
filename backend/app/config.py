"""
Configuration management for Email Analyzer
"""

import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '..', '.env'))


def _env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable with predictable semantics."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


def _offline_requested() -> bool:
    """Public ITgalya name plus legacy/generic compatibility."""
    return _env_bool('ITGALYA_OFFLINE_MODE') or _env_bool('OFFLINE_MODE')


def _network_feature_enabled(name: str, default: bool) -> bool:
    """Offline mode is a hard master switch over every network enrichment."""
    return not _offline_requested() and _env_bool(name, default)


class Config:
    """Base configuration"""

    # No hardcoded fallback — validated at startup in create_app()
    # Generate a key: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY = os.environ.get('SECRET_KEY')

    # API Keys
    ABUSEIPDB_KEY = os.environ.get('ABUSEIPDB_KEY')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

    # Server
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '0.0.0.0')
    TRUST_PROXY_COUNT = int(os.environ.get('TRUST_PROXY_COUNT', 0))

    # CORS. This is a browser policy, not authentication. Production
    # deployments should explicitly list their frontend origins.
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.environ.get(
            'CORS_ORIGINS', 'http://localhost:3000'
        ).split(',')
        if origin.strip()
    ]

    # File and parser resource limits. Uploaded mail is hostile input; these
    # bounds limit memory/CPU amplification before deeper analysis begins.
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_UPLOAD_BYTES', 25 * 1024 * 1024))
    UPLOAD_ALLOWED_EXTENSIONS = {'eml', 'msg'}
    MAX_MIME_PARTS = int(os.environ.get('MAX_MIME_PARTS', 250))
    MAX_ATTACHMENTS = int(os.environ.get('MAX_ATTACHMENTS', 100))
    MAX_ATTACHMENT_BYTES = int(
        os.environ.get('MAX_ATTACHMENT_BYTES', 10 * 1024 * 1024)
    )
    MAX_TOTAL_ATTACHMENT_BYTES = int(
        os.environ.get('MAX_TOTAL_ATTACHMENT_BYTES', 20 * 1024 * 1024)
    )
    MAX_TEXT_CHARS = int(os.environ.get('MAX_TEXT_CHARS', 2_000_000))
    MAX_URLS = int(os.environ.get('MAX_URLS', 500))
    MAX_URL_LENGTH = int(os.environ.get('MAX_URL_LENGTH', 4096))
    MAX_YARA_SCAN_BYTES = int(
        os.environ.get('MAX_YARA_SCAN_BYTES', 8 * 1024 * 1024)
    )
    MAX_ARCHIVE_MEMBERS = int(os.environ.get('MAX_ARCHIVE_MEMBERS', 100))
    MAX_ARCHIVE_UNCOMPRESSED_BYTES = int(
        os.environ.get('MAX_ARCHIVE_UNCOMPRESSED_BYTES', 200 * 1024 * 1024)
    )
    MAX_ARCHIVE_RATIO = int(os.environ.get('MAX_ARCHIVE_RATIO', 100))

    # YARA Rules — relative paths resolve against the backend root. In a
    # pip/pipx install there is no backend root above site-packages, so when
    # the default location is absent (and no explicit path was given) fall
    # back to the copy bundled inside the package by scripts/sync_webui.py.
    # This must live here, not in an entry point: the class body evaluates on
    # first import of the app package, before any main() can set env vars.
    _yara_path = os.environ.get('YARA_RULES_PATH', 'yara_rules')
    YARA_RULES_PATH = (
        _yara_path
        if os.path.isabs(_yara_path)
        else os.path.abspath(os.path.join(basedir, '..', _yara_path))
    )
    if 'YARA_RULES_PATH' not in os.environ and not os.path.isdir(YARA_RULES_PATH):
        _bundled_yara = os.path.join(basedir, 'bundled_yara')
        if os.path.isdir(_bundled_yara):
            YARA_RULES_PATH = _bundled_yara

    # Rate limiting
    RATELIMIT_ENABLED = _env_bool('RATELIMIT_ENABLED', True)
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '100 per hour')
    # Shared storage for rate-limit counters. With multiple gunicorn workers
    # the in-memory default keeps a separate counter per worker — point this
    # at Redis (redis://host:6379) in production. Falls back to REDIS_URL.
    RATELIMIT_STORAGE_URI = (
        os.environ.get('RATELIMIT_STORAGE_URI')
        or os.environ.get('REDIS_URL')
        or 'memory://'
    )

    # Timeouts
    DNS_TIMEOUT = int(os.environ.get('DNS_TIMEOUT', 5))
    WHOIS_TIMEOUT = int(os.environ.get('WHOIS_TIMEOUT', 10))
    HTTP_TIMEOUT = int(os.environ.get('HTTP_TIMEOUT', 10))

    # Privacy master switch. When enabled, every feature capable of making an
    # outbound lookup is disabled regardless of its individual feature flag.
    OFFLINE_MODE = _offline_requested()

    # Network-backed features
    ENABLE_WHOIS = _network_feature_enabled('ENABLE_WHOIS', True)
    ENABLE_ABUSEIPDB = _network_feature_enabled('ENABLE_ABUSEIPDB', True)
    ENABLE_VIRUSTOTAL = _network_feature_enabled('ENABLE_VIRUSTOTAL', False)
    # Independent DKIM verification performs DNS lookups, so offline mode must
    # disable it as well. Header claims remain available as untrusted evidence.
    ENABLE_AUTH_VERIFICATION = _network_feature_enabled(
        'ENABLE_AUTH_VERIFICATION', True
    )

    # Artifact enrichment. Reverse DNS and IP intelligence are on by default:
    # both are cheap, keyless, and describe the sending address rather than the
    # message. See PRIVACY.md — they do disclose the sending IP to third parties.
    ENABLE_REVERSE_DNS = _network_feature_enabled('ENABLE_REVERSE_DNS', True)
    ENABLE_IP_RDAP = _network_feature_enabled('ENABLE_IP_RDAP', True)
    ENABLE_ASN_LOOKUP = _network_feature_enabled('ENABLE_ASN_LOOKUP', True)
    ENABLE_MX_LOOKUP = _network_feature_enabled('ENABLE_MX_LOOKUP', False)
    # Advisory SPF re-evaluation. Off by default: both of its inputs come from
    # forgeable headers, so the result is display-only and never scored.
    ENABLE_SPF_ADVISORY = _network_feature_enabled('ENABLE_SPF_ADVISORY', False)
    SPF_TIMEOUT = int(os.environ.get('SPF_TIMEOUT', 8))

    # HTTPS is normally terminated by the application or an upstream proxy.
    # Plain-HTTP local Compose deployments explicitly disable this.
    FORCE_HTTPS = _env_bool('FORCE_HTTPS', True)

    # Trusted sender domain whitelist — empty by default.
    # The old default included gmail.com/outlook.com/etc., which are frequently
    # spoofed in phishing campaigns. Whitelisting now only gives a small discount
    # to otherwise low-risk mail and never suppresses high-risk evidence.
    # Set via env var: WHITELIST_DOMAINS=yourdomain.com,partner.com
    WHITELIST_DOMAINS = [
        d.strip()
        for d in os.environ.get('WHITELIST_DOMAINS', '').split(',')
        if d.strip()
    ]

    # Logging — stdout is the default sink; set LOG_TO_FILE=true for a
    # rotating file log under logs/ as well.
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_TO_FILE = _env_bool('LOG_TO_FILE', False)


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False


class TestingConfig(Config):
    """Testing configuration — safe ephemeral key, no external calls expected"""
    DEBUG = False
    TESTING = True
    SECRET_KEY = 'test-secret-key-not-for-production'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig,
}
