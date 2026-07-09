"""
Configuration management for Email Analyzer
"""

import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '..', '.env'))


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

    # CORS
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.environ.get(
            'CORS_ORIGINS', 'http://localhost:3000,https://ataram.uk'
        ).split(',')
        if origin.strip()
    ]

    # File upload
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    UPLOAD_ALLOWED_EXTENSIONS = {'eml', 'msg'}

    # YARA Rules
    YARA_RULES_PATH = os.environ.get('YARA_RULES_PATH', 'yara_rules')

    # Rate limiting
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'true').lower() == 'true'
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '100 per hour')

    # Timeouts
    DNS_TIMEOUT = int(os.environ.get('DNS_TIMEOUT', 5))
    WHOIS_TIMEOUT = int(os.environ.get('WHOIS_TIMEOUT', 10))
    HTTP_TIMEOUT = int(os.environ.get('HTTP_TIMEOUT', 10))

    # Features
    ENABLE_WHOIS = os.environ.get('ENABLE_WHOIS', 'true').lower() == 'true'
    ENABLE_ABUSEIPDB = os.environ.get('ENABLE_ABUSEIPDB', 'true').lower() == 'true'
    ENABLE_VIRUSTOTAL = os.environ.get('ENABLE_VIRUSTOTAL', 'false').lower() == 'true'

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

    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')


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
