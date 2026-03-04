"""
Configuration management for Email Analyzer
"""

import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '..', '.env'))


class Config:
    """Base configuration"""

    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # API Keys
    ABUSEIPDB_KEY = os.environ.get('ABUSEIPDB_KEY')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

    # Server
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '0.0.0.0')

    # CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,https://ataram.uk,https://ataram-email-analyzer-i3q5.onrender.com').split(',')

    # File upload
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max file size
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

    # Features (can be disabled for performance)
    ENABLE_WHOIS = os.environ.get('ENABLE_WHOIS', 'true').lower() == 'true'
    ENABLE_ABUSEIPDB = os.environ.get('ENABLE_ABUSEIPDB', 'true').lower() == 'true'
    ENABLE_VIRUSTOTAL = os.environ.get('ENABLE_VIRUSTOTAL', 'false').lower() == 'true'

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
    """Testing configuration"""
    DEBUG = False
    TESTING = True


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
