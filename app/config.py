"""
Configuration management for Email Analyzer
"""

import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', '.env'))

# The placeholder used when no SECRET_KEY is supplied in development. Kept as a
# module constant so production startup can refuse it explicitly — an operator
# who copies a dev .env to the server must not silently get a known key.
DEV_SECRET_KEY = 'dev-secret-key-DO-NOT-USE-IN-PRODUCTION'


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ('1', 'true', 'yes', 'on')


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_list(name: str, default: str) -> list:
    return [item.strip() for item in os.environ.get(name, default).split(',') if item.strip()]


class Config:
    """Base configuration"""

    # Anything other than 'development' is treated as a production-grade
    # environment for the purposes of the startup safety checks below.
    ENV_NAME = os.environ.get('FLASK_ENV', 'development')
    IS_PRODUCTION = ENV_NAME != 'development'

    # Security — must be set via SECRET_KEY env var in production
    _secret_key = os.environ.get('SECRET_KEY')
    if IS_PRODUCTION:
        if not _secret_key or _secret_key == DEV_SECRET_KEY:
            raise ValueError(
                "SECRET_KEY environment variable must be set to a unique value in "
                "production (the development placeholder is rejected). "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if len(_secret_key) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 characters. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
    elif not _secret_key:
        _secret_key = DEV_SECRET_KEY
    SECRET_KEY = _secret_key

    # API Keys
    ABUSEIPDB_KEY = os.environ.get('ABUSEIPDB_KEY')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

    # Server
    PORT = _env_int('PORT', 5000)
    HOST = os.environ.get('HOST', '0.0.0.0')

    # CORS. The production deployment is single-origin (nginx serves the frontend
    # and proxies /api), so CORS is unused there. An empty list means "no
    # cross-origin access at all", which is the safe default; a wildcard is
    # rejected outright at startup.
    CORS_ORIGINS = _env_list('CORS_ORIGINS', 'http://localhost:3000')
    if '*' in CORS_ORIGINS:
        raise ValueError(
            "CORS_ORIGINS must not contain '*'. List the exact origins that are "
            "allowed to call this API, or leave it empty for a same-origin deployment."
        )

    # Number of reverse proxies in front of the app whose X-Forwarded-* headers
    # may be trusted. Getting this wrong is a security bug in both directions:
    # too low and rate limits key on the proxy IP (one bucket for the whole
    # internet); too high and a client can spoof its own IP by sending its own
    # X-Forwarded-For and evade limits entirely. The reference deployment is
    # cloudflared -> nginx -> gunicorn, so the app sees nginx: one hop it may
    # trust, because nginx overwrites the header it forwards.
    TRUSTED_PROXY_COUNT = _env_int('TRUSTED_PROXY_COUNT', 1)

    # File upload
    MAX_CONTENT_LENGTH = _env_int('MAX_UPLOAD_MB', 25) * 1024 * 1024

    # MAX_FORM_MEMORY_SIZE does NOT mean "the size of non-file form fields",
    # which is what it looks like and what this was originally set to 64KB on
    # the strength of. Werkzeug applies it to the raw multipart *decoder
    # buffer* (werkzeug/sansio/multipart.py: `len(self.buffer) + len(data) >
    # max_form_memory_size` -> RequestEntityTooLarge), which fills with file
    # content while the parser scans for the next boundary.
    #
    # At 64KB that rejected every real line-structured email over roughly
    # 100KB with a 413 — i.e. it broke the product's main function. Flask's own
    # default of 500KB has the same defect, just at a higher threshold.
    #
    # It is therefore pinned to the overall request ceiling: the buffer can
    # never usefully exceed the body it is decoding, and MAX_CONTENT_LENGTH is
    # what actually bounds resource use. MAX_FORM_PARTS still caps part count.
    MAX_FORM_MEMORY_SIZE = MAX_CONTENT_LENGTH
    MAX_FORM_PARTS = 32
    UPLOAD_ALLOWED_EXTENSIONS = {'eml', 'msg'}

    # Analysis limits. These bound the CPU a single upload can consume: without
    # them a 50MB email body is fed whole to BeautifulSoup and a dozen regex
    # scans, which is a cheap way to saturate every worker.
    MAX_ANALYZED_BODY_CHARS = _env_int('MAX_ANALYZED_BODY_CHARS', 2 * 1024 * 1024)
    MAX_ANALYZED_HTML_CHARS = _env_int('MAX_ANALYZED_HTML_CHARS', 1024 * 1024)
    MAX_ANALYZED_URLS = _env_int('MAX_ANALYZED_URLS', 500)
    MAX_ANALYZED_ATTACHMENTS = _env_int('MAX_ANALYZED_ATTACHMENTS', 100)
    MAX_ANALYZED_HOPS = _env_int('MAX_ANALYZED_HOPS', 100)
    MAX_HOP_CHARS = _env_int('MAX_HOP_CHARS', 4096)

    # PARSE-TIME limits. These matter more than the analysis limits above,
    # because they bound work that happens BEFORE analysis begins.
    #
    # Python's email package parses headers lazily under policy.default, and
    # that parsing is super-linear in the number of tokens in a header value.
    # Measured against this code: a 1.5MB .eml carrying one enormous To: header
    # costs ~237s of CPU, and a 1MB file of encoded-word Received: headers costs
    # ~24s — both from files far under the 50MB upload ceiling, and both long
    # enough for gunicorn to SIGKILL the worker at --timeout 120.
    #
    # The guard therefore has to run on the RAW BYTES, before any header value
    # is touched. Slicing the header list afterwards is too late: the cost is
    # incurred by the access itself.
    MAX_HEADER_BLOCK_BYTES = _env_int('MAX_HEADER_BLOCK_BYTES', 256 * 1024)
    MAX_HEADER_LINE_BYTES = _env_int('MAX_HEADER_LINE_BYTES', 16 * 1024)
    MAX_HEADER_COUNT = _env_int('MAX_HEADER_COUNT', 500)
    # Ceiling on MIME parts walked. A part flood is the same attack by another
    # route: 20,000 parts measured at ~14s before any cap applied.
    MAX_MIME_PARTS = _env_int('MAX_MIME_PARTS', 1000)

    # Budgets for MIME SUB-PART Content-* headers, deliberately much tighter
    # than the RFC 5322 line limit above. A legitimate sub-part Content-Type is
    # under 1KB with a handful of parameters; 16 sub-parts carrying a 16KB
    # Content-Type cost 133 seconds of CPU.
    #
    # The parameter cap is the important one: Python's parser is super-linear
    # in the number of TOKENS, not bytes, so a run of bare `;;` costs an order
    # of magnitude more than the same bytes spent on `; a=b`.
    MAX_MIME_HEADER_BYTES = _env_int('MAX_MIME_HEADER_BYTES', 2048)
    MAX_MIME_HEADER_TOTAL_BYTES = _env_int('MAX_MIME_HEADER_TOTAL_KB', 64) * 1024
    MAX_MIME_HEADER_PARAMS = _env_int('MAX_MIME_HEADER_PARAMS', 64)

    # Wall-clock budget for ALL outbound lookups (DNS + WHOIS + AbuseIPDB) in a
    # single /api/analyze request. Four sync workers cannot absorb ten
    # concurrent requests that each block for half a minute on infrastructure
    # the attacker chose, so the enrichment is abandoned once the budget is gone
    # and the response is marked accordingly.
    LOOKUP_BUDGET_SECONDS = _env_int('LOOKUP_BUDGET_SECONDS', 8)

    # Bound on the in-process DNS/WHOIS/IP cache. Unbounded, a stream of unique
    # lookups grows the dict until the worker is OOM-killed.
    CACHE_MAX_ENTRIES = _env_int('CACHE_MAX_ENTRIES', 5000)
    # Entry count alone does not bound memory — one DNS answer can hold 20 TXT
    # records of 4KB each — so the cache is capped by size as well.
    CACHE_MAX_BYTES = _env_int('CACHE_MAX_MB', 32) * 1024 * 1024

    # YARA Rules
    YARA_RULES_PATH = os.environ.get('YARA_RULES_PATH', 'yara_rules')

    # Rate limiting
    RATELIMIT_ENABLED = _env_bool('RATELIMIT_ENABLED', True)
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '100 per hour')
    # In-memory storage is per-process, so with N gunicorn workers every limit is
    # effectively N times looser and resets on restart. Point this at Redis
    # (redis://host:6379/0) for a limit that actually holds across the fleet.
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
    # Per-endpoint limits, overridable without a code change.
    RATELIMIT_ANALYZE = os.environ.get('RATELIMIT_ANALYZE', '10 per minute;60 per hour')
    RATELIMIT_URL = os.environ.get('RATELIMIT_URL', '50 per minute;500 per hour')
    RATELIMIT_LOOKUP = os.environ.get('RATELIMIT_LOOKUP', '30 per minute;300 per hour')

    # Timeouts. Lowered from 5/10/10: every one of these blocks a whole sync
    # worker, and the target host is named by the uploaded email.
    DNS_TIMEOUT = _env_int('DNS_TIMEOUT', 3)
    WHOIS_TIMEOUT = _env_int('WHOIS_TIMEOUT', 5)
    HTTP_TIMEOUT = _env_int('HTTP_TIMEOUT', 5)

    # Features (can be disabled for performance)
    ENABLE_WHOIS = _env_bool('ENABLE_WHOIS', True)
    ENABLE_ABUSEIPDB = _env_bool('ENABLE_ABUSEIPDB', True)
    ENABLE_VIRUSTOTAL = _env_bool('ENABLE_VIRUSTOTAL', False)

    # /api/analyze/url, /api/check/domain and /api/check/ip are not used by the
    # frontend. Each one turns a cheap unauthenticated request into DNS, WHOIS
    # or third-party API traffic from this server's address, so on a public
    # deployment they are attack surface with no user-facing benefit. Off by
    # default; set ENABLE_UTILITY_ENDPOINTS=true to expose them deliberately.
    ENABLE_UTILITY_ENDPOINTS = _env_bool('ENABLE_UTILITY_ENDPOINTS', False)

    # Security headers
    # HSTS is only meaningful over HTTPS and is hard to undo, so it is opt-in.
    ENABLE_HSTS = _env_bool('ENABLE_HSTS', IS_PRODUCTION)
    HSTS_MAX_AGE = _env_int('HSTS_MAX_AGE', 31536000)
    # No third-party origin appears in the policy: the Google Fonts webfont was
    # removed in favour of the system font stack, which also stopped every
    # anonymous page load disclosing the visitor's IP to Google.
    CSP_STYLE_SRC = os.environ.get('CSP_STYLE_SRC', "'self' 'unsafe-inline'")
    CSP_FONT_SRC = os.environ.get('CSP_FONT_SRC', "'self'")

    # Session cookies. No session is used today, but if one is ever added these
    # must already be right rather than defaulted to insecure.
    SESSION_COOKIE_SECURE = IS_PRODUCTION
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Whitelist of trusted sender domains. An email from one of these whose SPF
    # both passes AND is backed by records this server retrieved is capped at
    # low risk.
    #
    # Free-mail providers (gmail.com, outlook.com, yahoo.com, hotmail.com) are
    # deliberately NOT in this list any more. Their SPF and DMARC records
    # authenticate that the message came from that provider's infrastructure —
    # not that the account behind it is honest. Anyone can open a Gmail account
    # and send perfectly authenticated phishing, and the cap would have held it
    # at "low" no matter what the message contained.
    WHITELIST_DOMAINS = _env_list(
        'WHITELIST_DOMAINS',
        'microsoft.com,google.com,amazon.com,apple.com,linkedin.com,facebook.com'
    )

    # Logging. Container deployments should log to stdout so the runtime collects
    # it and the filesystem can stay read-only.
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_TO_STDOUT = _env_bool('LOG_TO_STDOUT', IS_PRODUCTION)


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
    # Off by default so unrelated tests don't share and exhaust one limiter
    # bucket; the rate-limit tests switch it on for their own app instance.
    RATELIMIT_ENABLED = False
    ENABLE_UTILITY_ENDPOINTS = True


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
