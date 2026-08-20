"""
Email Analysis API Endpoints
"""

import traceback

from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from app.api.openapi import API_VERSION
from app.services.email_parser import EmailParserService
from app.services.email_analyzer import EmailAnalyzerService
from app.utils.validators import (
    allowed_file,
    validate_domain,
    validate_email_file,
    validate_public_ip,
)
from app import limiter

bp = Blueprint('analysis', __name__, url_prefix='/api')

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@bp.app_errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please wait before trying again.',
    }), 429


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@bp.route('/openapi.json', methods=['GET'])
def openapi_spec():
    """Machine-readable API contract (OpenAPI 3.0)."""
    from app.api.openapi import OPENAPI_SPEC
    return jsonify(OPENAPI_SPEC), 200


@bp.route('/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_email():
    """Analyze uploaded .eml or .msg file."""
    try:
        if 'emailfile' not in request.files:
            return jsonify({
                'error': 'No file provided',
                'message': 'Please upload an email file (.eml or .msg)',
            }), 400

        file = request.files['emailfile']

        if not file.filename:
            return jsonify({
                'error': 'Empty filename',
                'message': 'Please select a valid file',
            }), 400

        if not allowed_file(file.filename):
            return jsonify({
                'error': 'Invalid file type',
                'message': 'Only .eml and .msg files are supported',
            }), 400

        # API keys come from form (BYOK) or server config — never logged
        abuseipdb_key = None
        if current_app.config.get('ENABLE_ABUSEIPDB'):
            abuseipdb_key = (
                request.form.get('abuseipdb_key')
                or current_app.config.get('ABUSEIPDB_KEY')
            )
        virustotal_key = None
        if current_app.config.get('ENABLE_VIRUSTOTAL'):
            virustotal_key = (
                request.form.get('virustotal_key')
                or current_app.config.get('VIRUSTOTAL_API_KEY')
            )

        original_filename = file.filename.strip()
        extension = original_filename.rsplit('.', 1)[-1].lower()
        file_data = file.read()
        filename = secure_filename(original_filename) or f'upload.{extension}'

        is_valid, error_msg = validate_email_file(
            file_data,
            filename,
            max_bytes=current_app.config.get('MAX_CONTENT_LENGTH', 25 * 1024 * 1024),
        )
        if not is_valid:
            return jsonify({'error': 'Invalid file', 'message': error_msg}), 400

        current_app.logger.info(
            'Parsing uploaded email (%d bytes, extension=%s)',
            len(file_data),
            filename.rsplit('.', 1)[-1].lower(),
        )
        parser = EmailParserService(
            max_mime_parts=current_app.config.get('MAX_MIME_PARTS', 250),
            max_attachments=current_app.config.get('MAX_ATTACHMENTS', 100),
            max_attachment_bytes=current_app.config.get(
                'MAX_ATTACHMENT_BYTES', 10 * 1024 * 1024
            ),
            max_total_attachment_bytes=current_app.config.get(
                'MAX_TOTAL_ATTACHMENT_BYTES', 20 * 1024 * 1024
            ),
            max_text_chars=current_app.config.get('MAX_TEXT_CHARS', 2_000_000),
        )
        parsed_data = parser.parse_email(file_data, filename)

        if parsed_data.get('error'):
            return jsonify({'error': 'Parsing failed', 'message': parsed_data['error']}), 400

        current_app.logger.info('Analyzing uploaded email')
        analyzer = EmailAnalyzerService(
            abuseipdb_key=abuseipdb_key,
            whitelist_domains=current_app.config.get('WHITELIST_DOMAINS', []),
            enable_whois=current_app.config.get('ENABLE_WHOIS', True),
            enable_abuseipdb=current_app.config.get('ENABLE_ABUSEIPDB', True),
            enable_virustotal=current_app.config.get('ENABLE_VIRUSTOTAL', False),
            virustotal_key=virustotal_key,
            enable_auth_verification=current_app.config.get('ENABLE_AUTH_VERIFICATION', True),
            yara_rules_path=current_app.config.get('YARA_RULES_PATH'),
            max_yara_scan_bytes=current_app.config.get(
                'MAX_YARA_SCAN_BYTES', 8 * 1024 * 1024
            ),
            max_archive_members=current_app.config.get('MAX_ARCHIVE_MEMBERS', 100),
            max_archive_uncompressed_bytes=current_app.config.get(
                'MAX_ARCHIVE_UNCOMPRESSED_BYTES', 200 * 1024 * 1024
            ),
            max_archive_ratio=current_app.config.get('MAX_ARCHIVE_RATIO', 100),
            max_urls=current_app.config.get('MAX_URLS', 500),
            max_url_length=current_app.config.get('MAX_URL_LENGTH', 4096),
            dns_timeout=current_app.config.get('DNS_TIMEOUT', 5),
            whois_timeout=current_app.config.get('WHOIS_TIMEOUT', 10),
            http_timeout=current_app.config.get('HTTP_TIMEOUT', 10),
            enable_reverse_dns=current_app.config.get('ENABLE_REVERSE_DNS', True),
            enable_ip_rdap=current_app.config.get('ENABLE_IP_RDAP', True),
            enable_asn_lookup=current_app.config.get('ENABLE_ASN_LOOKUP', True),
            enable_spf_advisory=current_app.config.get('ENABLE_SPF_ADVISORY', False),
            enable_mx_lookup=current_app.config.get('ENABLE_MX_LOOKUP', False),
            spf_timeout=current_app.config.get('SPF_TIMEOUT', 8),
        )
        analysis_result = analyzer.analyze(parsed_data)

        analysis_result['metadata'] = {
            'filename': filename,
            'analyzed_at': analysis_result.get('timestamp'),
            'version': API_VERSION,
        }

        current_app.logger.info('Analysis complete')
        return jsonify(analysis_result), 200

    except HTTPException:
        # Let Flask's error handlers produce the proper status (413 etc.)
        raise
    except Exception as e:
        current_app.logger.error('Error analyzing email: %s', str(e))
        current_app.logger.error(traceback.format_exc())
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred while analyzing the email. Please try again.',
        }), 500


@bp.route('/analyze/url', methods=['POST'])
@limiter.limit("30 per minute")
def analyze_url():
    """Analyze a single URL for phishing indicators."""
    try:
        data = request.get_json(silent=True)

        if not data or 'url' not in data:
            return jsonify({'error': 'Missing URL', 'message': 'Please provide a URL'}), 400

        url = str(data['url']).strip()
        max_url_length = current_app.config.get('MAX_URL_LENGTH', 4096)
        if len(url) > max_url_length:
            return jsonify({
                'error': 'URL too long',
                'message': f'URL exceeds the maximum length of {max_url_length} characters',
            }), 400
        if not url.lower().startswith(('http://', 'https://')):
            return jsonify({
                'error': 'Invalid URL',
                'message': 'URL must start with http:// or https://',
            }), 400

        sender_domain = data.get('sender_domain')
        if sender_domain is not None:
            sender_domain = str(sender_domain).strip().lower()
            if not validate_domain(sender_domain):
                return jsonify({
                    'error': 'Invalid sender domain',
                    'message': 'sender_domain must be a valid public domain name',
                }), 400

        from app.services.url_analyzer import URLAnalyzerService
        result = URLAnalyzerService(
            max_url_length=max_url_length
        ).analyze_single_url(url, sender_domain)
        return jsonify(result), 200

    except Exception as e:
        current_app.logger.error('Error analyzing URL: %s', str(e))
        return jsonify({'error': 'Analysis failed', 'message': 'URL analysis failed'}), 500


@bp.route('/check/domain', methods=['POST'])
@limiter.limit("20 per minute")
def check_domain():
    """Check domain SPF/DMARC records and WHOIS info."""
    try:
        data = request.get_json(silent=True)

        if not data or 'domain' not in data:
            return jsonify({'error': 'Missing domain', 'message': 'Please provide a domain'}), 400

        domain = str(data['domain']).strip().lower()

        if not validate_domain(domain):
            return jsonify({
                'error': 'Invalid domain',
                'message': 'Domain must be a valid public domain name',
            }), 400

        from app.services.dns_checker import DNSCheckerService
        from app.services.whois_service import WhoisService

        dns_checker = DNSCheckerService(
            timeout=current_app.config.get('DNS_TIMEOUT', 5)
        )
        whois_service = None
        if current_app.config.get('ENABLE_WHOIS'):
            whois_service = WhoisService(
                timeout=current_app.config.get('WHOIS_TIMEOUT', 10)
            )

        result = {
            'domain': domain,
            'spf': dns_checker.check_spf(domain),
            'dmarc': dns_checker.check_dmarc(domain),
            'whois': whois_service.lookup(domain) if whois_service else None,
        }
        return jsonify(result), 200

    except Exception as e:
        current_app.logger.error('Error checking domain: %s', str(e))
        return jsonify({'error': 'Check failed', 'message': 'Domain check failed'}), 500


@bp.route('/check/ip', methods=['POST'])
@limiter.limit("20 per minute")
def check_ip():
    """Check IP reputation via AbuseIPDB."""
    try:
        data = request.get_json(silent=True)

        if not data or 'ip' not in data:
            return jsonify({'error': 'Missing IP', 'message': 'Please provide an IP address'}), 400

        ip = str(data['ip']).strip()

        if not validate_public_ip(ip):
            return jsonify({
                'error': 'Invalid IP',
                'message': 'IP must be a valid, globally routable address',
            }), 400

        if not current_app.config.get('ENABLE_ABUSEIPDB'):
            return jsonify({
                'error': 'Feature disabled',
                'message': 'IP reputation checks are disabled',
            }), 503

        abuseipdb_key = (
            data.get('abuseipdb_key')
            or current_app.config.get('ABUSEIPDB_KEY')
        )

        if not abuseipdb_key:
            return jsonify({
                'error': 'No API key',
                'message': 'AbuseIPDB API key is required',
            }), 400

        from app.services.ip_reputation import IPReputationService
        result = IPReputationService(
            abuseipdb_key,
            timeout=current_app.config.get('HTTP_TIMEOUT', 10),
        ).check_ip(ip)
        return jsonify(result), 200

    except Exception as e:
        current_app.logger.error('Error checking IP: %s', str(e))
        return jsonify({'error': 'Check failed', 'message': 'IP reputation check failed'}), 500
