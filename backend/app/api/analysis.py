"""
Email Analysis API Endpoints
"""

import traceback

from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

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

        file_data = file.read()
        filename = secure_filename(file.filename)

        is_valid, error_msg = validate_email_file(file_data, filename)
        if not is_valid:
            return jsonify({'error': 'Invalid file', 'message': error_msg}), 400

        current_app.logger.info('Parsing email: %s (%d bytes)', filename, len(file_data))
        parser = EmailParserService()
        parsed_data = parser.parse_email(file_data, filename)

        if parsed_data.get('error'):
            return jsonify({'error': 'Parsing failed', 'message': parsed_data['error']}), 400

        current_app.logger.info('Analyzing email: %s', filename)
        analyzer = EmailAnalyzerService(
            abuseipdb_key=abuseipdb_key,
            whitelist_domains=current_app.config.get('WHITELIST_DOMAINS', []),
            enable_whois=current_app.config.get('ENABLE_WHOIS', True),
            enable_abuseipdb=current_app.config.get('ENABLE_ABUSEIPDB', True),
            enable_virustotal=current_app.config.get('ENABLE_VIRUSTOTAL', False),
            virustotal_key=virustotal_key,
            enable_auth_verification=current_app.config.get('ENABLE_AUTH_VERIFICATION', True),
            yara_rules_path=current_app.config.get('YARA_RULES_PATH'),
            dns_timeout=current_app.config.get('DNS_TIMEOUT', 5),
            whois_timeout=current_app.config.get('WHOIS_TIMEOUT', 10),
            http_timeout=current_app.config.get('HTTP_TIMEOUT', 10),
        )
        analysis_result = analyzer.analyze(parsed_data)

        analysis_result['metadata'] = {
            'filename': filename,
            'analyzed_at': analysis_result.get('timestamp'),
            'version': '2.0',
        }

        current_app.logger.info('Analysis complete: %s', filename)
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
        if not url.lower().startswith(('http://', 'https://')):
            return jsonify({
                'error': 'Invalid URL',
                'message': 'URL must start with http:// or https://',
            }), 400

        sender_domain = data.get('sender_domain')

        from app.services.url_analyzer import URLAnalyzerService
        result = URLAnalyzerService().analyze_single_url(url, sender_domain)
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
