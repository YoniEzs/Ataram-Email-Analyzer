"""
Email Analysis API Endpoints
"""

from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from app.services.email_parser import EmailParserService
from app.services.email_analyzer import EmailAnalyzerService
from app.utils.validators import allowed_file, validate_email_file
import traceback

bp = Blueprint('analysis', __name__, url_prefix='/api')


@bp.route('/analyze', methods=['POST'])
def analyze_email():
    """
    Analyze uploaded email file

    Accepts: .eml or .msg files
    Returns: JSON analysis results
    """
    try:
        # Validate request
        if 'emailfile' not in request.files:
            return jsonify({
                'error': 'No file provided',
                'message': 'Please upload an email file (.eml or .msg)'
            }), 400

        file = request.files['emailfile']

        if file.filename == '':
            return jsonify({
                'error': 'Empty filename',
                'message': 'Please select a valid file'
            }), 400

        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({
                'error': 'Invalid file type',
                'message': 'Only .eml and .msg files are supported'
            }), 400

        # Get optional API key from request
        abuseipdb_key = request.form.get('abuseipdb_key') or current_app.config.get('ABUSEIPDB_KEY')

        # Read file data
        file_data = file.read()
        filename = secure_filename(file.filename)

        # Validate file content
        is_valid, error_msg = validate_email_file(file_data, filename)
        if not is_valid:
            return jsonify({
                'error': 'Invalid file',
                'message': error_msg
            }), 400

        # Parse email
        current_app.logger.info(f'Parsing email file: {filename}')
        parser = EmailParserService()
        parsed_data = parser.parse_email(file_data, filename)

        if parsed_data.get('error'):
            return jsonify({
                'error': 'Parsing failed',
                'message': parsed_data['error']
            }), 400

        # Analyze email
        current_app.logger.info(f'Analyzing email: {filename}')
        analyzer = EmailAnalyzerService(abuseipdb_key=abuseipdb_key)
        analysis_result = analyzer.analyze(parsed_data)

        # Add metadata
        analysis_result['metadata'] = {
            'filename': filename,
            'analyzed_at': analysis_result.get('timestamp'),
            'version': '2.0'
        }

        current_app.logger.info(f'Analysis completed successfully for: {filename}')
        return jsonify(analysis_result), 200

    except Exception as e:
        current_app.logger.error(f'Error analyzing email: {str(e)}')
        current_app.logger.error(traceback.format_exc())
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred while analyzing the email. Please try again.'
        }), 500


@bp.route('/analyze/url', methods=['POST'])
def analyze_url():
    """
    Analyze a single URL

    Request: {"url": "https://example.com", "sender_domain": "example.com"}
    Returns: URL analysis results
    """
    try:
        data = request.get_json()

        if not data or 'url' not in data:
            return jsonify({
                'error': 'Missing URL',
                'message': 'Please provide a URL to analyze'
            }), 400

        url = data['url']
        sender_domain = data.get('sender_domain')

        from app.services.url_analyzer import URLAnalyzerService
        analyzer = URLAnalyzerService()
        result = analyzer.analyze_single_url(url, sender_domain)

        return jsonify(result), 200

    except Exception as e:
        current_app.logger.error(f'Error analyzing URL: {str(e)}')
        return jsonify({
            'error': 'Analysis failed',
            'message': str(e)
        }), 500


@bp.route('/check/domain', methods=['POST'])
def check_domain():
    """
    Check domain reputation

    Request: {"domain": "example.com"}
    Returns: SPF, DMARC, DKIM, WHOIS info
    """
    try:
        data = request.get_json()

        if not data or 'domain' not in data:
            return jsonify({
                'error': 'Missing domain',
                'message': 'Please provide a domain to check'
            }), 400

        domain = data['domain']

        from app.services.dns_checker import DNSCheckerService
        from app.services.whois_service import WhoisService

        dns_checker = DNSCheckerService()
        whois_service = WhoisService()

        result = {
            'domain': domain,
            'spf': dns_checker.check_spf(domain),
            'dmarc': dns_checker.check_dmarc(domain),
            'whois': whois_service.lookup(domain) if current_app.config['ENABLE_WHOIS'] else None
        }

        return jsonify(result), 200

    except Exception as e:
        current_app.logger.error(f'Error checking domain: {str(e)}')
        return jsonify({
            'error': 'Check failed',
            'message': str(e)
        }), 500


@bp.route('/check/ip', methods=['POST'])
def check_ip():
    """
    Check IP reputation

    Request: {"ip": "1.2.3.4", "abuseipdb_key": "optional"}
    Returns: AbuseIPDB reputation data
    """
    try:
        data = request.get_json()

        if not data or 'ip' not in data:
            return jsonify({
                'error': 'Missing IP',
                'message': 'Please provide an IP address to check'
            }), 400

        ip = data['ip']
        abuseipdb_key = data.get('abuseipdb_key') or current_app.config.get('ABUSEIPDB_KEY')

        if not abuseipdb_key:
            return jsonify({
                'error': 'No API key',
                'message': 'AbuseIPDB API key is required'
            }), 400

        from app.services.ip_reputation import IPReputationService
        ip_service = IPReputationService(abuseipdb_key)
        result = ip_service.check_ip(ip)

        return jsonify(result), 200

    except Exception as e:
        current_app.logger.error(f'Error checking IP: {str(e)}')
        return jsonify({
            'error': 'Check failed',
            'message': str(e)
        }), 500
