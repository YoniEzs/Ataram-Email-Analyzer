"""
Email Analysis API Endpoints
"""

from functools import wraps

from flask import Blueprint, request, jsonify, current_app, abort
from werkzeug.exceptions import HTTPException
from app.services.email_parser import EmailParserService
from app.services.email_analyzer import EmailAnalyzerService
from app.utils.validators import (
    allowed_file,
    validate_email_file,
    validate_header_block,
    validate_mime_headers,
    validate_mime_structure,
    safe_display_filename,
)
from app.utils.net_guard import (
    validate_domain_input,
    validate_ip_input,
    validate_url_input,
)
from app import limiter
import traceback

bp = Blueprint('analysis', __name__, url_prefix='/api')

# Cap on a JSON body for the utility endpoints. They carry one short string;
# anything larger is either a mistake or an attempt to make the server allocate.
MAX_JSON_BODY_BYTES = 8 * 1024


def utility_endpoint(view):
    """
    Gate an endpoint behind ENABLE_UTILITY_ENDPOINTS.

    Responds 404 rather than 403 when disabled, so a disabled deployment does
    not advertise that the endpoint exists at all.
    """

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_app.config.get('ENABLE_UTILITY_ENDPOINTS', False):
            abort(404)
        return view(*args, **kwargs)

    return wrapper


def _reject_oversized_json():
    """
    Return an error response if the JSON body is implausibly large.

    Content-Length alone is not enough: with `Transfer-Encoding: chunked` there
    is no Content-Length at all, so the check was simply skipped and an
    arbitrarily large body reached the JSON parser. When the length is absent,
    read the body with an explicit cap instead of trusting the header.
    """
    length = request.content_length
    if length is not None:
        if length > MAX_JSON_BODY_BYTES:
            return jsonify({
                'error': 'Request too large',
                'message': 'The request body is larger than this endpoint accepts.'
            }), 413
        return None

    # Chunked request: measure what actually arrives.
    body = request.get_data(cache=True, as_text=False)
    if len(body) > MAX_JSON_BODY_BYTES:
        return jsonify({
            'error': 'Request too large',
            'message': 'The request body is larger than this endpoint accepts.'
        }), 413
    return None


def is_msg_upload(file_data: bytes, filename: str) -> bool:
    """MSG files are an OLE container, so the RFC 5322 header guard does not apply."""
    return EmailParserService.is_probably_msg(file_data, filename)


def _limit(config_key: str, fallback: str):
    """
    Read a rate limit from app config at request time.

    Flask-Limiter accepts a callable here, which is what lets the limits stay
    configurable per deployment instead of being frozen at import.
    """
    return lambda: current_app.config.get(config_key, fallback)


# NOTE ON DECORATOR ORDER: @bp.route must be the OUTERMOST decorator. With
# @limiter.limit above it, the route registers the undecorated function and the
# limit is silently never enforced — which is exactly how this file used to
# read, leaving every endpoint unlimited.
@bp.route('/analyze', methods=['POST'])
@limiter.limit(_limit('RATELIMIT_ANALYZE', '10 per minute;60 per hour'))
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

        if not file.filename:
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

        # API key comes from server config only — never trust client-supplied keys
        abuseipdb_key = current_app.config.get('ABUSEIPDB_KEY')

        # Read at most one byte more than the limit so an oversized body is
        # detected here too, not only by Werkzeug's MAX_CONTENT_LENGTH check.
        max_bytes = current_app.config['MAX_CONTENT_LENGTH']
        file_data = file.read(max_bytes + 1)
        if len(file_data) > max_bytes:
            return jsonify({
                'error': 'File too large',
                'message': f'The upload exceeds the {max_bytes // (1024 * 1024)}MB limit.'
            }), 413

        filename = safe_display_filename(file.filename)

        # Validate file content
        is_valid, error_msg = validate_email_file(file_data, filename, max_bytes)
        if not is_valid:
            return jsonify({
                'error': 'Invalid file',
                'message': error_msg
            }), 400

        # Bound the header block BEFORE the parser is allowed to touch it.
        # Python's email package parses header values lazily and
        # super-linearly, so one crafted header in a file well under the upload
        # limit costs minutes of CPU and kills the worker. This guard runs on
        # raw bytes because by the time a header value has been read, the cost
        # has already been paid.
        if not is_msg_upload(file_data, filename):
            header_ok, header_error = validate_header_block(
                file_data,
                max_block_bytes=current_app.config['MAX_HEADER_BLOCK_BYTES'],
                max_line_bytes=current_app.config['MAX_HEADER_LINE_BYTES'],
                max_headers=current_app.config['MAX_HEADER_COUNT'],
            )
            if not header_ok:
                return jsonify({
                    'error': 'Invalid file',
                    'message': header_error
                }), 400

            # Same reasoning for the body: the message tree is built in full
            # before any traversal cap can apply, so a part flood has to be
            # refused from the raw bytes.
            mime_ok, mime_error = validate_mime_structure(
                file_data,
                max_parts=current_app.config['MAX_MIME_PARTS'],
            )
            if not mime_ok:
                return jsonify({
                    'error': 'Invalid file',
                    'message': mime_error
                }), 400

            # And the sub-part headers, which sit AFTER the top-level block and
            # so are invisible to validate_header_block. A single sub-part
            # Content-Type carrying 200,000 parameters cost 337s of CPU and
            # 698MB of RSS while passing every other guard.
            # MAX_HEADER_LINE_BYTES (16KB) is the RFC 5322 line limit and is
            # right for a top-level header. It is far too generous for a MIME
            # sub-part Content-Type — passing it here silently reinstated
            # exactly the limit validate_mime_headers' own default rejects, and
            # 16 sub-parts at 16KB cost 133 seconds of CPU. Use the tighter,
            # separately configured sub-part budget.
            sub_ok, sub_error = validate_mime_headers(
                file_data,
                max_line_bytes=current_app.config['MAX_MIME_HEADER_BYTES'],
                max_headers=current_app.config['MAX_MIME_PARTS'] * 5,
                max_total_bytes=current_app.config['MAX_MIME_HEADER_TOTAL_BYTES'],
                max_params=current_app.config['MAX_MIME_HEADER_PARAMS'],
            )
            if not sub_ok:
                return jsonify({
                    'error': 'Invalid file',
                    'message': sub_error
                }), 400

        # Parse email. The filename is never logged: it is attacker-controlled
        # and frequently contains the user's own private context.
        current_app.logger.info('Parsing uploaded email file')
        parser = EmailParserService(limits=current_app.config)
        parsed_data = parser.parse_email(file_data, filename)

        if parsed_data.get('error'):
            return jsonify({
                'error': 'Parsing failed',
                'message': parsed_data['error']
            }), 400

        # Analyze email
        analyzer = EmailAnalyzerService(
            abuseipdb_key=abuseipdb_key,
            whitelist_domains=current_app.config.get('WHITELIST_DOMAINS', []),
            limits=current_app.config,
        )
        analysis_result = analyzer.analyze(parsed_data)

        # Add metadata
        analysis_result['metadata'] = {
            'filename': filename,
            'analyzed_at': analysis_result.get('timestamp'),
            'version': '2.0'
        }

        current_app.logger.info('Analysis completed successfully')
        return jsonify(analysis_result), 200

    except HTTPException:
        # 413 (upload over the limit), 404 from the utility gate and friends
        # carry their own correct status. Swallowing them into the generic
        # handler below reported every one of them as a 500.
        raise
    except Exception as e:
        current_app.logger.error(f'Error analyzing email: {type(e).__name__}')
        if current_app.debug:
            current_app.logger.debug(traceback.format_exc())
        return jsonify({
            'error': 'Internal server error',
            'message': 'An error occurred while analyzing the email. Please try again.'
        }), 500


@bp.route('/analyze/url', methods=['POST'])
@limiter.limit(_limit('RATELIMIT_URL', '50 per minute;500 per hour'))
@utility_endpoint
def analyze_url():
    """
    Analyze a single URL

    Request: {"url": "https://example.com", "sender_domain": "example.com"}
    Returns: URL analysis results
    """
    try:
        oversized = _reject_oversized_json()
        if oversized:
            return oversized

        data = request.get_json(silent=True)

        if not isinstance(data, dict) or 'url' not in data:
            return jsonify({
                'error': 'Missing URL',
                'message': 'Please provide a URL to analyze'
            }), 400

        is_valid, url, error_msg = validate_url_input(data['url'])
        if not is_valid:
            return jsonify({'error': 'Invalid URL', 'message': error_msg}), 400

        # sender_domain only ever feeds a string comparison, but it is still
        # user input and must not be an arbitrary object or an unbounded string.
        sender_domain = data.get('sender_domain')
        if sender_domain is not None:
            domain_ok, sender_domain, domain_err = validate_domain_input(sender_domain)
            if not domain_ok:
                return jsonify({'error': 'Invalid sender_domain', 'message': domain_err}), 400

        from app.services.url_analyzer import URLAnalyzerService
        analyzer = URLAnalyzerService()
        result = analyzer.analyze_single_url(url, sender_domain)

        return jsonify(result), 200

    except HTTPException:
        # 413 (upload over the limit), 404 from the utility gate and friends
        # carry their own correct status. Swallowing them into the generic
        # handler below reported every one of them as a 500.
        raise
    except Exception as e:
        current_app.logger.error(f'Error analyzing URL: {type(e).__name__}')
        if current_app.debug:
            current_app.logger.debug(traceback.format_exc())
        return jsonify({
            'error': 'Analysis failed',
            'message': 'An error occurred while analyzing the URL.'
        }), 500


@bp.route('/check/domain', methods=['POST'])
@limiter.limit(_limit('RATELIMIT_LOOKUP', '30 per minute;300 per hour'))
@utility_endpoint
def check_domain():
    """
    Check domain reputation

    Request: {"domain": "example.com"}
    Returns: SPF, DMARC, WHOIS info
    """
    try:
        oversized = _reject_oversized_json()
        if oversized:
            return oversized

        data = request.get_json(silent=True)

        if not isinstance(data, dict) or 'domain' not in data:
            return jsonify({
                'error': 'Missing domain',
                'message': 'Please provide a domain to check'
            }), 400

        # This endpoint makes the server perform DNS and WHOIS lookups on
        # demand. Without this check it is a resolver for internal names and an
        # amplifier pointed at whatever the caller names.
        is_valid, domain, error_msg = validate_domain_input(data['domain'])
        if not is_valid:
            return jsonify({'error': 'Invalid domain', 'message': error_msg}), 400

        from app.services.dns_checker import DNSCheckerService
        from app.services.whois_service import WhoisService

        dns_checker = DNSCheckerService(timeout=current_app.config.get('DNS_TIMEOUT', 5))
        whois_service = WhoisService(timeout=current_app.config.get('WHOIS_TIMEOUT', 10))

        result = {
            'domain': domain,
            'spf': dns_checker.check_spf(domain),
            'dmarc': dns_checker.check_dmarc(domain),
            'whois': whois_service.lookup(domain) if current_app.config['ENABLE_WHOIS'] else None
        }

        return jsonify(result), 200

    except HTTPException:
        # 413 (upload over the limit), 404 from the utility gate and friends
        # carry their own correct status. Swallowing them into the generic
        # handler below reported every one of them as a 500.
        raise
    except Exception as e:
        current_app.logger.error(f'Error checking domain: {type(e).__name__}')
        if current_app.debug:
            current_app.logger.debug(traceback.format_exc())
        return jsonify({
            'error': 'Check failed',
            'message': 'An error occurred while checking the domain.'
        }), 500


@bp.route('/check/ip', methods=['POST'])
@limiter.limit(_limit('RATELIMIT_LOOKUP', '30 per minute;300 per hour'))
@utility_endpoint
def check_ip():
    """
    Check IP reputation

    Request: {"ip": "1.2.3.4"}
    Returns: AbuseIPDB reputation data
    """
    try:
        oversized = _reject_oversized_json()
        if oversized:
            return oversized

        data = request.get_json(silent=True)

        if not isinstance(data, dict) or 'ip' not in data:
            return jsonify({
                'error': 'Missing IP',
                'message': 'Please provide an IP address to check'
            }), 400

        # Reject loopback, RFC1918 and link-local (169.254.169.254 cloud
        # metadata) before anything is sent upstream.
        is_valid, ip, error_msg = validate_ip_input(data['ip'])
        if not is_valid:
            return jsonify({'error': 'Invalid IP', 'message': error_msg}), 400

        # API key comes from server config only
        abuseipdb_key = current_app.config.get('ABUSEIPDB_KEY')

        if not abuseipdb_key:
            return jsonify({
                'error': 'No API key',
                'message': 'AbuseIPDB API key is not configured on this server'
            }), 400

        from app.services.ip_reputation import IPReputationService
        ip_service = IPReputationService(
            abuseipdb_key,
            timeout=current_app.config.get('HTTP_TIMEOUT', 10),
        )
        result = ip_service.check_ip(ip)

        return jsonify(result), 200

    except HTTPException:
        # 413 (upload over the limit), 404 from the utility gate and friends
        # carry their own correct status. Swallowing them into the generic
        # handler below reported every one of them as a 500.
        raise
    except Exception as e:
        current_app.logger.error(f'Error checking IP: {type(e).__name__}')
        if current_app.debug:
            current_app.logger.debug(traceback.format_exc())
        return jsonify({
            'error': 'Check failed',
            'message': 'An error occurred while checking the IP address.'
        }), 500
