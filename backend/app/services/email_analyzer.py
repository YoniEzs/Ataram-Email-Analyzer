"""
Email Analyzer Service
Main analysis orchestrator that coordinates all analysis modules
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from app.services.dns_checker import DNSCheckerService
from app.services.whois_service import WhoisService
from app.services.ip_reputation import IPReputationService
from app.services.url_analyzer import URLAnalyzerService
from app.services.content_analyzer import ContentAnalyzerService
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.utils.extractors import extract_sender_domain, extract_sender_ip


class EmailAnalyzerService:
    """Coordinates all email analysis modules"""

    def __init__(self, abuseipdb_key: Optional[str] = None):
        self.dns_checker = DNSCheckerService()
        self.whois_service = WhoisService()
        self.ip_reputation = IPReputationService(abuseipdb_key) if abuseipdb_key else None
        self.url_analyzer = URLAnalyzerService()
        self.content_analyzer = ContentAnalyzerService()
        self.attachment_analyzer = AttachmentAnalyzerService()

    def analyze(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive email analysis

        Args:
            parsed_data: Output from EmailParserService

        Returns:
            Complete analysis results
        """
        if parsed_data.get('error'):
            return {'error': parsed_data['error']}

        headers = parsed_data.get('headers', {})
        body_text = parsed_data.get('body_text', '')
        body_html = parsed_data.get('body_html', '')
        attachments = parsed_data.get('attachments', [])

        # Extract key information
        sender_domain = extract_sender_domain(headers.get('sender', ''))
        sender_ip = extract_sender_ip(headers.get('hops', []))

        # Perform DNS checks
        spf_record = self.dns_checker.check_spf(sender_domain) if sender_domain else None
        dmarc_record = self.dns_checker.check_dmarc(sender_domain) if sender_domain else None
        dkim_selector = self.dns_checker.parse_dkim_selector(headers.get('dkim_signature', ''))
        dkim_record = self.dns_checker.check_dkim(sender_domain, dkim_selector) if sender_domain else None

        # WHOIS lookup
        whois_data = self.whois_service.lookup(sender_domain) if sender_domain else None

        # IP reputation check
        abuse_data = None
        if self.ip_reputation and sender_ip:
            abuse_data = self.ip_reputation.check_ip(sender_ip)

        # Analyze content
        combined_text = f"{body_text}\n{body_html}"
        content_analysis = self.content_analyzer.analyze(combined_text, body_html)

        # Analyze URLs
        urls = self.url_analyzer.extract_urls(combined_text)
        url_analysis = self.url_analyzer.analyze_urls(urls, sender_domain)

        # Analyze attachments
        attachment_analysis = self.attachment_analyzer.analyze_attachments(attachments)

        # Analyze authentication results
        auth_analysis = self._analyze_authentication(headers.get('auth_results', ''))

        # Detect suspicions
        suspicions = self._detect_suspicions(headers, abuse_data, auth_analysis, url_analysis, attachment_analysis)

        # Calculate risk score
        risk_score, risk_level = self._calculate_risk_score(
            auth_analysis, abuse_data, url_analysis,
            attachment_analysis, content_analysis, suspicions
        )

        return {
            'timestamp': datetime.utcnow().isoformat(),
            'headers': {
                'sender': headers.get('sender'),
                'recipients': headers.get('recipients'),
                'reply_to': headers.get('reply_to'),
                'subject': headers.get('subject'),
                'date': headers.get('date'),
                'message_id': headers.get('message_id'),
                'return_path': headers.get('return_path'),
            },
            'authentication': {
                'auth_results_raw': headers.get('auth_results'),
                'auth_analysis': auth_analysis,
                'spf': spf_record,
                'dmarc': dmarc_record,
                'dkim': dkim_record,
            },
            'sender_info': {
                'domain': sender_domain,
                'ip': sender_ip,
                'whois': whois_data,
                'abuse_report': abuse_data,
            },
            'content': content_analysis,
            'urls': url_analysis,
            'attachments': attachment_analysis,
            'routing': {
                'hops': headers.get('hops', []),
                'hop_count': len(headers.get('hops', []))
            },
            'suspicions': suspicions,
            'risk_assessment': {
                'score': risk_score,
                'level': risk_level,
                'verdict': self._get_verdict(risk_level)
            }
        }

    def _analyze_authentication(self, auth_results: str) -> Dict[str, Any]:
        """Parse authentication results header"""
        if not auth_results:
            return {
                'spf': None,
                'dkim': None,
                'dmarc': None
            }

        import re
        lower = auth_results.lower()

        def extract_result(name: str) -> Optional[str]:
            m = re.search(rf"{name}\s*=\s*([a-z]+)", lower)
            return m.group(1) if m else None

        return {
            'spf': extract_result('spf'),
            'dkim': extract_result('dkim'),
            'dmarc': extract_result('dmarc')
        }

    def _detect_suspicions(
        self,
        headers: Dict[str, Any],
        abuse_data: Optional[Dict[str, Any]],
        auth_analysis: Dict[str, Any],
        url_analysis: Dict[str, Any],
        attachment_analysis: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Detect suspicious indicators"""
        suspicions = []

        def add_suspicion(category: str, severity: str, message: str):
            suspicions.append({
                'category': category,
                'severity': severity,
                'message': message
            })

        # Check authentication failures
        for auth_type, result in auth_analysis.items():
            if result in {'fail', 'softfail', 'permerror'}:
                add_suspicion('authentication', 'high', f'{auth_type.upper()} check failed: {result}')
            elif result in {'none', 'neutral', 'temperror'}:
                add_suspicion('authentication', 'medium', f'{auth_type.upper()} check inconclusive: {result or "none"}')

        # Check domain mismatches
        from app.utils.extractors import email_domain
        from_domain = email_domain(headers.get('sender', ''))
        return_path_domain = email_domain(headers.get('return_path', ''))
        reply_to_domain = email_domain(headers.get('reply_to', ''))

        if from_domain and return_path_domain and from_domain != return_path_domain:
            add_suspicion('headers', 'medium', f'Return-Path domain ({return_path_domain}) differs from sender ({from_domain})')

        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            add_suspicion('headers', 'low', f'Reply-To domain ({reply_to_domain}) differs from sender ({from_domain})')

        # Check IP reputation
        if abuse_data and isinstance(abuse_data.get('abuseConfidenceScore'), int):
            score = abuse_data['abuseConfidenceScore']
            if score >= 70:
                add_suspicion('ip_reputation', 'critical', f'Sender IP has high abuse score: {score}%')
            elif score > 0:
                add_suspicion('ip_reputation', 'medium', f'Sender IP has abuse reports: {score}%')

        # Check URLs
        if url_analysis.get('suspicious_count', 0) > 0:
            add_suspicion('urls', 'high', f'Found {url_analysis["suspicious_count"]} suspicious URLs')

        # Check attachments
        if attachment_analysis.get('suspicious_count', 0) > 0:
            add_suspicion('attachments', 'high', f'Found {attachment_analysis["suspicious_count"]} suspicious attachments')

        return suspicions

    def _calculate_risk_score(
        self,
        auth_analysis: Dict[str, Any],
        abuse_data: Optional[Dict[str, Any]],
        url_analysis: Dict[str, Any],
        attachment_analysis: Dict[str, Any],
        content_analysis: Dict[str, Any],
        suspicions: List[Dict[str, str]]
    ) -> tuple:
        """Calculate overall risk score (0-100) and risk level"""
        score = 0

        # Authentication failures (max 30 points)
        for result in auth_analysis.values():
            if result in {'fail', 'softfail', 'permerror'}:
                score += 10
            elif result in {'none', 'neutral'}:
                score += 5

        # IP reputation (max 25 points)
        if abuse_data and isinstance(abuse_data.get('abuseConfidenceScore'), int):
            score += min(25, abuse_data['abuseConfidenceScore'] // 4)

        # URLs (max 20 points)
        score += min(20, url_analysis.get('suspicious_count', 0) * 5)

        # Attachments (max 15 points)
        score += min(15, attachment_analysis.get('suspicious_count', 0) * 5)

        # Content indicators (max 10 points)
        score += min(10, len(content_analysis.get('urgent_phrases', [])) * 2)

        # Cap at 100
        score = min(100, score)

        # Determine risk level
        if score >= 75:
            risk_level = 'critical'
        elif score >= 50:
            risk_level = 'high'
        elif score >= 25:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        return score, risk_level

    def _get_verdict(self, risk_level: str) -> str:
        """Get human-readable verdict"""
        verdicts = {
            'critical': 'HIGHLY SUSPICIOUS - Likely phishing or malicious',
            'high': 'SUSPICIOUS - Exercise extreme caution',
            'medium': 'QUESTIONABLE - Review carefully before interacting',
            'low': 'APPEARS LEGITIMATE - Standard security measures apply'
        }
        return verdicts.get(risk_level, 'UNKNOWN')
