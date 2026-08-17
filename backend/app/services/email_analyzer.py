"""
Email Analyzer Service
Main analysis orchestrator that coordinates all analysis modules
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Any, Callable, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from app.services.dns_checker import DNSCheckerService
from app.services.whois_service import WhoisService
from app.services.ip_reputation import IPReputationService
from app.services.url_analyzer import URLAnalyzerService
from app.services.content_analyzer import ContentAnalyzerService
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.services.header_forensics import HeaderForensicsService
from app.services.auth_verifier import AuthVerifierService
from app.services.virustotal_service import VirusTotalService
from app.services.yara_scanner import get_scanner
from app.utils.extractors import extract_sender_domain, extract_sender_ip
from app.utils.validators import validate_domain, validate_public_ip

logger = logging.getLogger(__name__)


class EmailAnalyzerService:
    """Coordinates all email analysis modules"""

    def __init__(
        self,
        abuseipdb_key: Optional[str] = None,
        whitelist_domains: Optional[List[str]] = None,
        *,
        enable_whois: bool = True,
        enable_abuseipdb: bool = True,
        enable_virustotal: bool = False,
        virustotal_key: Optional[str] = None,
        enable_auth_verification: bool = True,
        yara_rules_path: Optional[str] = None,
        max_yara_scan_bytes: int = 8 * 1024 * 1024,
        max_archive_members: int = 100,
        max_archive_uncompressed_bytes: int = 200 * 1024 * 1024,
        max_archive_ratio: int = 100,
        max_urls: int = 500,
        max_url_length: int = 4096,
        dns_timeout: int = 5,
        whois_timeout: int = 10,
        http_timeout: int = 10,
    ):
        self.dns_checker = DNSCheckerService(timeout=dns_timeout)
        self.whois_service = (
            WhoisService(timeout=whois_timeout) if enable_whois else None
        )
        self.ip_reputation = (
            IPReputationService(abuseipdb_key, timeout=http_timeout)
            if enable_abuseipdb and abuseipdb_key
            else None
        )
        self.virustotal = (
            VirusTotalService(virustotal_key, timeout=http_timeout)
            if enable_virustotal and virustotal_key
            else None
        )
        self.auth_verifier = (
            AuthVerifierService(timeout=dns_timeout * 2)
            if enable_auth_verification
            else None
        )
        self.yara_scanner = get_scanner(
            yara_rules_path, max_scan_bytes=max_yara_scan_bytes
        )
        self.url_analyzer = URLAnalyzerService(
            max_urls=max_urls,
            max_url_length=max_url_length,
        )
        self.content_analyzer = ContentAnalyzerService()
        self.attachment_analyzer = AttachmentAnalyzerService(
            max_archive_members=max_archive_members,
            max_archive_uncompressed_bytes=max_archive_uncompressed_bytes,
            max_archive_ratio=max_archive_ratio,
        )
        self.header_forensics = HeaderForensicsService()
        self.whitelist_domains = {
            domain.strip().lower()
            for domain in (whitelist_domains or [])
            if validate_domain(domain.strip().lower())
        }
        # Every lookup already enforces its own timeout; this is a safety net
        # so one misbehaving lookup can never stall a whole analysis.
        self.lookup_deadline = max(dns_timeout, whois_timeout, http_timeout) + 5

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
        if sender_domain and not validate_domain(sender_domain):
            sender_domain = None

        sender_ip = extract_sender_ip(headers.get('hops', []))
        if sender_ip and not validate_public_ip(sender_ip):
            sender_ip = None

        # DKIM keys live under the signing domain (d= tag), which may differ
        # from the From: domain (e.g. mail sent via an ESP).
        dkim_signature = headers.get('dkim_signature', '')
        dkim_selector = self.dns_checker.parse_dkim_selector(dkim_signature)
        dkim_domain = self.dns_checker.parse_dkim_domain(dkim_signature)
        if not dkim_domain or not validate_domain(dkim_domain.lower()):
            dkim_domain = sender_domain

        # Local analysis first (CPU only) — its outputs feed the lookups
        combined_text = f"{body_text}\n{body_html}"
        content_analysis = self.content_analyzer.analyze(combined_text, body_html)

        # Analyze URLs (regex over text + href/src attributes from HTML)
        urls = self.url_analyzer.extract_urls(combined_text, body_html)
        url_analysis = self.url_analyzer.analyze_urls(urls, sender_domain)

        # Analyze attachments (includes magic-byte content inspection)
        attachment_analysis = self.attachment_analyzer.analyze_attachments(attachments)

        # YARA scan over body and attachment bytes
        self._apply_yara(
            combined_text, attachments, content_analysis, attachment_analysis
        )

        # External lookups (DNS, WHOIS, IP reputation, VirusTotal, and
        # independent auth verification) are independent — run them
        # concurrently instead of paying each timeout in sequence.
        lookups = self._run_external_lookups(
            sender_domain, sender_ip, dkim_domain, dkim_selector,
            attachment_hashes=[
                a.get('sha256') for a in attachment_analysis.get('attachments', [])
                if a.get('sha256')
            ],
            raw_bytes=parsed_data.get('raw_bytes'),
        )
        spf_record = lookups.get('spf')
        dmarc_record = lookups.get('dmarc')
        dkim_record = lookups.get('dkim')
        whois_data = lookups.get('whois')
        abuse_data = lookups.get('abuse')
        verification = lookups.get('verify')
        reverse_dns = lookups.get('reverse_dns')

        # Merge VirusTotal verdicts into the attachment results
        self._apply_virustotal(lookups.get('vt') or {}, attachment_analysis)

        # Authentication-Results from an uploaded file are display-only claims.
        # Even the topmost header can be fabricated outside a trusted MTA.
        auth_analysis = self._analyze_authentication(
            headers.get('auth_results_top') or headers.get('auth_results', '')
        )

        # Header forensics
        routing_forensics = self.header_forensics.analyze(
            hops=headers.get('hops', []),
            date_header=headers.get('date', ''),
            sender_domain=sender_domain or ''
        )

        # Detect suspicions (now also checks domain age)
        suspicions = self._detect_suspicions(
            headers, abuse_data, auth_analysis,
            url_analysis, attachment_analysis, whois_data,
            verification=verification,
        )

        # Calculate risk score (domain age + compound rules + whitelist)
        risk_score, risk_level, whitelist_applied = self._calculate_risk_score(
            auth_analysis, abuse_data, url_analysis,
            attachment_analysis, content_analysis, suspicions,
            whois_data=whois_data, sender_domain=sender_domain,
            verification=verification,
        )

        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            # Concise "official artifacts" summary — the key, verifiable facts
            # extracted from the message, surfaced up front as a conclusion.
            'conclusion': {
                'sender_address': headers.get('sender'),
                'subject': headers.get('subject'),
                # BCC recipients never appear in delivered headers, so this
                # reflects only the visible To/Cc recipients.
                'recipients': headers.get('recipients'),
                'date': headers.get('date'),
                'sending_server_ip': sender_ip,
                'reverse_dns': reverse_dns,
                'reply_to': headers.get('reply_to'),
            },
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
                'header_claims': auth_analysis,
                'auth_analysis': auth_analysis,
                'verification': verification,
                'spf': spf_record,
                'dmarc': dmarc_record,
                'dkim': dkim_record,
            },
            'sender_info': {
                'domain': sender_domain,
                'ip': sender_ip,
                'reverse_dns': reverse_dns,
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
            'routing_forensics': routing_forensics,
            'suspicions': suspicions,
            'risk_assessment': {
                'score': risk_score,
                'level': risk_level,
                'verdict': self._get_verdict(risk_level),
                'whitelist_applied': whitelist_applied,
            }
        }

    def _apply_yara(
        self,
        combined_text: str,
        attachments: List[Dict[str, Any]],
        content_analysis: Dict[str, Any],
        attachment_analysis: Dict[str, Any],
    ) -> None:
        """Scan body + attachment bytes with YARA and merge matches in place."""
        if not self.yara_scanner.available:
            return

        body_matches = self.yara_scanner.scan(combined_text.encode('utf-8', 'replace'))
        existing = content_analysis.get('yara_matches', [])
        content_analysis['yara_matches'] = list(dict.fromkeys(existing + body_matches))

        analyzed = attachment_analysis.get('attachments', [])
        for original, result in zip(attachments, analyzed):
            data = original.get('data') or b''
            if not data:
                continue
            matches = self.yara_scanner.scan(data)
            if matches:
                result['yara_matches'] = matches
                result['issues'].append('yara_match')
                result['is_suspicious'] = True
                result['severity'] = 'critical'
        attachment_analysis['suspicious_count'] = sum(
            1 for a in analyzed if a.get('is_suspicious')
        )

    def _apply_virustotal(
        self,
        vt_results: Dict[str, Any],
        attachment_analysis: Dict[str, Any],
    ) -> None:
        """Merge VirusTotal verdicts into analyzed attachments in place."""
        if not vt_results:
            return

        analyzed = attachment_analysis.get('attachments', [])
        for result in analyzed:
            verdict = vt_results.get(result.get('sha256'))
            if verdict is None:
                continue
            result['virustotal'] = verdict
            if verdict.get('malicious', 0) > 0:
                result['issues'].append('virustotal_malicious')
                result['is_suspicious'] = True
                result['severity'] = 'critical'
        attachment_analysis['suspicious_count'] = sum(
            1 for a in analyzed if a.get('is_suspicious')
        )

    def _run_external_lookups(
        self,
        sender_domain: Optional[str],
        sender_ip: Optional[str],
        dkim_domain: Optional[str],
        dkim_selector: Optional[str],
        attachment_hashes: Optional[List[str]] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """Run all network lookups concurrently.

        Each service enforces its own timeout; on top of that a global
        deadline bounds the whole batch, and any single failure is logged
        and treated as "no data" rather than failing the analysis.
        """
        jobs: Dict[str, Tuple[Callable[..., Any], tuple]] = {}
        if sender_domain:
            jobs['spf'] = (self.dns_checker.check_spf, (sender_domain,))
            jobs['dmarc'] = (self.dns_checker.check_dmarc, (sender_domain,))
            if self.whois_service:
                jobs['whois'] = (self.whois_service.lookup, (sender_domain,))
        if dkim_domain and dkim_selector:
            jobs['dkim'] = (self.dns_checker.check_dkim, (dkim_domain, dkim_selector))
        if sender_ip:
            jobs['reverse_dns'] = (self.dns_checker.reverse_dns, (sender_ip,))
        if self.ip_reputation and sender_ip:
            jobs['abuse'] = (self.ip_reputation.check_ip, (sender_ip,))
        if self.virustotal and attachment_hashes:
            jobs['vt'] = (self.virustotal.check_hashes, (attachment_hashes,))
        if self.auth_verifier and self.auth_verifier.available and raw_bytes:
            jobs['verify'] = (
                self.auth_verifier.verify,
                (raw_bytes, sender_domain),
            )

        results: Dict[str, Any] = {}
        if not jobs:
            return results

        executor = ThreadPoolExecutor(max_workers=len(jobs))
        try:
            futures = {
                name: executor.submit(fn, *args) for name, (fn, args) in jobs.items()
            }
            deadline = time.monotonic() + self.lookup_deadline
            for name, future in futures.items():
                remaining = max(0.1, deadline - time.monotonic())
                try:
                    results[name] = future.result(timeout=remaining)
                except FutureTimeoutError:
                    logger.warning(f"[EmailAnalyzerService] {name} lookup timed out")
                    results[name] = None
                except Exception as e:
                    logger.warning(f"[EmailAnalyzerService] {name} lookup failed: {e}")
                    results[name] = None
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        return results

    def _analyze_authentication(self, auth_results: str) -> Dict[str, Any]:
        """Parse untrusted Authentication-Results claims for display only."""
        if not auth_results:
            return {
                'spf': None,
                'dkim': None,
                'dmarc': None,
                'trusted': False,
                'source': 'uploaded_header_claim',
            }

        import re
        lower = auth_results.lower()

        def extract_result(name: str) -> Optional[str]:
            m = re.search(rf"{name}\s*=\s*([a-z]+)", lower)
            return m.group(1) if m else None

        return {
            'spf': extract_result('spf'),
            'dkim': extract_result('dkim'),
            'dmarc': extract_result('dmarc'),
            'trusted': False,
            'source': 'uploaded_header_claim',
        }

    def _get_domain_age_days(self, whois_data: Optional[Dict[str, Any]]) -> Optional[int]:
        """Calculate domain age in days from WHOIS creation_date"""
        if not whois_data:
            return None
        creation_str = whois_data.get('creation_date')
        if not creation_str:
            return None
        try:
            creation_dt = datetime.fromisoformat(str(creation_str))
            # Normalise to aware UTC for comparison
            if creation_dt.tzinfo is None:
                creation_dt = creation_dt.replace(tzinfo=timezone.utc)
            else:
                creation_dt = creation_dt.astimezone(timezone.utc)
            return max(0, (datetime.now(timezone.utc) - creation_dt).days)
        except Exception as e:
            logger.warning(f"[EmailAnalyzerService] Failed to parse creation_date {creation_str!r}: {e}")
            return None

    def _detect_suspicions(
        self,
        headers: Dict[str, Any],
        abuse_data: Optional[Dict[str, Any]],
        auth_analysis: Dict[str, Any],
        url_analysis: Dict[str, Any],
        attachment_analysis: Dict[str, Any],
        whois_data: Optional[Dict[str, Any]] = None,
        verification: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, str]]:
        """Detect suspicious indicators"""
        suspicions = []

        def add_suspicion(category: str, severity: str, message: str) -> None:
            suspicions.append({
                'category': category,
                'severity': severity,
                'message': message
            })

        # Header authentication values are not scored: the entire uploaded
        # message can be forged. They remain in authentication.header_claims.

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

        # Check domain age
        domain_age_days = self._get_domain_age_days(whois_data)
        if domain_age_days is not None and domain_age_days < 30:
            add_suspicion(
                'domain_age', 'high',
                f'Domain registered only {domain_age_days} day(s) ago — newly registered domain'
            )

        # Independent DKIM verification is cryptographic and can influence the
        # result. SPF/DMARC are unavailable without trusted SMTP context.
        if verification and verification.get('available'):
            if verification.get('dkim') == 'fail':
                add_suspicion(
                    'authentication',
                    'high',
                    'Independent DKIM signature verification failed',
                )

        # VirusTotal verdicts on attachments
        for attachment in attachment_analysis.get('attachments', []):
            verdict = attachment.get('virustotal') or {}
            if verdict.get('malicious', 0) > 0:
                label = verdict.get('popular_threat_label') or 'malware'
                add_suspicion(
                    'attachments', 'critical',
                    f'VirusTotal: {verdict["malicious"]} engine(s) flag '
                    f'"{attachment.get("filename", "attachment")}" as malicious ({label})'
                )

        return suspicions

    def _calculate_risk_score(
        self,
        auth_analysis: Dict[str, Any],
        abuse_data: Optional[Dict[str, Any]],
        url_analysis: Dict[str, Any],
        attachment_analysis: Dict[str, Any],
        content_analysis: Dict[str, Any],
        suspicions: List[Dict[str, str]],
        whois_data: Optional[Dict[str, Any]] = None,
        sender_domain: Optional[str] = None,
        verification: Optional[Dict[str, Any]] = None
    ) -> tuple:
        """Calculate overall risk score (0-100), risk level, and whitelist flag"""
        score = 0

        # Authentication-Results header claims are deliberately not scored.

        # IP reputation (max 25 points)
        if abuse_data and isinstance(abuse_data.get('abuseConfidenceScore'), int):
            score += min(25, abuse_data['abuseConfidenceScore'] // 4)

        # URLs (max 20 points)
        score += min(20, url_analysis.get('suspicious_count', 0) * 5)

        # Attachments (max 15 points) — weighted by severity so one critical
        # attachment (hidden executable, VT hit) outweighs mild oddities
        severity_points = {'critical': 12, 'high': 8, 'medium': 5, 'low': 2}
        weighted = sum(
            severity_points.get(a.get('severity'), 0)
            for a in attachment_analysis.get('attachments', [])
            if a.get('is_suspicious')
        )
        count_based = attachment_analysis.get('suspicious_count', 0) * 5
        score += min(15, max(weighted, count_based))

        # Content indicators (max 10 points)
        score += min(10, len(content_analysis.get('urgent_phrases', [])) * 2)

        # Domain age scoring
        domain_age_days = self._get_domain_age_days(whois_data)
        if domain_age_days is not None:
            if domain_age_days < 7:
                score += 20
            elif domain_age_days < 30:
                score += 15
            elif domain_age_days < 90:
                score += 8
            elif domain_age_days < 365:
                score += 3

        # Independently verified DKIM failure is cryptographic evidence.
        if verification and verification.get('available'):
            if verification.get('dkim') == 'fail':
                score += 12

        # VirusTotal detections: confirmed malware forces critical
        vt_malicious = max(
            (
                (a.get('virustotal') or {}).get('malicious', 0)
                for a in attachment_analysis.get('attachments', [])
            ),
            default=0,
        )
        if vt_malicious >= 3:
            score = max(score, 85)
        elif vt_malicious >= 1:
            score += 15

        # Compound escalation rules
        abuse_score = (abuse_data or {}).get('abuseConfidenceScore') or 0
        if not isinstance(abuse_score, int):
            abuse_score = 0
        has_executable = any(
            'executable_file' in a.get('issues', [])
            for a in attachment_analysis.get('attachments', [])
        )
        suspicious_url_count = url_analysis.get('suspicious_count', 0)
        urgent_phrase_count = len(content_analysis.get('urgent_phrases', []))

        # Rule 1: new domain + executable attachment → force critical
        if domain_age_days is not None and domain_age_days < 30 and has_executable:
            score = max(score, 85)
            suspicions.append({
                'category': 'compound_escalation',
                'severity': 'critical',
                'message': 'Combined: newly registered domain + executable attachment'
            })

        # Rule 2: young domain + high abuse score → force high
        if domain_age_days is not None and domain_age_days < 90 and abuse_score > 50:
            score = max(score, 75)

        # Rule 3: Many suspicious URLs + urgent content
        if suspicious_url_count >= 3 and urgent_phrase_count > 2:
            score += 10

        # Apply a whitelist discount only when cryptographically valid DKIM is
        # aligned with the visible From domain.
        is_whitelisted = bool(
            sender_domain and sender_domain.lower() in self.whitelist_domains
        )
        whitelist_applied = bool(
            is_whitelisted
            and verification
            and verification.get('dkim') == 'pass'
            and verification.get('dkim_alignment_relaxed') == 'pass'
        )
        # Trust is only a weak positive signal. It must never hide a high or
        # critical score because trusted domains and accounts can be compromised.
        if whitelist_applied and score < 50:
            score = max(0, score - 5)

        # Final cap
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

        return score, risk_level, whitelist_applied

    def _get_verdict(self, risk_level: str) -> str:
        """Get human-readable verdict"""
        verdicts = {
            'critical': 'HIGHLY SUSPICIOUS - Likely phishing or malicious',
            'high': 'SUSPICIOUS - Exercise extreme caution',
            'medium': 'QUESTIONABLE - Review carefully before interacting',
            'low': 'NO STRONG INDICATORS DETECTED - Not a guarantee of safety'
        }
        return verdicts.get(risk_level, 'UNKNOWN')
