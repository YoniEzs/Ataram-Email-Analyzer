"""
Email Analyzer Service
Main analysis orchestrator that coordinates all analysis modules
"""

import logging
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from app.services.dns_checker import DNSCheckerService
from app.services.whois_service import WhoisService
from app.services.ip_reputation import IPReputationService
from app.services.url_analyzer import URLAnalyzerService
from app.services.content_analyzer import ContentAnalyzerService
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.services.header_forensics import HeaderForensicsService
from app.utils.extractors import extract_sender_domain, extract_sender_ip

logger = logging.getLogger(__name__)


# Defaults used when no limits mapping is supplied (direct instantiation in
# tests or scripts). The API passes the app config, so these stay in sync with
# app/config.py rather than being the source of truth.
DEFAULT_LIMITS = {
    'MAX_ANALYZED_BODY_CHARS': 2 * 1024 * 1024,
    'MAX_ANALYZED_HTML_CHARS': 1024 * 1024,
    'MAX_ANALYZED_URLS': 500,
    'MAX_ANALYZED_ATTACHMENTS': 100,
    'MAX_ANALYZED_HOPS': 100,
    'MAX_HOP_CHARS': 4096,
    'DNS_TIMEOUT': 3,
    'WHOIS_TIMEOUT': 5,
    'HTTP_TIMEOUT': 5,
    'LOOKUP_BUDGET_SECONDS': 8,
    'ENABLE_WHOIS': True,
}


class LookupBudget:
    """
    A wall-clock budget shared by every outbound lookup in one request.

    Individual timeouts are not enough. A single analysis performs an SPF query,
    a DMARC query, a DKIM query, a WHOIS lookup (which itself chains IANA →
    registry → registrar) and an AbuseIPDB call — all against infrastructure
    named by the uploaded file. Summed, they exceed what four sync workers can
    absorb at the rate nginx already permits, so one IP staying inside the
    published rate limit can hold every worker indefinitely.

    Once the budget is spent the remaining enrichment is skipped and the result
    is marked `lookups_truncated` rather than silently looking clean.
    """

    def __init__(self, seconds: float):
        self.seconds = max(0.0, float(seconds))
        self._started = time.monotonic()
        self.exhausted = False

    def remaining(self) -> float:
        return max(0.0, self.seconds - (time.monotonic() - self._started))

    def allows(self, minimum: float = 0.5) -> bool:
        if self.remaining() < minimum:
            self.exhausted = True
            return False
        return True


class EmailAnalyzerService:
    """Coordinates all email analysis modules"""

    def __init__(
        self,
        abuseipdb_key: Optional[str] = None,
        whitelist_domains: Optional[List[str]] = None,
        limits: Optional[Dict[str, Any]] = None,
    ):
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}
        # The configured timeouts used to be dead on this path: the services
        # were constructed with no arguments, so DNS_TIMEOUT / WHOIS_TIMEOUT /
        # HTTP_TIMEOUT applied only to the utility endpoints, which are
        # disabled by default. Lowering them in .env changed nothing.
        self.dns_checker = DNSCheckerService(timeout=int(self.limits['DNS_TIMEOUT']))
        self.whois_service = WhoisService(timeout=int(self.limits['WHOIS_TIMEOUT']))
        self.ip_reputation = (
            IPReputationService(abuseipdb_key, timeout=int(self.limits['HTTP_TIMEOUT']))
            if abuseipdb_key else None
        )
        self.url_analyzer = URLAnalyzerService()
        self.content_analyzer = ContentAnalyzerService()
        self.attachment_analyzer = AttachmentAnalyzerService()
        self.header_forensics = HeaderForensicsService()
        self.whitelist_domains = whitelist_domains or []

    def _limit(self, name: str) -> int:
        return int(self.limits.get(name, DEFAULT_LIMITS[name]))

    def _apply_timeout(self, remaining: float) -> None:
        """Clamp each service's own timeout to what is left of the budget."""
        seconds = max(1, int(remaining))
        self.dns_checker.timeout = min(int(self.limits['DNS_TIMEOUT']), seconds)
        self.whois_service.timeout = min(int(self.limits['WHOIS_TIMEOUT']), seconds)
        if self.ip_reputation is not None:
            self.ip_reputation.timeout = min(int(self.limits['HTTP_TIMEOUT']), seconds)

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
        attachments = parsed_data.get('attachments', [])

        # Truncate before any analysis touches the content. Everything below
        # this line does linear-or-worse work over these strings.
        body_text = (parsed_data.get('body_text') or '')[:self._limit('MAX_ANALYZED_BODY_CHARS')]
        body_html = (parsed_data.get('body_html') or '')[:self._limit('MAX_ANALYZED_HTML_CHARS')]
        attachments = attachments[:self._limit('MAX_ANALYZED_ATTACHMENTS')]

        all_hops = headers.get('hops', []) or []
        # Bound the count AND the length of each hop: MAX_ANALYZED_HOPS capped
        # only how many were kept, so 100 multi-megabyte Received headers were
        # still serialised into the JSON response in full.
        max_hop_chars = self._limit('MAX_HOP_CHARS')
        hops = [str(h)[:max_hop_chars] for h in all_hops[:self._limit('MAX_ANALYZED_HOPS')]]
        # The parser truncates before this point, so the true count has to come
        # from the parser. Without it a 300-hop email reported 100 hops and
        # hops_truncated=False.
        total_hops = parsed_data.get('total_hop_count')
        if not isinstance(total_hops, int) or total_hops < len(all_hops):
            total_hops = len(all_hops)

        # Extract key information
        sender_domain = extract_sender_domain(headers.get('sender', ''))
        sender_ip = extract_sender_ip(hops)

        # All outbound lookups share one wall-clock budget. Each of these blocks
        # a whole sync worker against a host the uploaded file chose.
        budget = LookupBudget(self.limits['LOOKUP_BUDGET_SECONDS'])

        def within_budget(fn, *args):
            """
            Run a lookup only if the budget allows, and only for as long as the
            budget has left.

            Checking the budget beforehand is not enough on its own: it bounds
            how many lookups start, not how long one runs. With five lookups
            each permitted their full individual timeout, a single request held
            a worker for 39 seconds against an 8-second budget. Shrinking each
            call's own timeout to the remaining budget makes the total an
            actual deadline.
            """
            if not budget.allows():
                return None
            self._apply_timeout(budget.remaining())
            try:
                return fn(*args)
            except Exception as e:
                logger.warning(f'[EmailAnalyzerService] Lookup failed: {type(e).__name__}')
                return None

        # Perform DNS checks
        spf_record = within_budget(self.dns_checker.check_spf, sender_domain) if sender_domain else None
        dmarc_record = within_budget(self.dns_checker.check_dmarc, sender_domain) if sender_domain else None
        dkim_selector = self.dns_checker.parse_dkim_selector(headers.get('dkim_signature', ''))
        dkim_record = (
            within_budget(self.dns_checker.check_dkim, sender_domain, dkim_selector)
            if sender_domain and dkim_selector else None
        )

        # WHOIS lookup. ENABLE_WHOIS was honoured only on the utility endpoint,
        # so an operator could not switch off the expensive lookup where it
        # actually runs.
        whois_data = (
            within_budget(self.whois_service.lookup, sender_domain)
            if sender_domain and self.limits.get('ENABLE_WHOIS', True) else None
        )

        # IP reputation check
        abuse_data = None
        if self.ip_reputation and sender_ip:
            abuse_data = within_budget(self.ip_reputation.check_ip, sender_ip)

        # Analyze content
        combined_text = f"{body_text}\n{body_html}"
        content_analysis = self.content_analyzer.analyze(combined_text, body_html)

        # Analyze URLs. A crafted body can contain hundreds of thousands of
        # links; only the first MAX_ANALYZED_URLS are examined.
        #
        # Union the raw-source regex hits with the links the HTML parser
        # actually resolved. A regex over unparsed source cannot see an href
        # written with HTML entities (&#104;ttp://…) or a protocol-relative
        # //evil.tld — both of which a mail client renders as a live link. Any
        # URL hidden from this step scored zero.
        max_urls = self._limit('MAX_ANALYZED_URLS')
        urls = self.url_analyzer.extract_urls(combined_text, max_urls)
        dom_urls = content_analysis.get('dom_urls', []) or []
        for candidate in dom_urls:
            if len(urls) >= max_urls:
                break
            if candidate not in urls:
                urls.append(candidate)
        url_analysis = self.url_analyzer.analyze_urls(urls, sender_domain)

        # Analyze attachments
        attachment_analysis = self.attachment_analyzer.analyze_attachments(attachments)

        # Analyze authentication results
        auth_analysis = self._analyze_authentication(headers.get('auth_results', ''))

        # Header forensics
        routing_forensics = self.header_forensics.analyze(
            hops=hops,
            date_header=headers.get('date', ''),
            sender_domain=sender_domain or ''
        )

        # Detect suspicions (now also checks domain age)
        suspicions = self._detect_suspicions(
            headers, abuse_data, auth_analysis,
            url_analysis, attachment_analysis, whois_data,
            content_analysis=content_analysis,
            spf_record=spf_record, dmarc_record=dmarc_record,
            sender_domain=sender_domain,
        )

        # Calculate risk score (domain age + compound rules + whitelist)
        risk_score, risk_level, whitelist_applied, sender_domain_is_trusted = self._calculate_risk_score(
            auth_analysis, abuse_data, url_analysis,
            attachment_analysis, content_analysis, suspicions,
            whois_data=whois_data, sender_domain=sender_domain,
            spf_record=spf_record, dmarc_record=dmarc_record,
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
                # Parsed from a header INSIDE the uploaded file. Whoever sent
                # the mail wrote it, so it is reportable evidence and nothing
                # more — the flag exists so the UI can say so rather than
                # showing a reassuring green "SPF: pass" the sender chose.
                'auth_analysis': auth_analysis,
                'auth_analysis_is_self_reported': True,
                # Retrieved by this server over DNS; the sender cannot forge these.
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
            # Signals that enrichment was cut short, so an absent SPF/WHOIS
            # result is not mistaken for a clean one.
            'lookups_truncated': budget.exhausted,
            'content': content_analysis,
            'urls': url_analysis,
            'attachments': attachment_analysis,
            'routing': {
                'hops': hops,
                'hop_count': total_hops,
                'hops_truncated': total_hops > len(hops),
            },
            'routing_forensics': routing_forensics,
            'suspicions': suspicions,
            'risk_assessment': {
                'score': risk_score,
                'level': risk_level,
                'verdict': self._get_verdict(risk_level),
                # Always False. Kept so existing consumers of the JSON do not
                # break; the trusted-sender list no longer lowers any score.
                'whitelist_applied': whitelist_applied,
                # Informational only: the From domain appears on the operator's
                # trusted list. The From header is unauthenticated, so this says
                # what the message CLAIMS, and deliberately affects nothing.
                'sender_domain_is_trusted': sender_domain_is_trusted,
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

    def _get_domain_age_days(self, whois_data: Optional[Dict[str, Any]]) -> Optional[int]:
        """Calculate domain age in days from WHOIS creation_date"""
        if not whois_data:
            return None
        creation_str = whois_data.get('creation_date')
        if not creation_str:
            return None
        try:
            creation_dt = datetime.fromisoformat(str(creation_str))
            # Normalise to naive UTC for comparison
            if creation_dt.tzinfo is not None:
                creation_dt = creation_dt.astimezone(timezone.utc).replace(tzinfo=None)
            return max(0, (datetime.utcnow() - creation_dt).days)
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
        content_analysis: Optional[Dict[str, Any]] = None,
        spf_record: Optional[str] = None,
        dmarc_record: Optional[str] = None,
        sender_domain: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        """Detect suspicious indicators"""
        suspicions = []
        content_analysis = content_analysis or {}

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

        # Check URLs. The severity has to reflect what was actually found:
        # a blanket 'high' meant an unsubscribe link containing "url=" produced
        # the same indicator as a punycode homograph, and — once the risk level
        # is floored at the worst suspicion — flagged ordinary newsletters as
        # high risk.
        suspicious_urls = url_analysis.get('suspicious_count', 0)
        if suspicious_urls > 0:
            strong_url_issues = {
                'brand_impersonation_in_host', 'host_parser_confusion',
                'punycode_domain', 'invalid_host_characters', 'ip_address_host',
                'url_contains_at_sign', 'shortened_url',
            }
            has_strong = any(
                set(u.get('issues', [])) & strong_url_issues
                for u in url_analysis.get('urls', [])
            )
            add_suspicion(
                'urls', 'high' if has_strong else 'medium',
                f'Found {suspicious_urls} suspicious URLs'
            )

        # Check attachments — severity taken from the worst attachment rather
        # than assumed. `invoice.pdf` merely matches a filename keyword.
        suspicious_attachments = attachment_analysis.get('suspicious_count', 0)
        if suspicious_attachments > 0:
            worst_attachment = 'low'
            order = ['low', 'medium', 'high', 'critical']
            for attachment in attachment_analysis.get('attachments', []):
                severity = attachment.get('severity', 'low')
                if attachment.get('is_suspicious') and severity in order:
                    if order.index(severity) > order.index(worst_attachment):
                        worst_attachment = severity
            add_suspicion(
                'attachments', worst_attachment,
                f'Found {suspicious_attachments} suspicious attachments'
            )

        # Credential harvesting, detected structurally. Without this a complete
        # phishing page with a masked password field produced an empty
        # suspicions list and a "low" banner.
        if content_analysis.get('credential_inputs'):
            add_suspicion(
                'content', 'critical',
                'Email contains a password-style input field — legitimate senders do not '
                'collect credentials inside an email'
            )
        elif content_analysis.get('forms'):
            add_suspicion(
                'content', 'high',
                'Email contains an HTML form, which legitimate mail almost never does'
            )
        if content_analysis.get('external_form_actions'):
            add_suspicion(
                'content', 'high',
                'A form in this email submits to an external address'
            )

        # Records this server retrieved itself — unlike Authentication-Results,
        # the sender cannot forge these.
        if sender_domain:
            if not spf_record:
                add_suspicion('authentication', 'medium',
                              f'{sender_domain} publishes no SPF record')
            if not dmarc_record:
                add_suspicion('authentication', 'medium',
                              f'{sender_domain} publishes no DMARC policy')

        # Check domain age
        domain_age_days = self._get_domain_age_days(whois_data)
        if domain_age_days is not None and domain_age_days < 30:
            add_suspicion(
                'domain_age', 'high',
                f'Domain registered only {domain_age_days} day(s) ago — newly registered domain'
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
        spf_record: Optional[str] = None,
        dmarc_record: Optional[str] = None,
    ) -> tuple:
        """Calculate overall risk score (0-100), risk level, and whitelist flag"""
        score = 0

        # Authentication failures (max 30 points).
        #
        # `None` means the uploaded file carried no Authentication-Results
        # header at all. That used to score ZERO — so omitting the header
        # entirely was worth 15-30 points less than honestly reporting a
        # failure, and simply deleting one header was the cheapest score
        # reduction available. An absent claim is not evidence of a pass.
        # A CLAIMED pass earns no credit. This header is written by whoever
        # sent the mail, so `spf=pass` is an assertion, not evidence — and
        # while it earned a discount, adding one line to a phishing sample was
        # worth 15 points (measured: 91 -> 76). An unverifiable claim of
        # success carries exactly as much information as saying nothing, so it
        # is scored the same as silence.
        #
        # An admitted FAILURE is different: nobody forges a failure, so it is
        # trustworthy evidence and still costs more.
        for result in auth_analysis.values():
            if result in {'fail', 'softfail', 'permerror'}:
                score += 10
            # Everything else — 'pass', 'none', 'neutral', 'temperror' or the
            # header being absent — scores ZERO. None of it is verifiable, and
            # scoring any of it creates a lever the sender controls: while a
            # claimed pass earned credit, one forged line was worth 15 points;
            # while silence was scored, ordinary mail was penalised for a
            # header its provider simply did not add.
            #
            # The penalty for genuinely unauthenticated mail comes from the
            # SPF/DMARC records this server retrieves itself, below. Those
            # cannot be forged by the sender, and they apply equally whether
            # the file admits, denies or omits its own authentication.

        # IP reputation (max 25 points)
        if abuse_data and isinstance(abuse_data.get('abuseConfidenceScore'), int):
            score += min(25, abuse_data['abuseConfidenceScore'] // 4)

        # URLs (max 20 points)
        score += min(20, url_analysis.get('suspicious_count', 0) * 5)

        # Attachments (max 15 points)
        score += min(15, attachment_analysis.get('suspicious_count', 0) * 5)

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

        # Compound escalation rules
        spf_result = auth_analysis.get('spf', '') or ''
        spf_fails = spf_result in {'fail', 'softfail', 'permerror'}
        abuse_score = (abuse_data or {}).get('abuseConfidenceScore') or 0
        if not isinstance(abuse_score, int):
            abuse_score = 0
        has_executable = any(
            'executable_file' in a.get('issues', [])
            for a in attachment_analysis.get('attachments', [])
        )
        suspicious_url_count = url_analysis.get('suspicious_count', 0)
        urgent_phrase_count = len(content_analysis.get('urgent_phrases', []))

        # Rule 1: SPF fail + new domain + executable attachment → force critical
        compound_critical = False
        if spf_fails and domain_age_days is not None and domain_age_days < 30 and has_executable:
            score = max(score, 85)
            compound_critical = True
            suspicions.append({
                'category': 'compound_escalation',
                'severity': 'critical',
                'message': 'Combined: SPF failure + newly registered domain + executable attachment'
            })

        # Rule 2: SPF fail + young domain + high abuse score → force high
        if spf_fails and domain_age_days is not None and domain_age_days < 90 and abuse_score > 50:
            score = max(score, 75)

        # Rule 3: Many suspicious URLs + urgent content
        if suspicious_url_count >= 3 and urgent_phrase_count > 2:
            score += 10

        # Score the signals the analyzers already compute. These were displayed
        # in the UI but contributed nothing, so an email with a credential-
        # harvesting form, hidden elements and anchor-text mismatches could
        # still be scored 'low'.
        yara_matches = content_analysis.get('yara_matches', []) or []
        if 'PhishingForm' in yara_matches:
            score += 15
        if any(m.startswith('Kit:') for m in yara_matches):
            score += 15
        if 'ObfuscatedJS' in yara_matches or 'JSRedirect' in yara_matches:
            score += 5
        anchor_mismatches = content_analysis.get('anchor_mismatches', []) or []
        if anchor_mismatches:
            score += min(10, 5 * len(anchor_mismatches))
        if content_analysis.get('hidden_elements'):
            score += 3

        # Structural credential-harvesting detection.
        #
        # This used to require `forms AND credential_requests`, where the
        # latter was a keyword match on the body text. A masked input written
        # as <input type="text" style="-webkit-text-security:disc"> renders as
        # a password box while containing none of those words, so a complete
        # Microsoft-365 credential harvester scored exactly 0 and was reported
        # as "APPEARS LEGITIMATE". A form in an email is the pattern itself.
        credential_inputs = content_analysis.get('credential_inputs', 0) or 0
        form_count = content_analysis.get('forms', 0) or 0
        if credential_inputs:
            score += 30
        elif form_count and content_analysis.get('credential_requests'):
            score += 20
        elif form_count:
            score += 12

        # A form that posts off-domain is exfiltration by construction.
        if content_analysis.get('external_form_actions'):
            score += 10

        # Severity-weighted attachments: one .exe is not equivalent to one
        # innocuous .zip, but flat suspicious_count treated them identically.
        for attachment in attachment_analysis.get('attachments', []):
            issues = attachment.get('issues', [])
            if any(i in issues for i in
                   ('executable_file', 'double_extension', 'shortcut_file')):
                score = max(score, 70)
                break
            # The bytes contradict the name: a disguise is stronger evidence
            # than either the name or the content would be alone.
            if any(i.startswith('content_mismatch:') for i in issues):
                score = max(score, 70)
                break
            if 'script_file' in issues or 'possible_macro_document' in issues:
                score = max(score, 55)

        # The SPF/DMARC/DKIM records this server actually retrieved were
        # displayed but never scored — only the attacker's own header was.
        # A domain publishing no SPF and no DMARC is a real signal, and unlike
        # Authentication-Results it cannot be forged by the sender.
        if sender_domain:
            if not spf_record:
                score += 8
            if not dmarc_record:
                score += 8
            elif 'p=none' in (dmarc_record or '').lower():
                score += 4

        # THE WHITELIST NO LONGER CAPS THE SCORE. It is reported for context
        # only, and `sender_domain_is_trusted` says exactly that.
        #
        # The cap was unsound in principle, not merely misconfigured. Every
        # input gating it is chosen by the attacker:
        #   * `sender_domain` comes from the From header, which is unauthenticated
        #     by definition;
        #   * `spf_result` comes from the Authentication-Results header inside
        #     the uploaded file, which the sender writes.
        # Requiring DNS-verified SPF and DMARC records looked like a fix, but
        # those are looked up for the SPOOFED domain — so spoofing
        # `From: security@microsoft.com` satisfies the gate using Microsoft's
        # own real DNS. Every domain worth impersonating publishes both records.
        #
        # SPF cannot be verified from a file at all: it authenticates the SMTP
        # envelope sender against the connecting IP, and an offline .eml has
        # neither. A signal that can only ever LOWER risk, and that an attacker
        # can switch on at will, is worse than no signal.
        #
        # Removing it costs nothing in false positives — legitimate mail scores
        # 0-13 here without any cap (see TestNoFalsePositives).
        sender_domain_is_trusted = bool(
            sender_domain and
            sender_domain.lower() in [d.lower() for d in self.whitelist_domains]
        )
        whitelist_applied = False

        highest_suspicion = self._highest_severity(suspicions)

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

        # A banner reading 'low' above a list containing a critical indicator is
        # worse than no banner: it actively reassures. But floor the level ONE
        # step below the worst finding rather than at it — promoting the banner
        # straight to the severity of any single heuristic makes routine mail
        # (a newsletter whose unsubscribe link contains "url=") read as high
        # risk, and a tool that cries wolf gets ignored.
        floor = {'critical': 'high', 'high': 'medium'}.get(highest_suspicion)
        if floor:
            risk_level = self._max_level(risk_level, floor)

        return score, risk_level, whitelist_applied, sender_domain_is_trusted

    @staticmethod
    def _highest_severity(suspicions: List[Dict[str, str]]) -> str:
        order = ['low', 'medium', 'high', 'critical']
        worst = 'low'
        for suspicion in suspicions:
            severity = suspicion.get('severity', 'low')
            if severity in order and order.index(severity) > order.index(worst):
                worst = severity
        return worst

    @staticmethod
    def _max_level(a: str, b: str) -> str:
        order = ['low', 'medium', 'high', 'critical']
        try:
            return a if order.index(a) >= order.index(b) else b
        except ValueError:
            return a

    def _get_verdict(self, risk_level: str) -> str:
        """Get human-readable verdict"""
        verdicts = {
            'critical': 'HIGHLY SUSPICIOUS - Likely phishing or malicious',
            'high': 'SUSPICIOUS - Exercise extreme caution',
            'medium': 'QUESTIONABLE - Review carefully before interacting',
            'low': 'APPEARS LEGITIMATE - Standard security measures apply'
        }
        return verdicts.get(risk_level, 'UNKNOWN')
