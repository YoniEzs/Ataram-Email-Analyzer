"""
Email Analyzer Service
Main analysis orchestrator that coordinates all analysis modules
"""

import logging
import time
from functools import partial
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Any, Callable, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from app.services.artifact_extractor import (
    ArtifactExtractorService,
    collect_flags,
)
from app.services.dns_checker import DNSCheckerService
from app.services.ip_intel import IPIntelService
from app.services.spf_advisor import SPFAdvisorService
from app.services.whois_service import WhoisService
from app.services.ip_reputation import IPReputationService
from app.services.url_analyzer import URLAnalyzerService
from app.services.content_analyzer import ContentAnalyzerService
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.services.header_forensics import HeaderForensicsService
from app.services.auth_verifier import AuthVerifierService
from app.services.virustotal_service import VirusTotalService
from app.services.yara_scanner import get_scanner
from app.utils.domains import registered_domain
from app.utils.extractors import extract_sender_domain, extract_sender_ip
from app.utils.validators import validate_domain, validate_public_ip

logger = logging.getLogger(__name__)


# Artifact flags that contribute to the risk score, and by how much.
#
# The rule for inclusion is that an attacker who controls the uploaded file
# cannot make the signal go away by editing headers:
#   observed  - re-queried from DNS at analysis time
#   computed  - a property of the attacker's own chosen string, where choosing
#               it is itself the evidence (script mixing, self-contradiction)
#
# Everything else is shown to the analyst and scored at zero. In particular
# ptr_helo_mismatch is the sharpest new indicator here, but the HELO half of
# the comparison is forgeable, so it stays unscored. Artifact flags can only
# ever raise a score, never lower one.
ARTIFACT_SCORE_POINTS: Dict[str, int] = {
    'fcrdns_fail': 5,
    'bidi_override_in_subject': 5,
    'homoglyph_sender_domain': 5,
    'sender_domain_has_no_mx': 4,
    'date_before_first_hop': 3,
    'date_after_last_hop': 3,
}
ARTIFACT_SCORE_CAP = 15

# Artifact flags worth reporting to the analyst, with the wording used in the
# suspicions list. Membership here says nothing about scoring.
ARTIFACT_SUSPICION_MESSAGES: Dict[str, Tuple[str, str]] = {
    'fcrdns_fail': (
        'sending_server',
        'Reverse DNS for the sending IP does not forward-confirm (FCrDNS failed)',
    ),
    'no_ptr_record': (
        'sending_server', 'Sending IP has no reverse DNS (PTR) record'
    ),
    'ptr_helo_mismatch': (
        'sending_server',
        'Reverse DNS name does not match the HELO name claimed in Received',
    ),
    'no_public_sender_ip': (
        'sending_server', 'No public sending IP could be recovered from Received headers'
    ),
    'sender_domain_has_no_mx': (
        'sender', 'Sender domain publishes no MX records'
    ),
    'homoglyph_sender_domain': (
        'sender', 'Sender domain mixes scripts and imitates a Latin domain'
    ),
    'punycode_sender_domain': ('sender', 'Sender domain is punycode-encoded'),
    'display_name_domain_mismatch': (
        'sender', 'Display name contains an address from a different domain'
    ),
    'disposable_sender_domain': (
        'sender', 'Sender domain is a known disposable mailbox provider'
    ),
    'multiple_from_addresses': ('sender', 'Message carries multiple From addresses'),
    'bidi_override_in_subject': (
        'subject', 'Subject contains bidirectional override characters'
    ),
    'zero_width_in_subject': ('subject', 'Subject contains zero-width characters'),
    'mixed_charsets_in_subject': (
        'subject', 'Subject mixes multiple encoded-word character sets'
    ),
    'reply_prefix_without_thread_headers': (
        'subject', 'Subject claims to be a reply but carries no thread headers'
    ),
    'possible_bcc_delivery': (
        'recipients', 'Delivered to an address absent from To and Cc (possible BCC)'
    ),
    'undisclosed_recipients': ('recipients', 'Recipients are undisclosed'),
    'large_recipient_list': ('recipients', 'Unusually large visible recipient list'),
    'future_dated': ('date', 'Date header is in the future'),
    'date_before_first_hop': (
        'date', 'Date header predates the first Received hop'
    ),
    'date_after_last_hop': (
        'date', 'Date header is later than the last Received hop'
    ),
    'received_chain_out_of_order': (
        'date', 'Received chain timestamps are out of order'
    ),
    'freemail_reply_target': (
        'reply_to', 'Reply-To points at consumer webmail while the sender does not'
    ),
    'freemail_return_path': (
        'return_path',
        'Return-Path points at consumer webmail while the sender does not',
    ),
    'message_id_domain_differs_from_sender': (
        'headers', 'Message-ID domain differs from the sender domain'
    ),
}


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
        enable_reverse_dns: bool = True,
        enable_ip_rdap: bool = True,
        enable_asn_lookup: bool = True,
        enable_spf_advisory: bool = False,
        enable_mx_lookup: bool = False,
        spf_timeout: int = 8,
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
        self.artifact_extractor = ArtifactExtractorService()
        self.enable_reverse_dns = enable_reverse_dns
        self.enable_mx_lookup = enable_mx_lookup
        self.ip_intel = (
            IPIntelService(
                dns_checker=self.dns_checker,
                http_timeout=http_timeout,
                enable_rdap=enable_ip_rdap,
                enable_asn=enable_asn_lookup,
            )
            if (enable_ip_rdap or enable_asn_lookup)
            else None
        )
        self.spf_advisor = (
            SPFAdvisorService(timeout=spf_timeout) if enable_spf_advisory else None
        )
        self.whitelist_domains = {
            domain.strip().lower()
            for domain in (whitelist_domains or [])
            if validate_domain(domain.strip().lower())
        }
        # Every lookup already enforces its own timeout; this is a safety net
        # so one misbehaving lookup can never stall a whole analysis.
        # Reverse DNS is PTR followed by a forward A/AAAA confirmation, so
        # its worst case is several sequential round-trips rather than one.
        self.lookup_deadline = (
            max(dns_timeout * 3, whois_timeout, http_timeout, spf_timeout) + 5
        )

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

        # Offline artifacts first: the lookups below need the originating IP,
        # the claimed HELO and the envelope sender it derives.
        artifacts = self.artifact_extractor.extract(headers)
        spf_mail_from = artifacts.pop('_spf_mail_from', None)

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
            artifacts=artifacts,
            spf_mail_from=spf_mail_from,
        )
        spf_record = lookups.get('spf')
        dmarc_record = lookups.get('dmarc')
        dkim_record = lookups.get('dkim')
        whois_data = lookups.get('whois')
        abuse_data = lookups.get('abuse')
        verification = lookups.get('verify')
        reverse_dns = (lookups.get('rdns') or {}).get('ptr_name')

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

        # Fold live lookups into the artifact block and refresh its flags.
        self._merge_artifact_enrichment(artifacts, lookups, sender_domain, sender_ip)

        # Detect suspicions (now also checks domain age)
        suspicions = self._detect_suspicions(
            headers, abuse_data, auth_analysis,
            url_analysis, attachment_analysis, whois_data,
            verification=verification,
            artifacts=artifacts,
        )

        # Calculate risk score (domain age + compound rules + whitelist)
        risk_score, risk_level, whitelist_applied, risk_factors = self._calculate_risk_score(
            auth_analysis, abuse_data, url_analysis,
            attachment_analysis, content_analysis, suspicions,
            whois_data=whois_data, sender_domain=sender_domain,
            verification=verification,
            artifacts=artifacts,
        )

        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            # Concise "official artifacts" summary — the key, verifiable facts
            # extracted from the message, surfaced up front as a conclusion.
            #
            # Projected from `artifacts` so the two can never disagree. This
            # deliberately reads each artifact's verbatim `value`, not its
            # parsed form: `conclusion` reports the message as received, while
            # `artifacts.checklist` reports it normalised (parsed address, UTC
            # date, recipients split into To and Cc).
            'conclusion': self._build_conclusion(artifacts),
            'headers': {
                'sender': headers.get('sender'),
                'recipients': headers.get('recipients'),
                'reply_to': headers.get('reply_to'),
                'subject': headers.get('subject'),
                'date': headers.get('date'),
                'message_id': headers.get('message_id'),
                'return_path': headers.get('return_path'),
            },
            'artifacts': artifacts,
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
                # Ordered breakdown of what contributed to the score, so the UI
                # can explain the verdict instead of showing a bare number.
                'factors': risk_factors,
            }
        }

    @staticmethod
    def _build_conclusion(artifacts: Dict[str, Any]) -> Dict[str, Any]:
        """Verbatim seven-field summary, projected from the artifact block.

        Values are the artifacts' raw `value` fields, so this reports exactly
        what the message said. The normalised view lives in
        `artifacts.checklist`.
        """
        def value(key: str) -> Any:
            return (artifacts.get(key) or {}).get('value')

        return {
            'sender_address': value('sender'),
            'subject': value('subject'),
            # BCC recipients never appear in delivered headers, so this
            # reflects only the visible To/Cc recipients.
            'recipients': value('recipients'),
            'date': value('date'),
            'sending_server_ip': (artifacts.get('sending_server') or {}).get('ip'),
            'reverse_dns': value('reverse_dns'),
            'reply_to': value('reply_to'),
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
        *,
        artifacts: Optional[Dict[str, Any]] = None,
        spf_mail_from: Optional[str] = None,
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
        if self.ip_reputation and sender_ip:
            jobs['abuse'] = (self.ip_reputation.check_ip, (sender_ip,))
        if self.virustotal and attachment_hashes:
            jobs['vt'] = (self.virustotal.check_hashes, (attachment_hashes,))
        if self.auth_verifier and self.auth_verifier.available and raw_bytes:
            jobs['verify'] = (
                self.auth_verifier.verify,
                (raw_bytes, sender_domain),
            )

        server = (artifacts or {}).get('sending_server') or {}
        enrich_ip = server.get('enriched_ip') or sender_ip
        if enrich_ip:
            if self.enable_reverse_dns:
                # One job serves both the conclusion hostname and the FCrDNS
                # verdict; the two share a PTR cache entry underneath.
                jobs['rdns'] = (self.dns_checker.reverse_dns_details, (enrich_ip,))
            if self.ip_intel:
                jobs['ip_intel'] = (self.ip_intel.lookup, (enrich_ip,))
            if self.spf_advisor and self.spf_advisor.available:
                # partial() with an empty args tuple fits the existing
                # executor.submit(fn, *args) dispatch without changing it.
                jobs['spf_advisory'] = (
                    partial(
                        self.spf_advisor.evaluate,
                        ip=enrich_ip,
                        mail_from=spf_mail_from,
                        helo=server.get('helo_claimed'),
                        mail_from_source=(
                            'return_path_header'
                            if (artifacts or {}).get('return_path', {}).get('address')
                            else 'from_header'
                        ),
                    ),
                    (),
                )
        if self.enable_mx_lookup and sender_domain:
            jobs['mx'] = (self.dns_checker.get_mx_records, (sender_domain,))

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

    def _merge_artifact_enrichment(
        self,
        artifacts: Dict[str, Any],
        lookups: Dict[str, Any],
        sender_domain: Optional[str],
        sender_ip: Optional[str] = None,
    ) -> None:
        """Fold live lookup results into the artifact block.

        Sets an explicit status for every enrichment source so the UI never
        shows a blank field without saying why it is blank.
        """
        try:
            server = artifacts.get('sending_server') or {}
            enrichment = server.setdefault('enrichment', {})
            status = artifacts.setdefault('enrichment_status', {})
            # Must mirror _run_external_lookups' fallback exactly: if a
            # lookup actually ran, the status must never claim it was
            # skipped — that is a privacy statement, not cosmetics.
            has_ip = bool(server.get('enriched_ip') or sender_ip)

            # -- reverse DNS ------------------------------------------------
            rdns = lookups.get('rdns')
            if not self.enable_reverse_dns:
                status['reverse_dns'] = 'disabled'
            elif not has_ip:
                status['reverse_dns'] = 'skipped_no_public_ip'
            elif rdns is None:
                status['reverse_dns'] = 'error'
            else:
                status['reverse_dns'] = (
                    'error' if rdns.get('fcrdns') == 'lookup_failed' else 'ok'
                )

            reverse_artifact = artifacts.get('reverse_dns') or {}
            if rdns:
                helo = server.get('helo_claimed')
                ptr_name = rdns.get('ptr_name')
                matches = None
                if helo and ptr_name:
                    matches = registered_domain(ptr_name) == registered_domain(helo)

                enrichment['reverse_dns'] = {
                    'trust': 'observed',
                    'source': 'live_dns',
                    'ptr': rdns.get('ptr', []),
                    'ptr_name': ptr_name,
                    'forward_ips': rdns.get('forward_ips', {}),
                    'fcrdns': rdns.get('fcrdns'),
                    'ptr_matches_helo': matches,
                    # The PTR half is observed but the HELO half is copied out
                    # of a forgeable Received header, so the comparison is only
                    # as trustworthy as its weakest input. Shown, never scored.
                    'ptr_helo_comparison_trust': 'header_claim',
                    'checked_at': rdns.get('checked_at'),
                }
                reverse_artifact['value'] = ptr_name
                reverse_artifact['status'] = rdns.get('fcrdns')
                reverse_artifact['fcrdns'] = rdns.get('fcrdns')
                reverse_artifact['forward_ips'] = rdns.get('forward_ips', {})
                reverse_artifact['helo_claimed'] = helo
                reverse_artifact['ptr_matches_helo'] = matches

                flags = []
                if rdns.get('fcrdns') == 'fail':
                    flags.append('fcrdns_fail')
                elif rdns.get('fcrdns') == 'no_ptr':
                    flags.append('no_ptr_record')
                if matches is False:
                    flags.append('ptr_helo_mismatch')
                reverse_artifact['flags'] = flags
            else:
                reverse_artifact['status'] = status.get('reverse_dns', 'unavailable')
                reverse_artifact['flags'] = []
            artifacts['reverse_dns'] = reverse_artifact

            # -- ASN / RDAP -------------------------------------------------
            ip_intel = lookups.get('ip_intel')
            if self.ip_intel is None:
                status['ip_intel'] = 'disabled'
            elif not has_ip:
                status['ip_intel'] = 'skipped_no_public_ip'
            elif ip_intel is None:
                status['ip_intel'] = 'unavailable'
            else:
                status['ip_intel'] = 'ok'
                enrichment['ip_intel'] = ip_intel

            # -- MX ---------------------------------------------------------
            # get_mx_records is tri-state: a list of hosts, [] for an
            # authoritative "no MX records", None for a resolver failure.
            # Only the authoritative answer is evidence — flagging on None
            # would let a DNS outage fabricate scored points.
            mx = lookups.get('mx')
            sender_artifact = artifacts.get('sender') or {}
            if not self.enable_mx_lookup:
                status['mx'] = 'disabled'
            elif not sender_domain:
                status['mx'] = 'skipped_no_sender_domain'
            elif mx is None:
                status['mx'] = 'unavailable'
            else:
                status['mx'] = 'ok'
                sender_artifact['enrichment'] = {
                    'trust': 'observed', 'source': 'live_dns', 'mx': mx,
                }
                if not mx:
                    sender_artifact.setdefault('flags', []).append(
                        'sender_domain_has_no_mx'
                    )

            # -- advisory SPF ------------------------------------------------
            advisory = artifacts.setdefault('authentication_advisory', {})
            spf = lookups.get('spf_advisory')
            if self.spf_advisor is None:
                status['spf_advisory'] = 'disabled'
                advisory['spf'] = None
            elif not self.spf_advisor.available:
                status['spf_advisory'] = 'unavailable'
                advisory['spf'] = None
            elif not has_ip:
                status['spf_advisory'] = 'skipped_no_public_ip'
                advisory['spf'] = None
            elif spf is None:
                status['spf_advisory'] = 'error'
                advisory['spf'] = None
            else:
                status['spf_advisory'] = 'ok'
                advisory['spf'] = spf

        except Exception as exc:
            # A partial merge must not masquerade as a complete one. Record it
            # against every source that never reached a terminal status, so the
            # report says the enrichment broke instead of showing a confident
            # verdict built on half-merged data.
            logger.warning(
                '[EmailAnalyzerService] artifact enrichment merge failed: %s', exc
            )
            status = artifacts.setdefault('enrichment_status', {})
            for source in (
                'reverse_dns', 'ip_intel', 'mx', 'spf_advisory',
            ):
                status.setdefault(source, 'error')
            status['merge'] = 'error'
        finally:
            # Always rebuilt, never skipped. These are derived views over
            # `artifacts`; leaving the pre-enrichment copies in place after a
            # failure would contradict the block they claim to summarise.
            # Guarded in turn, because a rebuild that raised out of `finally`
            # would take down the whole analysis — a worse failure than the
            # stale views this replaces.
            try:
                artifacts['checklist'] = ArtifactExtractorService._build_checklist(
                    artifacts
                )
            except Exception as exc:
                logger.warning(
                    '[EmailAnalyzerService] checklist rebuild failed: %s', exc
                )
                artifacts.setdefault('enrichment_status', {})['merge'] = 'error'
            try:
                artifacts['flags'] = collect_flags(artifacts)
            except Exception as exc:
                logger.warning(
                    '[EmailAnalyzerService] flag rebuild failed: %s', exc
                )
                artifacts.setdefault('enrichment_status', {})['merge'] = 'error'

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
        verification: Optional[Dict[str, Any]] = None,
        *,
        artifacts: Optional[Dict[str, Any]] = None,
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

        # Artifact findings. Reply-To and Return-Path mismatches are already
        # reported above, so they are skipped here rather than duplicated.
        for flag in (artifacts or {}).get('flags', []):
            entry = ARTIFACT_SUSPICION_MESSAGES.get(flag.get('code', ''))
            if not entry:
                continue
            category, message = entry
            add_suspicion(category, flag.get('severity', 'info'), message)

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
        verification: Optional[Dict[str, Any]] = None,
        *,
        artifacts: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """Calculate the risk score (0-100), level, whitelist flag, and the
        ordered breakdown of factors that produced the score.

        ``factors`` is the single source of truth behind the number: each entry
        records the points a signal added (or removed) plus a short, human
        readable label and detail, so the UI can explain the verdict.
        """
        score = 0
        factors: List[Dict[str, Any]] = []

        def add_factor(label: str, points: int, severity: str, detail: str = '') -> None:
            """Record a scoring contribution (skips no-op zero-point signals)."""
            if points:
                factors.append({
                    'label': label,
                    'points': int(points),
                    'severity': severity,
                    'detail': detail,
                })

        # Artifact evidence, capped so header forensics can never dominate
        # the verdict on its own. Only observed and computed flags appear in
        # ARTIFACT_SCORE_POINTS, so nothing here is forgeable. Each scored
        # flag is registered as a factor, because `factors` is what the UI
        # shows as the reason behind the number — points added without one
        # would leave the verdict partly unexplained.
        artifact_budget = ARTIFACT_SCORE_CAP
        for flag in (artifacts or {}).get('flags', []):
            code = flag.get('code', '')
            points = ARTIFACT_SCORE_POINTS.get(code, 0)
            if not points or artifact_budget <= 0:
                continue
            points = min(points, artifact_budget)
            artifact_budget -= points
            score += points
            entry = ARTIFACT_SUSPICION_MESSAGES.get(code)
            add_factor(
                entry[1] if entry else code,
                points,
                flag.get('severity', 'medium'),
                f"{flag.get('trust', 'computed')} signal from header artifacts",
            )

        # Authentication-Results header claims are deliberately not scored.

        # IP reputation (max 25 points)
        if abuse_data and isinstance(abuse_data.get('abuseConfidenceScore'), int):
            abuse_conf = abuse_data['abuseConfidenceScore']
            pts = min(25, abuse_conf // 4)
            score += pts
            add_factor(
                'Sender IP reputation', pts,
                'critical' if abuse_conf >= 70 else 'medium',
                f'AbuseIPDB confidence {abuse_conf}%',
            )

        # URLs (max 20 points)
        suspicious_url_count = url_analysis.get('suspicious_count', 0)
        url_pts = min(20, suspicious_url_count * 5)
        score += url_pts
        add_factor(
            'Suspicious URLs', url_pts, 'high',
            f'{suspicious_url_count} flagged link(s)',
        )

        # Attachments (max 40 points) — weighted by severity. A single
        # locally-verified critical attachment (hidden executable, executable
        # bytes under a document extension, malware YARA hit, executable inside
        # an archive) is high-confidence and non-forgeable, so it alone must
        # clear the "medium" floor (25) — otherwise a message literally
        # carrying an executable reads as "no strong indicators detected".
        severity_points = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3}
        suspicious_attachments = [
            a for a in attachment_analysis.get('attachments', [])
            if a.get('is_suspicious')
        ]
        weighted = sum(
            severity_points.get(a.get('severity'), 0)
            for a in suspicious_attachments
        )
        count_based = attachment_analysis.get('suspicious_count', 0) * 5
        att_pts = min(40, max(weighted, count_based))
        score += att_pts
        add_factor(
            'Suspicious attachments', att_pts,
            'critical'
            if any(a.get('severity') == 'critical' for a in suspicious_attachments)
            else 'high',
            f"{attachment_analysis.get('suspicious_count', 0)} flagged file(s)",
        )

        # Content indicators (max 10 points)
        urgent_phrase_count = len(content_analysis.get('urgent_phrases', []))
        content_pts = min(10, urgent_phrase_count * 2)
        score += content_pts
        add_factor(
            'Urgent / pressure language', content_pts, 'medium',
            f'{urgent_phrase_count} phrase(s)',
        )

        # Domain age scoring
        domain_age_days = self._get_domain_age_days(whois_data)
        if domain_age_days is not None:
            if domain_age_days < 7:
                age_pts = 20
            elif domain_age_days < 30:
                age_pts = 15
            elif domain_age_days < 90:
                age_pts = 8
            elif domain_age_days < 365:
                age_pts = 3
            else:
                age_pts = 0
            score += age_pts
            add_factor(
                'Domain age', age_pts,
                'high' if domain_age_days < 30
                else 'medium' if domain_age_days < 90 else 'low',
                f'Registered {domain_age_days} day(s) ago',
            )

        # Independently verified DKIM failure is cryptographic evidence.
        if verification and verification.get('available'):
            if verification.get('dkim') == 'fail':
                score += 12
                add_factor(
                    'DKIM verification failed', 12, 'high',
                    'Signature did not validate',
                )

        # VirusTotal detections: confirmed malware forces critical
        vt_malicious = max(
            (
                (a.get('virustotal') or {}).get('malicious', 0)
                for a in attachment_analysis.get('attachments', [])
            ),
            default=0,
        )
        if vt_malicious >= 3:
            before = score
            score = max(score, 85)
            add_factor(
                'VirusTotal detections', max(score - before, 0), 'critical',
                f'{vt_malicious} engines flagged an attachment',
            )
        elif vt_malicious >= 1:
            score += 15
            add_factor(
                'VirusTotal detections', 15, 'critical',
                f'{vt_malicious} engine(s) flagged an attachment',
            )

        # Compound escalation rules
        abuse_score = (abuse_data or {}).get('abuseConfidenceScore') or 0
        if not isinstance(abuse_score, int):
            abuse_score = 0
        # An executable delivered inside an archive (zip-hidden payload) is
        # tagged 'archive_contains_executable', not 'executable_file'. Treat
        # both as an executable so zipping the payload doesn't dodge the
        # new-domain escalation below.
        executable_issue_tags = {
            'executable_file',
            'archive_contains_executable',
            'executable_content_mismatch',
        }
        has_executable = any(
            executable_issue_tags.intersection(a.get('issues', []))
            for a in attachment_analysis.get('attachments', [])
        )

        # Rule 1: new domain + executable attachment → force critical
        if domain_age_days is not None and domain_age_days < 30 and has_executable:
            before = score
            score = max(score, 85)
            add_factor(
                'Newly registered domain + executable attachment',
                max(score - before, 0), 'critical', 'Escalated to critical',
            )
            suspicions.append({
                'category': 'compound_escalation',
                'severity': 'critical',
                'message': 'Combined: newly registered domain + executable attachment'
            })

        # Rule 2: young domain + high abuse score → force high
        if domain_age_days is not None and domain_age_days < 90 and abuse_score > 50:
            before = score
            score = max(score, 75)
            add_factor(
                'Young domain + high-abuse sender IP',
                max(score - before, 0), 'high', 'Escalated to high',
            )

        # Rule 3: Many suspicious URLs + urgent content
        if suspicious_url_count >= 3 and urgent_phrase_count > 2:
            score += 10
            add_factor(
                'Many suspicious URLs combined with urgent content',
                10, 'high', '',
            )

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
            before = score
            score = max(0, score - 5)
            add_factor(
                'Trusted domain with verified DKIM',
                score - before, 'info', 'Small trust discount applied',
            )

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

        return score, risk_level, whitelist_applied, factors

    def _get_verdict(self, risk_level: str) -> str:
        """Get human-readable verdict"""
        verdicts = {
            'critical': 'HIGHLY SUSPICIOUS - Likely phishing or malicious',
            'high': 'SUSPICIOUS - Exercise extreme caution',
            'medium': 'QUESTIONABLE - Review carefully before interacting',
            'low': 'NO STRONG INDICATORS DETECTED - Not a guarantee of safety'
        }
        return verdicts.get(risk_level, 'UNKNOWN')
