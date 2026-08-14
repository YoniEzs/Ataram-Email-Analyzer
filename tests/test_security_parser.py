"""
Regression tests for the parse-time denial-of-service surface and the scoring
bypasses found by the adversarial audit.

Every test here corresponds to a measured attack. The timings in the comments
are what the audit recorded against the code before these guards existed — they
are the reason the guards operate on raw bytes rather than on parsed objects.
"""
import io
import time

import pytest

from app import create_app
from app.config import TestingConfig
from app.services.content_analyzer import ContentAnalyzerService
from app.services.email_analyzer import EmailAnalyzerService, LookupBudget
from app.services.email_parser import EmailParserService
from app.utils.validators import (
    allowed_file,
    safe_display_filename,
    validate_header_block,
    validate_mime_structure,
)


HEADER_LIMITS = dict(max_block_bytes=256 * 1024, max_line_bytes=16 * 1024, max_headers=500)

MINIMAL_EML = (
    b"From: sender@example.com\r\n"
    b"To: recipient@example.com\r\n"
    b"Subject: Test\r\n"
    b"Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"
    b"\r\n"
    b"Body text\r\n"
)


def _address_flood(count: int) -> bytes:
    addresses = ', '.join(f'user{i}@example.com' for i in range(count))
    return f'From: a@b.com\r\nTo: {addresses}\r\n\r\nhi'.encode()


def _mime_flood(parts: int) -> bytes:
    body = b''.join(b'--X\r\nContent-Type: text/plain\r\n\r\nhello\r\n' for _ in range(parts))
    return (
        b'From: a@b.com\r\nTo: b@c.com\r\nSubject: t\r\n'
        b'Content-Type: multipart/mixed; boundary=X\r\n\r\n' + body + b'--X--\r\n'
    )


class TestHeaderBlockGuard:
    """
    Python's email package parses header values lazily and super-linearly. The
    audit measured a 1.5MB .eml with one enormous To: header at ~237s of CPU —
    3% of the allowed upload size, and twice gunicorn's 120s worker timeout.

    A cap expressed as "keep the first N headers" cannot help: the cost is paid
    by the access that builds the list. The guard must run on raw bytes.
    """

    def test_address_flood_is_rejected(self):
        ok, message = validate_header_block(_address_flood(64000), **HEADER_LIMITS)
        assert not ok
        assert message

    def test_rejection_is_immediate(self):
        """The guard must not itself be expensive, or it becomes the DoS."""
        payload = _address_flood(64000)
        start = time.monotonic()
        ok, _ = validate_header_block(payload, **HEADER_LIMITS)
        elapsed = time.monotonic() - start
        assert not ok
        assert elapsed < 0.5, f'guard took {elapsed:.2f}s — it must be O(header block)'

    def test_encoded_word_received_flood_is_rejected(self):
        word = '=?utf-8?B?QUFBQUFBQUFBQQ==?='
        headers = b''.join((f'Received: {word * 16000}\r\n').encode() for _ in range(3))
        ok, _ = validate_header_block(b'From: a@b.com\r\n' + headers + b'\r\nhi', **HEADER_LIMITS)
        assert not ok

    def test_too_many_headers_rejected(self):
        headers = b''.join(f'X-Custom-{i}: value\r\n'.encode() for i in range(2000))
        ok, message = validate_header_block(b'From: a@b.com\r\n' + headers + b'\r\nbody', **HEADER_LIMITS)
        assert not ok
        assert 'too many headers' in message.lower()

    def test_file_with_no_header_terminator_rejected(self):
        ok, _ = validate_header_block(b'From: a@b.com\r\n' + b'x' * 400_000, **HEADER_LIMITS)
        assert not ok

    def test_ordinary_email_passes(self):
        ok, message = validate_header_block(MINIMAL_EML, **HEADER_LIMITS)
        assert ok, message

    def test_folded_headers_are_measured_unfolded(self):
        """A long value split across continuation lines must still be caught."""
        folded = b'Subject: ' + b''.join(b'\r\n ' + b'a' * 900 for _ in range(40)) + b'\r\n'
        ok, _ = validate_header_block(b'From: a@b.com\r\n' + folded + b'\r\nbody', **HEADER_LIMITS)
        assert not ok

    def test_lf_only_line_endings_supported(self):
        ok, message = validate_header_block(b'From: a@b.com\nTo: c@d.com\n\nbody', **HEADER_LIMITS)
        assert ok, message


class TestMimeStructureGuard:
    """
    BytesParser builds the entire message tree before any traversal cap can
    apply, so a part flood has to be refused from the raw bytes too. The audit
    measured 20,000 parts at ~14s.
    """

    def test_part_flood_is_rejected(self):
        ok, message = validate_mime_structure(_mime_flood(20000), max_parts=1000)
        assert not ok
        assert 'MIME parts' in message

    def test_rejection_is_immediate(self):
        payload = _mime_flood(20000)
        start = time.monotonic()
        ok, _ = validate_mime_structure(payload, max_parts=1000)
        elapsed = time.monotonic() - start
        assert not ok
        assert elapsed < 0.5, f'guard took {elapsed:.2f}s'

    def test_ordinary_multipart_passes(self):
        normal = (
            b'From: a@b.com\r\nContent-Type: multipart/alternative; boundary=X\r\n\r\n'
            b'--X\r\nContent-Type: text/plain\r\n\r\nhi\r\n'
            b'--X\r\nContent-Type: text/html\r\n\r\n<b>hi</b>\r\n--X--\r\n'
        )
        ok, _ = validate_mime_structure(normal, max_parts=1000)
        assert ok


class TestParserLimits:
    def test_attachment_size_is_estimated_not_decoded(self):
        """
        get_payload(decode=True) allocated the whole attachment just to call
        len() on it — hundreds of megabytes of pure waste per request.
        """
        payload = b'QUJDREVGR0g=' * 4000  # base64 text
        eml = (
            b'From: a@b.com\r\nTo: b@c.com\r\nSubject: t\r\n'
            b'Content-Type: multipart/mixed; boundary=X\r\n\r\n'
            b'--X\r\nContent-Type: application/octet-stream\r\n'
            b'Content-Transfer-Encoding: base64\r\n'
            b'Content-Disposition: attachment; filename="payload.bin"\r\n\r\n'
            + payload + b'\r\n--X--\r\n'
        )
        result = EmailParserService().parse_email(eml, 'x.eml')
        attachments = result['attachments']
        assert len(attachments) == 1
        # 4 base64 chars per 3 bytes, so roughly three quarters of the encoded size.
        assert attachments[0]['size'] == pytest.approx(len(payload) * 3 // 4, rel=0.05)

    def test_mime_part_traversal_is_capped(self):
        result = EmailParserService(limits={'MAX_MIME_PARTS': 50}).parse_email(_mime_flood(5000), 'x.eml')
        assert 'error' not in result

    def test_body_budget_enforced_during_traversal(self):
        body = 'A' * 50_000
        eml = (
            f'From: a@b.com\r\nTo: b@c.com\r\nSubject: t\r\n\r\n{body}'
        ).encode()
        result = EmailParserService(limits={'MAX_ANALYZED_BODY_CHARS': 1000}).parse_email(eml, 'x.eml')
        assert len(result['body_text']) <= 1000

    def test_hops_are_capped_in_count_and_length(self):
        hops = b''.join(b'Received: from ' + b'h' * 5000 + b'\r\n' for _ in range(10))
        eml = b'From: a@b.com\r\n' + hops + b'\r\nbody'
        result = EmailParserService(
            limits={'MAX_ANALYZED_HOPS': 3, 'MAX_HOP_CHARS': 100}
        ).parse_email(eml, 'x.eml')
        assert len(result['headers']['hops']) == 3
        assert all(len(h) <= 100 for h in result['headers']['hops'])

    def test_parsed_message_object_is_not_retained(self):
        """It pinned every part's payload in memory for the life of the request."""
        result = EmailParserService().parse_email(MINIMAL_EML, 'x.eml')
        assert 'msg_object' not in result

    def test_parse_failure_does_not_echo_exception_text(self):
        """The raw Python exception string used to be returned to the caller."""
        parser = EmailParserService()
        result = parser.parse_email(b'\xd0\xcf\x11\xe0' + b'\x00' * 200, 'x.msg')
        if result.get('error'):
            lowered = result['error'].lower()
            assert 'traceback' not in lowered
            assert 'typeerror' not in lowered
            assert 'initial_value' not in lowered

    def test_unknown_charset_on_single_part_degrades(self):
        """This used to abort the entire analysis rather than degrade."""
        eml = (
            b'From: a@b.com\r\nTo: b@c.com\r\nSubject: t\r\n'
            b'Content-Type: text/plain; charset="definitely-not-a-charset"\r\n\r\n'
            b'body content\r\n'
        )
        result = EmailParserService().parse_email(eml, 'x.eml')
        assert 'error' not in result


class TestFilenameHandling:
    def test_non_ascii_filename_keeps_its_extension(self):
        """
        secure_filename strips every non-ASCII character, so 'דואר.eml' became
        'eml' — no dot — and the extension re-derived downstream was empty,
        rejecting every Hebrew, Arabic or Chinese named upload.
        """
        for name in ['דואר.eml', 'رسالة.eml', '邮件.msg']:
            safe = safe_display_filename(name)
            assert '.' in safe, f'{name!r} lost its extension: {safe!r}'
            assert safe.rsplit('.', 1)[1] in ('eml', 'msg')

    def test_non_ascii_named_upload_is_accepted_end_to_end(self):
        app = create_app(TestingConfig)
        client = app.test_client()
        response = client.post(
            '/api/analyze',
            data={'emailfile': (io.BytesIO(MINIMAL_EML), 'דואר.eml')},
            content_type='multipart/form-data',
        )
        assert response.status_code == 200, response.get_data(as_text=True)

    def test_traversal_is_still_stripped(self):
        assert '/' not in safe_display_filename('../../etc/passwd.eml')
        assert not allowed_file('../../etc/passwd.eml')


class TestUploadRejection:
    def test_header_flood_rejected_by_api(self):
        client = create_app(TestingConfig).test_client()
        response = client.post(
            '/api/analyze',
            data={'emailfile': (io.BytesIO(_address_flood(64000)), 'flood.eml')},
            content_type='multipart/form-data',
        )
        assert response.status_code == 400
        assert response.is_json

    @pytest.mark.parametrize('parts', [2000, 20000])
    def test_mime_flood_rejected_by_api(self, parts):
        """
        Rejected either by the MIME-structure guard (400) or, for the largest
        floods, by Werkzeug's multipart limits before the view runs (413).
        Both are correct refusals; what matters is that neither reaches the parser.
        """
        client = create_app(TestingConfig).test_client()
        response = client.post(
            '/api/analyze',
            data={'emailfile': (io.BytesIO(_mime_flood(parts)), 'flood.eml')},
            content_type='multipart/form-data',
        )
        assert response.status_code in (400, 413)
        assert response.is_json

    @pytest.mark.parametrize('megabytes,attachments', [(1, 3), (10, 5), (20, 10)])
    def test_realistic_multi_attachment_email_still_accepted(self, megabytes, attachments):
        """
        The flood guards must not reject ordinary mail with attachments.

        Sizes stay under MAX_UPLOAD_MB (lowered to 25MB so the nginx body spool
        fits its tmpfs at the permitted concurrency).
        """
        chunk = b'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=' * (
            (megabytes * 1024 * 1024) // (36 * attachments))
        body = b''.join(
            b'--X\r\nContent-Type: application/pdf\r\n'
            b'Content-Transfer-Encoding: base64\r\n'
            b'Content-Disposition: attachment; filename="doc%d.pdf"\r\n\r\n' % i
            + chunk + b'\r\n'
            for i in range(attachments)
        )
        eml = (
            b'From: real@example.com\r\nTo: me@example.com\r\nSubject: Invoices\r\n'
            b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n'
            b'Content-Type: multipart/mixed; boundary=X\r\n\r\n' + body + b'--X--\r\n'
        )
        client = create_app(TestingConfig).test_client()
        response = client.post(
            '/api/analyze',
            data={'emailfile': (io.BytesIO(eml), 'invoices.eml')},
            content_type='multipart/form-data',
        )
        assert response.status_code == 200, response.get_data(as_text=True)[:300]

    def test_api_rejects_flood_quickly(self):
        client = create_app(TestingConfig).test_client()
        payload = _address_flood(64000)
        start = time.monotonic()
        client.post(
            '/api/analyze',
            data={'emailfile': (io.BytesIO(payload), 'flood.eml')},
            content_type='multipart/form-data',
        )
        elapsed = time.monotonic() - start
        assert elapsed < 5, f'request took {elapsed:.1f}s — the guard is not short-circuiting'


class TestScoringBypasses:
    """
    The whitelist cap was gated on an SPF result read out of the uploaded file's
    own Authentication-Results header — a header the attacker writes.
    """

    @staticmethod
    def _parsed(sender, auth_results, **extra):
        data = {
            'headers': {
                'sender': sender,
                'auth_results': auth_results,
                'hops': [],
                'return_path': '',
                'reply_to': '',
                'dkim_signature': '',
            },
            'body_text': '',
            'body_html': '',
            'attachments': [],
        }
        data.update(extra)
        return data

    def test_self_asserted_spf_pass_does_not_earn_the_whitelist_cap(self, monkeypatch):
        monkeypatch.setattr(
            'app.services.dns_checker.DNSCheckerService.check_spf', lambda *a, **k: None)
        monkeypatch.setattr(
            'app.services.dns_checker.DNSCheckerService.check_dmarc', lambda *a, **k: None)
        monkeypatch.setattr(
            'app.services.whois_service.WhoisService.lookup', lambda *a, **k: None)

        analyzer = EmailAnalyzerService(whitelist_domains=['gmail.com'])
        result = analyzer.analyze(self._parsed(
            'attacker@gmail.com',
            'mx.example.com; spf=pass; dkim=pass; dmarc=pass',
        ))
        assert result['risk_assessment']['whitelist_applied'] is False, (
            'A spoofed From plus a forged Authentication-Results header capped the score'
        )

    def test_spoofing_a_whitelisted_brand_earns_no_cap(self, monkeypatch):
        """
        Requiring DNS-verified SPF+DMARC looked like a fix but was not: those
        records are looked up for the SPOOFED domain, so spoofing
        `From: security@microsoft.com` satisfies the gate using Microsoft's own
        real DNS. Every domain worth impersonating publishes both.

        The cap is therefore gone entirely — it could only ever lower risk, and
        an attacker could switch it on at will.
        """
        monkeypatch.setattr(
            'app.services.dns_checker.DNSCheckerService.check_spf',
            lambda *a, **k: 'v=spf1 include:spf.protection.outlook.com -all')
        monkeypatch.setattr(
            'app.services.dns_checker.DNSCheckerService.check_dmarc',
            lambda *a, **k: 'v=DMARC1; p=reject')
        monkeypatch.setattr(
            'app.services.whois_service.WhoisService.lookup', lambda *a, **k: None)

        analyzer = EmailAnalyzerService(whitelist_domains=['microsoft.com'])
        result = analyzer.analyze(self._parsed(
            'security@microsoft.com', 'mx; spf=pass; dkim=pass; dmarc=pass'))

        assessment = result['risk_assessment']
        assert assessment['whitelist_applied'] is False
        # Reported for context, but explicitly non-load-bearing.
        assert assessment['sender_domain_is_trusted'] is True

    def test_trusted_sender_does_not_lower_the_score(self, monkeypatch):
        """The flag must be inert: same message, same score, listed or not."""
        for name in ('check_spf', 'check_dmarc'):
            monkeypatch.setattr(f'app.services.dns_checker.DNSCheckerService.{name}',
                                lambda *a, **k: 'v=spf1 -all')
        monkeypatch.setattr('app.services.whois_service.WhoisService.lookup',
                            lambda *a, **k: None)

        parsed = self._parsed('security@microsoft.com', 'mx; spf=pass; dkim=pass; dmarc=pass')
        listed = EmailAnalyzerService(whitelist_domains=['microsoft.com']).analyze(dict(parsed))
        unlisted = EmailAnalyzerService(whitelist_domains=[]).analyze(dict(parsed))
        assert listed['risk_assessment']['score'] == unlisted['risk_assessment']['score']

    def test_risk_level_is_floored_at_worst_suspicion(self, monkeypatch):
        """A banner reading 'low' above a critical indicator actively reassures."""
        monkeypatch.setattr(
            'app.services.dns_checker.DNSCheckerService.check_spf', lambda *a, **k: None)
        monkeypatch.setattr(
            'app.services.dns_checker.DNSCheckerService.check_dmarc', lambda *a, **k: None)
        monkeypatch.setattr(
            'app.services.whois_service.WhoisService.lookup', lambda *a, **k: None)

        analyzer = EmailAnalyzerService()
        result = analyzer.analyze(self._parsed(
            'a@b.com', '',
            attachments=[{
                'filename': 'invoice.pdf.exe', 'extension': 'exe',
                'content_type': 'application/octet-stream', 'size': 4096,
            }],
        ))
        levels = ['low', 'medium', 'high', 'critical']
        worst = max(
            (s['severity'] for s in result['suspicions'] if s['severity'] in levels),
            key=levels.index, default='low')
        assert levels.index(result['risk_assessment']['level']) >= levels.index(worst)

    def test_executable_attachment_forces_elevated_risk(self, monkeypatch):
        for name in ('check_spf', 'check_dmarc'):
            monkeypatch.setattr(f'app.services.dns_checker.DNSCheckerService.{name}',
                                lambda *a, **k: None)
        monkeypatch.setattr('app.services.whois_service.WhoisService.lookup',
                            lambda *a, **k: None)

        analyzer = EmailAnalyzerService()
        result = analyzer.analyze(self._parsed(
            'a@b.com', '',
            attachments=[{
                'filename': 'setup.exe', 'extension': 'exe',
                'content_type': 'application/octet-stream', 'size': 500_000,
            }],
        ))
        assert result['risk_assessment']['level'] in ('high', 'critical')


class TestUrlDiscovery:
    """
    A regex over unparsed HTML cannot see a link written with entities or a
    protocol-relative href, but a mail client renders both as live links. Any
    URL invisible to this step contributed zero to the score.
    """

    def test_entity_encoded_href_is_found(self):
        html = '<a href="&#104;ttps://evil-test.tk/login">click</a>'
        result = ContentAnalyzerService().analyze('', html)
        assert any('evil-test.tk' in u for u in result['dom_urls'])

    def test_protocol_relative_href_is_found(self):
        result = ContentAnalyzerService().analyze('', '<a href="//evil-test.tk/x">click</a>')
        assert any('evil-test.tk' in u for u in result['dom_urls'])

    def test_hidden_link_reaches_url_analysis(self, monkeypatch):
        for name in ('check_spf', 'check_dmarc'):
            monkeypatch.setattr(f'app.services.dns_checker.DNSCheckerService.{name}',
                                lambda *a, **k: None)
        monkeypatch.setattr('app.services.whois_service.WhoisService.lookup',
                            lambda *a, **k: None)

        analyzer = EmailAnalyzerService()
        result = analyzer.analyze({
            'headers': {'sender': 'a@b.com', 'auth_results': '', 'hops': [],
                        'return_path': '', 'reply_to': '', 'dkim_signature': ''},
            'body_text': '',
            'body_html': '<a href="&#104;ttps://phish.tk/login.php?userid=1">bank</a>',
            'attachments': [],
        })
        assert result['urls']['total_count'] >= 1

    def test_dom_url_collection_is_bounded(self):
        html = ''.join(f'<a href="https://example{i}.com">x</a>' for i in range(2000))
        result = ContentAnalyzerService().analyze('', html)
        assert len(result['dom_urls']) <= ContentAnalyzerService.MAX_DOM_URLS


class TestContentAnalyzerRobustness:
    def test_bytes_html_does_not_raise(self):
        """extract_msg returns htmlBody as Optional[bytes]."""
        result = ContentAnalyzerService().analyze(b'plain bytes', b'<b>html bytes</b>')
        assert 'yara_matches' in result


class TestWhoisAmplification:
    """
    WHOIS for mail.example.com returns example.com's record, so keying the
    cache on the full hostname handed an attacker a guaranteed cache miss — and
    a fresh outbound connection — from every request just by varying the
    subdomain, while flushing the bounded LRU.
    """

    def test_subdomains_reduce_to_one_registrable_domain(self):
        from app.services.whois_service import registrable_domain

        assert registrable_domain('a.example.com') == 'example.com'
        assert registrable_domain('deep.nested.example.com') == 'example.com'
        assert registrable_domain('example.com') == 'example.com'

    def test_multi_label_suffixes_are_respected(self):
        from app.services.whois_service import registrable_domain

        assert registrable_domain('mail.example.co.uk') == 'example.co.uk'
        assert registrable_domain('shop.example.co.il') == 'example.co.il'

    def test_subdomain_flood_produces_a_single_lookup(self, monkeypatch):
        from app.services.whois_service import WhoisService
        from app.utils.cache import cache_clear

        cache_clear()
        calls = []

        class FakeWhois:
            @staticmethod
            def whois(domain, **kwargs):
                calls.append(domain)
                return type('W', (), {
                    'registrar': 'R', 'creation_date': None, 'expiration_date': None,
                    'updated_date': None, 'status': None, 'name_servers': [],
                })()

        service = WhoisService()
        monkeypatch.setattr(service, 'whois_module', FakeWhois)

        for i in range(50):
            service.lookup(f'random{i}.example.com')

        assert len(calls) == 1, f'{len(calls)} outbound WHOIS lookups for one domain'
        cache_clear()


class TestSecurityHeaderParity:
    """The backend and both nginx configs must not drift apart."""

    @staticmethod
    def _nginx_csp(path):
        import re
        text = path.read_text(encoding='utf-8')
        matches = re.findall(r'add_header Content-Security-Policy "([^"]+)"', text)
        assert matches, f'no CSP in {path}'
        return matches

    def test_no_third_party_origin_in_any_csp(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[2]
        for rel in ['deploy/nginx.conf', 'ataram-frontend/nginx.conf']:
            for csp in self._nginx_csp(root / rel):
                assert 'http://' not in csp, f'{rel} CSP permits a plaintext origin'
                assert 'fonts.googleapis.com' not in csp, f'{rel} still allows Google Fonts'
                assert 'fonts.gstatic.com' not in csp, f'{rel} still allows Google Fonts'

    def test_every_nginx_csp_blocks_inline_script(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[2]
        for rel in ['deploy/nginx.conf', 'ataram-frontend/nginx.conf']:
            for csp in self._nginx_csp(root / rel):
                script_src = csp.split('script-src')[1].split(';')[0]
                assert "'unsafe-inline'" not in script_src, rel
                assert "'unsafe-eval'" not in script_src, rel

    def test_backend_csp_matches_nginx(self):
        """
        Divergence here is silent: the API and the page would enforce different
        policies and nobody would notice until an XSS slipped through one.
        """
        from pathlib import Path

        def directives(policy):
            """Full directive -> sources map. Comparing only NAMES would let
            `style-src https://evil.example` match `style-src 'self'`."""
            parsed = {}
            for part in policy.split(';'):
                tokens = part.split()
                if tokens:
                    parsed[tokens[0]] = tuple(sorted(tokens[1:]))
            return parsed

        app = create_app(TestingConfig)
        backend_csp = app.test_client().get('/health').headers['Content-Security-Policy']
        root = Path(__file__).resolve().parents[2]
        nginx_csp = self._nginx_csp(root / 'deploy/nginx.conf')[0]

        backend = directives(backend_csp)
        nginx = directives(nginx_csp)

        assert set(backend) == set(nginx), (
            f'CSP directive drift: backend-only={set(backend) - set(nginx)}, '
            f'nginx-only={set(nginx) - set(backend)}'
        )
        for name, sources in backend.items():
            assert sources == nginx[name], (
                f'CSP source drift on {name}: backend={sources} nginx={nginx[name]}'
            )

    def test_frontend_page_loads_no_third_party_resource(self):
        """A public security tool should not disclose its visitors to a third party."""
        from pathlib import Path

        html = (Path(__file__).resolve().parents[2]
                / 'ataram-frontend/src/index.html').read_text(encoding='utf-8')
        import re
        # Ignore commented-out blocks.
        stripped = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
        for attr in re.findall(r'(?:href|src)="([^"]+)"', stripped):
            assert not attr.startswith('http'), f'external resource still referenced: {attr}'


class TestLookupBudget:
    def test_budget_reports_exhaustion(self):
        budget = LookupBudget(0)
        assert budget.allows() is False
        assert budget.exhausted is True

    def test_budget_allows_within_window(self):
        budget = LookupBudget(30)
        assert budget.allows() is True
        assert budget.exhausted is False

    def test_result_flags_truncated_lookups(self, monkeypatch):
        for name in ('check_spf', 'check_dmarc'):
            monkeypatch.setattr(f'app.services.dns_checker.DNSCheckerService.{name}',
                                lambda *a, **k: None)
        monkeypatch.setattr('app.services.whois_service.WhoisService.lookup',
                            lambda *a, **k: None)

        analyzer = EmailAnalyzerService(limits={'LOOKUP_BUDGET_SECONDS': 0})
        result = analyzer.analyze({
            'headers': {'sender': 'a@example.com', 'auth_results': '', 'hops': [],
                        'return_path': '', 'reply_to': '', 'dkim_signature': ''},
            'body_text': '', 'body_html': '', 'attachments': [],
        })
        assert result['lookups_truncated'] is True

    def test_configured_timeouts_reach_the_services(self):
        """
        These were dead on the analyze path: the services were constructed with
        no arguments, so DNS_TIMEOUT / WHOIS_TIMEOUT applied only to the utility
        endpoints, which are disabled by default.
        """
        analyzer = EmailAnalyzerService(
            abuseipdb_key='k',
            limits={'DNS_TIMEOUT': 2, 'WHOIS_TIMEOUT': 4, 'HTTP_TIMEOUT': 6},
        )
        assert analyzer.dns_checker.timeout == 2
        assert analyzer.whois_service.timeout == 4
        assert analyzer.ip_reputation.timeout == 6

    def test_enable_whois_is_honoured_on_analyze_path(self, monkeypatch):
        called = []
        monkeypatch.setattr('app.services.whois_service.WhoisService.lookup',
                            lambda self, d: called.append(d))
        for name in ('check_spf', 'check_dmarc'):
            monkeypatch.setattr(f'app.services.dns_checker.DNSCheckerService.{name}',
                                lambda *a, **k: None)

        analyzer = EmailAnalyzerService(limits={'ENABLE_WHOIS': False})
        analyzer.analyze({
            'headers': {'sender': 'a@example.com', 'auth_results': '', 'hops': [],
                        'return_path': '', 'reply_to': '', 'dkim_signature': ''},
            'body_text': '', 'body_html': '', 'attachments': [],
        })
        assert called == [], 'ENABLE_WHOIS=false did not stop the lookup'
