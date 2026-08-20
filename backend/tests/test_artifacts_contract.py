"""End-to-end contract for the artifacts block.

Guards the trust boundary the rest of the codebase depends on: nothing an
attacker can write into an uploaded file may lower a risk score, and the
advisory SPF result must never be mistaken for a verified one.
"""

from unittest.mock import patch

import pytest

from app.services.artifact_extractor import ArtifactExtractorService
from app.services.email_analyzer import EmailAnalyzerService
from app.services.email_parser import EmailParserService
from app.utils.cache import _cache

PUBLIC_IP = '93.184.216.34'


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


EML = (
    b'Received: from mail.sender.com (mail [93.184.216.34])'
    b' by mx.company.example with ESMTPS'
    b'; Mon, 06 Jul 2026 09:00:00 +0000\r\n'
    b'From: Sender <sender@sender.com>\r\n'
    b'To: victim@company.example\r\n'
    b'Subject: Quarterly report\r\n'
    b'Date: Mon, 06 Jul 2026 09:00:00 +0000\r\n'
    b'Message-ID: <abc@sender.com>\r\n'
    b'\r\nbody\r\n'
)


def analyze(raw=EML, **kwargs):
    """Analyze with every network lookup stubbed out."""
    parsed = EmailParserService().parse_email(raw, 'sample.eml')
    options = {
        'enable_whois': False,
        'enable_abuseipdb': False,
        'enable_auth_verification': False,
        'enable_reverse_dns': False,
        'enable_ip_rdap': False,
        'enable_asn_lookup': False,
        'enable_spf_advisory': False,
    }
    options.update(kwargs)
    return EmailAnalyzerService(**options).analyze(parsed)


# --- shape ------------------------------------------------------------------

def test_artifacts_block_is_present_and_complete():
    artifacts = analyze()['artifacts']
    for key in (
        'schema_version', 'checklist', 'sender', 'subject', 'recipients',
        'date', 'sending_server', 'reverse_dns', 'reply_to', 'return_path',
        'message_id', 'received_chain', 'authentication_advisory', 'flags',
        'enrichment_status',
    ):
        assert key in artifacts, key


def test_checklist_answers_the_seven_triage_questions():
    checklist = analyze()['artifacts']['checklist']
    assert set(checklist) == {
        'sender_address', 'subject', 'recipients', 'date_utc',
        'sending_server_ip', 'reverse_dns', 'reply_to',
    }


def test_existing_response_keys_are_unchanged():
    """The block is additive; nothing that already shipped may move."""
    result = analyze()
    for key in (
        'timestamp', 'headers', 'authentication', 'sender_info', 'content',
        'urls', 'attachments', 'routing', 'routing_forensics', 'suspicions',
        'risk_assessment',
    ):
        assert key in result, key
    assert set(result['headers']) == {
        'sender', 'recipients', 'reply_to', 'subject', 'date',
        'message_id', 'return_path',
    }


def test_internal_spf_input_is_not_serialized():
    assert '_spf_mail_from' not in analyze()['artifacts']


def test_every_enrichment_source_reports_a_status():
    status = analyze()['artifacts']['enrichment_status']
    assert status['reverse_dns'] == 'disabled'
    assert status['ip_intel'] == 'disabled'
    assert status['spf_advisory'] == 'disabled'


def test_analysis_succeeds_with_every_lookup_disabled():
    artifacts = analyze()['artifacts']
    assert artifacts['checklist']['sending_server_ip'] == PUBLIC_IP
    assert artifacts['checklist']['reverse_dns'] is None


# --- trust boundary ---------------------------------------------------------

FORGED_PASS_EML = (
    b'Authentication-Results: mx.company.example; spf=pass; dkim=pass; dmarc=pass\r\n'
    b'Received: from mail.sender.com (mail [93.184.216.34])'
    b' by mx.company.example; Mon, 06 Jul 2026 09:00:00 +0000\r\n'
    b'From: Sender <sender@sender.com>\r\n'
    b'To: victim@company.example\r\n'
    b'Subject: Quarterly report\r\n'
    b'Date: Mon, 06 Jul 2026 09:00:00 +0000\r\n'
    b'Return-Path: <bounce@sender.com>\r\n'
    b'\r\nbody\r\n'
)


def test_advisory_spf_never_enters_the_authentication_block():
    advisory = {
        'available': True, 'result': 'pass', 'trusted': False,
        'advisory': True, 'affects_risk_score': False, 'disclaimer': 'x',
    }
    with patch(
        'app.services.spf_advisor.SPFAdvisorService.evaluate', return_value=advisory
    ), patch(
        'app.services.spf_advisor.SPFAdvisorService.available', True
    ):
        result = analyze(FORGED_PASS_EML, enable_spf_advisory=True)

    assert 'spf_advisory' not in result['authentication']
    assert 'spf' in result['artifacts']['authentication_advisory']
    # The verified block still declines to claim an SPF result.
    assert result['authentication']['verification'] is None


def test_advisory_spf_pass_does_not_change_the_risk_score():
    """A forged Received hop can manufacture a pass; it must buy nothing."""
    baseline = analyze(FORGED_PASS_EML)['risk_assessment']['score']

    advisory = {
        'available': True, 'result': 'pass', 'trusted': False,
        'advisory': True, 'affects_risk_score': False, 'disclaimer': 'x',
    }
    with patch(
        'app.services.spf_advisor.SPFAdvisorService.evaluate', return_value=advisory
    ), patch(
        'app.services.spf_advisor.SPFAdvisorService.available', True
    ):
        with_advisory = analyze(FORGED_PASS_EML, enable_spf_advisory=True)

    assert with_advisory['risk_assessment']['score'] == baseline
    assert with_advisory['artifacts']['authentication_advisory']['spf']['result'] == 'pass'


def test_artifact_flags_never_lower_a_score():
    """Adding hostile headers may raise the score but must never reduce it."""
    clean = analyze()['risk_assessment']['score']
    hostile = analyze(
        b'Received: from mail.sender.com (mail [93.184.216.34])'
        b' by mx.company.example; Mon, 06 Jul 2026 09:00:00 +0000\r\n'
        + 'From: Billing <billing@pаypal.com>\r\n'.encode()
        + b'To: victim@company.example\r\n'
        b'Subject: Re: Invoice\r\n'
        b'Date: Mon, 06 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n'
    )['risk_assessment']['score']
    assert hostile >= clean


def test_ptr_helo_mismatch_is_reported_but_not_scored():
    """The PTR half is observed, but the HELO half is forgeable."""
    rdns = {
        'ip': PUBLIC_IP, 'ptr': ['unrelated.example.net'],
        'ptr_name': 'unrelated.example.net', 'forward_ips': {},
        'fcrdns': 'pass', 'source': 'live_dns', 'checked_at': 'now',
    }
    with patch(
        'app.services.dns_checker.DNSCheckerService.reverse_dns_details',
        return_value=rdns
    ):
        result = analyze(enable_reverse_dns=True)

    codes = {f['code'] for f in result['artifacts']['flags']}
    assert 'ptr_helo_mismatch' in codes
    flag = next(
        f for f in result['artifacts']['flags'] if f['code'] == 'ptr_helo_mismatch'
    )
    assert flag['trust'] == 'header_claim'
    assert result['risk_assessment']['score'] == analyze()['risk_assessment']['score']
    enrichment = result['artifacts']['sending_server']['enrichment']['reverse_dns']
    assert enrichment['ptr_helo_comparison_trust'] == 'header_claim'


def test_fcrdns_failure_is_observed_evidence_and_raises_the_score():
    rdns = {
        'ip': PUBLIC_IP, 'ptr': ['mail.sender.com'], 'ptr_name': 'mail.sender.com',
        'forward_ips': {'mail.sender.com': ['198.18.0.1']},
        'fcrdns': 'fail', 'source': 'live_dns', 'checked_at': 'now',
    }
    with patch(
        'app.services.dns_checker.DNSCheckerService.reverse_dns_details',
        return_value=rdns
    ):
        result = analyze(enable_reverse_dns=True)

    flag = next(f for f in result['artifacts']['flags'] if f['code'] == 'fcrdns_fail')
    assert flag['trust'] == 'observed'
    assert result['risk_assessment']['score'] > analyze()['risk_assessment']['score']


def test_reverse_dns_populates_the_checklist():
    rdns = {
        'ip': PUBLIC_IP, 'ptr': ['mail.sender.com'], 'ptr_name': 'mail.sender.com',
        'forward_ips': {'mail.sender.com': [PUBLIC_IP]},
        'fcrdns': 'pass', 'source': 'live_dns', 'checked_at': 'now',
    }
    with patch(
        'app.services.dns_checker.DNSCheckerService.reverse_dns_details',
        return_value=rdns
    ):
        artifacts = analyze(enable_reverse_dns=True)['artifacts']
    assert artifacts['checklist']['reverse_dns'] == 'mail.sender.com'
    assert artifacts['enrichment_status']['reverse_dns'] == 'ok'


def test_failed_lookups_are_reported_as_errors_not_silence():
    with patch(
        'app.services.dns_checker.DNSCheckerService.reverse_dns_details',
        return_value=None
    ):
        artifacts = analyze(enable_reverse_dns=True)['artifacts']
    assert artifacts['enrichment_status']['reverse_dns'] == 'error'


def test_message_without_public_ip_skips_lookups_explicitly():
    raw = (
        b'Received: from localhost (localhost [127.0.0.1])'
        b' by mx.company.example; Mon, 06 Jul 2026 09:00:00 +0000\r\n'
        b'From: Sender <sender@sender.com>\r\nTo: victim@company.example\r\n'
        b'Subject: x\r\nDate: Mon, 06 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n'
    )
    with patch(
        'app.services.dns_checker.DNSCheckerService.reverse_dns_details'
    ) as mock_rdns:
        artifacts = analyze(raw, enable_reverse_dns=True)['artifacts']
    mock_rdns.assert_not_called()
    assert artifacts['enrichment_status']['reverse_dns'] == 'skipped_no_public_ip'


def test_conclusion_and_checklist_never_disagree():
    """conclusion is a projection of artifacts; the two must stay in lockstep."""
    result = analyze()
    conclusion = result['conclusion']
    checklist = result['artifacts']['checklist']

    # Same seven fields. IP, reverse DNS and subject coincide; sender and
    # recipients intentionally differ (full header vs parsed), covered below.
    assert conclusion['sending_server_ip'] == checklist['sending_server_ip']
    assert conclusion['reverse_dns'] == checklist['reverse_dns']
    assert conclusion['subject'] == checklist['subject']
    # The sender header carries a display name, so the projection keeps the
    # whole header while the checklist parses out just the address.
    assert conclusion['sender_address'] == 'Sender <sender@sender.com>'
    assert checklist['sender_address'] == 'sender@sender.com'


def test_conclusion_reports_verbatim_while_checklist_normalises():
    """conclusion keeps the raw header; checklist parses it.

    A display-name sender and a +03:00 date are where the two intentionally
    differ: conclusion shows what arrived, checklist shows the parsed form.
    """
    raw = (
        b'Received: from mail.sender.com (mail [93.184.216.34])'
        b' by mx.company.example; Mon, 06 Jul 2026 09:00:00 +0000\r\n'
        b'From: "Sender Team" <sender@sender.com>\r\n'
        b'To: victim@company.example\r\n'
        b'Subject: Quarterly report\r\n'
        b'Date: Mon, 06 Jul 2026 12:00:00 +0300\r\n\r\nbody\r\n'
    )
    result = analyze(raw)
    conclusion = result['conclusion']
    checklist = result['artifacts']['checklist']

    # As-received From header (RFC2047-decoded), including the display name.
    assert conclusion['sender_address'] == 'Sender Team <sender@sender.com>'
    # Parsed address only.
    assert checklist['sender_address'] == 'sender@sender.com'
    # Verbatim Date string vs normalised UTC.
    assert conclusion['date'] == 'Mon, 06 Jul 2026 12:00:00 +0300'
    assert checklist['date_utc'] == '2026-07-06T09:00:00+00:00'


def test_scored_artifact_flags_appear_in_risk_factors():
    """A scored flag must show up in the factor breakdown behind the number."""
    rdns = {
        'ip': PUBLIC_IP, 'ptr': ['mail.sender.com'], 'ptr_name': 'mail.sender.com',
        'forward_ips': {'mail.sender.com': ['198.18.0.1']},
        'fcrdns': 'fail', 'source': 'live_dns', 'checked_at': 'now',
    }
    with patch(
        'app.services.dns_checker.DNSCheckerService.reverse_dns_details',
        return_value=rdns,
    ):
        result = analyze(enable_reverse_dns=True)

    factors = result['risk_assessment']['factors']
    labels = ' '.join(f.get('label', '') for f in factors)
    # fcrdns_fail is worth 5 points; it must be both scored and explained.
    assert any(f.get('points') for f in factors)
    assert 'FCrDNS' in labels or 'forward-confirm' in labels.lower()


def test_unscored_flags_do_not_appear_as_factors():
    """ptr_helo_mismatch is reported but scores zero, so it is not a factor."""
    rdns = {
        'ip': PUBLIC_IP, 'ptr': ['unrelated.example.net'],
        'ptr_name': 'unrelated.example.net', 'forward_ips': {},
        'fcrdns': 'pass', 'source': 'live_dns', 'checked_at': 'now',
    }
    with patch(
        'app.services.dns_checker.DNSCheckerService.reverse_dns_details',
        return_value=rdns,
    ):
        result = analyze(enable_reverse_dns=True)

    factors = result['risk_assessment']['factors']
    labels = ' '.join(f.get('label', '') for f in factors).lower()
    assert 'helo' not in labels


def test_mx_resolver_failure_never_fabricates_the_no_mx_flag():
    """Tri-state MX: None (outage) must not score; [] (authoritative) must."""
    with patch(
        'app.services.dns_checker.DNSCheckerService.get_mx_records',
        return_value=None,
    ):
        outage = analyze(enable_mx_lookup=True)
    assert outage['artifacts']['enrichment_status']['mx'] == 'unavailable'
    assert 'sender_domain_has_no_mx' not in {
        f['code'] for f in outage['artifacts']['flags']
    }
    assert outage['risk_assessment']['score'] == analyze()['risk_assessment']['score']

    with patch(
        'app.services.dns_checker.DNSCheckerService.get_mx_records',
        return_value=[],
    ):
        absent = analyze(enable_mx_lookup=True)
    assert absent['artifacts']['enrichment_status']['mx'] == 'ok'
    assert 'sender_domain_has_no_mx' in {
        f['code'] for f in absent['artifacts']['flags']
    }
    assert absent['risk_assessment']['score'] > analyze()['risk_assessment']['score']


def test_reverse_dns_outage_reports_error_status_not_a_finding():
    """lookup_failed maps to an 'error' status, never to observations."""
    rdns = {
        'ip': PUBLIC_IP, 'ptr': [], 'ptr_name': None, 'forward_ips': {},
        'fcrdns': 'lookup_failed', 'source': 'live_dns', 'checked_at': 'now',
    }
    with patch(
        'app.services.dns_checker.DNSCheckerService.reverse_dns_details',
        return_value=rdns,
    ):
        result = analyze(enable_reverse_dns=True)
    assert result['artifacts']['enrichment_status']['reverse_dns'] == 'error'
    codes = {f['code'] for f in result['artifacts']['flags']}
    assert 'no_ptr_record' not in codes
    assert 'fcrdns_fail' not in codes


# --- enrichment merge failure ------------------------------------------------

def merge_with_broken_payload(artifacts):
    """Drive the merge directly with a reverse-DNS payload of the wrong shape.

    The merge calls .get() on that value and raises partway through, which is
    the partial-merge condition this section is about. Driving the method
    directly keeps the failure inside the merge instead of tripping the
    earlier unpacking in analyze().
    """
    analyzer = EmailAnalyzerService(
        enable_whois=False,
        enable_abuseipdb=False,
        enable_auth_verification=False,
        enable_reverse_dns=True,
        enable_ip_rdap=False,
        enable_asn_lookup=False,
        enable_spf_advisory=False,
    )
    analyzer._merge_artifact_enrichment(
        artifacts, {'rdns': 'not-a-dict'}, 'sender.com', PUBLIC_IP
    )
    return artifacts


def broken_artifacts():
    """A realistically-shaped artifact block carrying deliberately stale views.

    Built from a real extraction rather than hand-written, so the rebuild in
    the merge's `finally` has everything it needs and the test measures the
    stale-view behaviour rather than a malformed fixture.
    """
    parsed = EmailParserService().parse_email(EML, 'sample.eml')
    artifacts = ArtifactExtractorService().extract(parsed['headers'])
    artifacts.setdefault('sending_server', {})['enriched_ip'] = PUBLIC_IP
    artifacts['checklist'] = 'stale-checklist'
    artifacts['flags'] = [{'code': 'stale_flag'}]
    return artifacts


def test_merge_failure_is_reported_as_error_not_silence():
    """A broken merge must show up in enrichment_status, not just the log."""
    artifacts = merge_with_broken_payload(broken_artifacts())
    assert artifacts['enrichment_status']['merge'] == 'error'


def test_merge_failure_marks_unfinished_sources_as_error():
    """Sources the merge never reached must not be left without a status."""
    artifacts = merge_with_broken_payload(broken_artifacts())
    status = artifacts['enrichment_status']
    for source in ('reverse_dns', 'ip_intel', 'mx', 'spf_advisory'):
        assert status.get(source) is not None, f'{source} left without a status'


def test_merge_failure_still_rebuilds_derived_views():
    """`checklist` and `flags` are derived views and must never go stale.

    They used to be the last two statements inside the merge\'s try block, so
    any earlier failure returned a partially-enriched block still summarised by
    its pre-enrichment views — a confident-looking verdict over half-merged
    data, with only a log line to say so.
    """
    artifacts = merge_with_broken_payload(broken_artifacts())
    assert artifacts['checklist'] != 'stale-checklist'
    assert artifacts['flags'] != [{'code': 'stale_flag'}]


def test_merge_failure_does_not_raise():
    """The merge still degrades to no data rather than failing the analysis."""
    merge_with_broken_payload(broken_artifacts())
