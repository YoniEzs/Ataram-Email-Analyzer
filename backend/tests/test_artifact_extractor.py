"""Tests for offline artifact extraction.

Every case here is CPU-only: no DNS, no HTTP, and a fixed clock so date
comparisons are deterministic.
"""

from datetime import datetime, timezone

import pytest

from app.services.artifact_extractor import (
    ArtifactExtractorService,
    analyze_recipients,
    analyze_subject,
    classify_domain,
    split_address,
)
from app.services.email_parser import EmailParserService

PUBLIC_IP = '93.184.216.34'
NOW = datetime(2026, 7, 6, 10, 0, 0, tzinfo=timezone.utc)


def build(headers_block: bytes) -> dict:
    """Parse a raw EML and extract artifacts with a frozen clock."""
    parsed = EmailParserService().parse_email(headers_block, 'sample.eml')
    assert not parsed.get('error'), parsed.get('error')
    return ArtifactExtractorService(now=lambda: NOW).extract(parsed['headers'])


BASE_HOP = (
    b"Received: from mail.sender.example (mail.sender.example [93.184.216.34])\r\n"
    b"\tby mx.company.example with ESMTPS id ABC\r\n"
    b"\tfor <victim@company.example>; Mon, 06 Jul 2026 09:00:00 +0000\r\n"
)


def eml(extra: bytes = b'', hop: bytes = BASE_HOP) -> bytes:
    return (
        hop
        + b"From: Sender <sender@sender.example>\r\n"
        + b"To: victim@company.example\r\n"
        + b"Subject: Quarterly report\r\n"
        + b"Date: Mon, 06 Jul 2026 09:00:00 +0000\r\n"
        + b"Message-ID: <abc@sender.example>\r\n"
        + extra
        + b"\r\nbody\r\n"
    )


def codes(artifacts: dict) -> set:
    return {flag['code'] for flag in artifacts['flags']}


# --- the seven checklist artifacts -----------------------------------------

def test_checklist_covers_all_seven_triage_fields():
    artifacts = build(eml(b"Reply-To: replies@sender.example\r\n"))
    checklist = artifacts['checklist']
    assert set(checklist) == {
        'sender_address', 'subject', 'recipients', 'date_utc',
        'sending_server_ip', 'reverse_dns', 'reply_to',
    }
    assert checklist['sender_address'] == 'sender@sender.example'
    assert checklist['subject'] == 'Quarterly report'
    assert checklist['recipients'] == 'victim@company.example'
    assert checklist['date_utc'] == '2026-07-06T09:00:00+00:00'
    assert checklist['sending_server_ip'] == PUBLIC_IP
    assert checklist['reply_to'] == 'replies@sender.example'
    # Filled in later by the live lookup layer.
    assert checklist['reverse_dns'] is None


def test_clean_message_raises_no_flags():
    assert codes(build(eml())) == set()


# --- sender ----------------------------------------------------------------

def test_display_name_carrying_a_foreign_address_is_flagged():
    artifacts = build(
        BASE_HOP
        + b'From: "Support security@paypal.com" <billing@evil.example>\r\n'
        + b"To: victim@company.example\r\nSubject: x\r\n"
        + b"Date: Mon, 06 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n"
    )
    assert 'display_name_domain_mismatch' in codes(artifacts)
    assert artifacts['sender']['embedded_display_address'] == 'security@paypal.com'


def test_display_name_with_matching_domain_is_not_flagged():
    artifacts = build(
        BASE_HOP
        + b'From: "Billing billing@sender.example" <other@sender.example>\r\n'
        + b"To: victim@company.example\r\nSubject: x\r\n"
        + b"Date: Mon, 06 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n"
    )
    assert 'display_name_domain_mismatch' not in codes(artifacts)


def test_freemail_and_disposable_sender_domains_are_classified():
    assert classify_domain('gmail.com')['freemail'] is True
    assert classify_domain('mailinator.com')['disposable'] is True
    assert classify_domain('sender.example')['freemail'] is False


def test_homoglyph_sender_domain_is_flagged_as_computed():
    artifacts = build(
        BASE_HOP
        + 'From: Billing <billing@pаypal.com>\r\n'.encode()
        + b"To: victim@company.example\r\nSubject: x\r\n"
        + b"Date: Mon, 06 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n"
    )
    flag = next(f for f in artifacts['flags'] if f['code'] == 'homoglyph_sender_domain')
    assert flag['trust'] == 'computed'
    assert flag['severity'] == 'high'


def test_split_address_handles_bare_and_angle_forms():
    assert split_address('a@b.example')['address'] == 'a@b.example'
    parsed = split_address('Name <A@B.Example>')
    assert parsed['display_name'] == 'Name'
    assert parsed['address'] == 'a@b.example'
    assert parsed['domain'] == 'b.example'
    assert split_address('')['address'] is None


# --- subject ---------------------------------------------------------------

def test_rtl_override_in_subject_is_flagged():
    artifacts = build(eml())
    artifacts_subject = analyze_subject({'subject': 'Invoice ‮fdp.exe'})
    assert 'bidi_override_in_subject' in artifacts_subject['flags']
    assert artifacts_subject['bidi_controls'] == ['U+202E']
    assert artifacts is not None


def test_hebrew_subject_with_directional_marks_is_not_flagged():
    """LRM/RLM are ordinary in Hebrew mail and must not raise a flag.

    This is the asymmetry with filename checking, which does flag them.
    """
    result = analyze_subject({'subject': '‎שלום, מצורף החשבון‏'})
    assert result['bidi_controls'] == []
    assert 'bidi_override_in_subject' not in result['flags']


def test_zero_width_characters_in_subject_are_flagged():
    result = analyze_subject({'subject': 'pay​pal security notice'})
    assert result['zero_width'] == ['U+200B']
    assert 'zero_width_in_subject' in result['flags']


def test_mixed_encoded_word_charsets_are_flagged():
    result = analyze_subject({
        'subject': 'Re: Invoice',
        'subject_raw': '=?utf-8?B?UmU6?= =?windows-1251?B?7/Do?=',
    })
    assert result['charsets'] == ['utf-8', 'windows-1251']
    assert 'mixed_charsets_in_subject' in result['flags']


def test_reply_prefix_without_thread_headers_is_flagged():
    result = analyze_subject({'subject': 'Re: Invoice 4471'})
    assert result['reply_prefixes'] == ['Re']
    assert 'reply_prefix_without_thread_headers' in result['flags']


def test_reply_prefix_with_thread_headers_is_not_flagged():
    result = analyze_subject({
        'subject': 'Re: Invoice 4471',
        'references': '<original@sender.example>',
    })
    assert result['has_thread_headers'] is True
    assert 'reply_prefix_without_thread_headers' not in result['flags']


def test_stacked_and_counted_reply_prefixes_are_recognised():
    assert analyze_subject({'subject': 'Re[2]: Fwd: x'})['reply_prefixes']


def test_empty_subject_is_flagged():
    assert 'empty_subject' in analyze_subject({'subject': '   '})['flags']


# --- recipients ------------------------------------------------------------

def test_to_and_cc_are_split_not_merged():
    artifacts = build(
        BASE_HOP
        + b"From: Sender <sender@sender.example>\r\n"
        + b"To: a@company.example, b@company.example\r\n"
        + b"Cc: c@company.example\r\n"
        + b"Subject: x\r\nDate: Mon, 06 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n"
    )
    recipients = artifacts['recipients']
    assert recipients['to_count'] == 2
    assert recipients['cc_count'] == 1
    assert [e['address'] for e in recipients['cc']] == ['c@company.example']


def test_delivered_to_outside_to_and_cc_infers_bcc_delivery():
    artifacts = build(eml(b"Delivered-To: hidden@company.example\r\n"))
    assert artifacts['recipients']['bcc_inferred'] == ['hidden@company.example']
    assert 'possible_bcc_delivery' in codes(artifacts)


def test_delivered_to_matching_a_visible_recipient_is_not_bcc():
    artifacts = build(eml(b"Delivered-To: victim@company.example\r\n"))
    assert artifacts['recipients']['bcc_inferred'] == []
    assert 'possible_bcc_delivery' not in codes(artifacts)


def test_undisclosed_recipients_group_syntax_is_detected():
    """getaddresses() flattens this to [('','')], so to_raw is the only tell."""
    result = analyze_recipients({
        'to': [], 'cc': [],
        'to_raw': 'undisclosed-recipients:;',
    })
    assert result['undisclosed'] is True
    assert 'undisclosed_recipients' in result['flags']
    assert 'no_visible_recipients' not in result['flags']


def test_missing_to_header_is_distinct_from_undisclosed():
    result = analyze_recipients({'to': [], 'cc': [], 'to_raw': ''})
    assert result['undisclosed'] is False
    assert 'no_visible_recipients' in result['flags']


def test_large_recipient_list_is_flagged():
    many = [{'name': '', 'address': f'u{i}@company.example'} for i in range(60)]
    assert 'large_recipient_list' in analyze_recipients({'to': many})['flags']


# --- date ------------------------------------------------------------------

def test_date_is_normalised_to_utc_with_offset_preserved():
    artifacts = build(
        BASE_HOP
        + b"From: Sender <sender@sender.example>\r\nTo: victim@company.example\r\n"
        + b"Subject: x\r\nDate: Mon, 06 Jul 2026 12:00:00 +0300\r\n\r\nbody\r\n"
    )
    assert artifacts['date']['utc'] == '2026-07-06T09:00:00+00:00'
    assert artifacts['date']['offset_minutes'] == 180


def test_future_dated_message_is_flagged():
    artifacts = build(
        BASE_HOP
        + b"From: Sender <sender@sender.example>\r\nTo: victim@company.example\r\n"
        + b"Subject: x\r\nDate: Tue, 07 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n"
    )
    assert 'future_dated' in codes(artifacts)


def test_date_after_last_hop_is_flagged_as_computed():
    """Date claims 09:30 but the newest hop stamped 09:00 — self-inconsistent."""
    artifacts = build(
        BASE_HOP
        + b"From: Sender <sender@sender.example>\r\nTo: victim@company.example\r\n"
        + b"Subject: x\r\nDate: Mon, 06 Jul 2026 09:30:00 +0000\r\n\r\nbody\r\n"
    )
    assert 'date_after_last_hop' in codes(artifacts)
    flag = next(f for f in artifacts['flags'] if f['code'] == 'date_after_last_hop')
    assert flag['trust'] == 'computed'


def test_small_clock_skew_is_tolerated():
    artifacts = build(
        BASE_HOP
        + b"From: Sender <sender@sender.example>\r\nTo: victim@company.example\r\n"
        + b"Subject: x\r\nDate: Mon, 06 Jul 2026 09:01:00 +0000\r\n\r\nbody\r\n"
    )
    assert 'date_after_last_hop' not in codes(artifacts)


def test_unparseable_and_missing_dates_are_flagged():
    from app.services.artifact_extractor import analyze_date
    assert 'unparseable_date' in analyze_date({'date': 'yesterday'}, [], NOW)['flags']
    assert 'missing_date' in analyze_date({'date': ''}, [], NOW)['flags']


def test_out_of_order_received_chain_is_flagged():
    hop = (
        b"Received: from a.example by b.example; Mon, 06 Jul 2026 08:00:00 +0000\r\n"
        b"Received: from c.example by d.example; Mon, 06 Jul 2026 09:00:00 +0000\r\n"
    )
    artifacts = build(eml(hop=hop))
    assert 'received_chain_out_of_order' in codes(artifacts)


# --- sending server --------------------------------------------------------

def test_oldest_public_hop_is_the_sending_server():
    hop = (
        b"Received: from edge.example (edge [1.1.1.1])"
        b" by mx.company.example; Mon, 06 Jul 2026 09:00:10 +0000\r\n"
        b"Received: from mail.sender.example (mail [93.184.216.34])"
        b" by edge.example; Mon, 06 Jul 2026 09:00:00 +0000\r\n"
    )
    server = build(eml(hop=hop))['sending_server']
    assert server['ip'] == PUBLIC_IP
    assert server['edge_ip'] == '1.1.1.1'
    assert server['ip_chain'] == ['1.1.1.1', PUBLIC_IP]
    assert server['helo_claimed'] == 'mail.sender.example'
    # Only the origin is enriched, bounding the per-message lookup budget.
    assert server['enriched_ip'] == PUBLIC_IP


def test_repeated_origin_ip_does_not_shift_to_a_middle_relay():
    """Dedup regression: hops [A, B, A] must keep A as the origin.

    The chain dedups newest-first to [A, B]; taking its last element would
    misname the middle relay B as the sending server, diverging from
    extract_sender_ip which scans from the oldest hop.
    """
    hop = (
        b"Received: from edge.example (edge [1.1.1.1])"
        b" by mx.company.example; Mon, 06 Jul 2026 09:00:20 +0000\r\n"
        b"Received: from mid.example (mid [9.9.9.9])"
        b" by edge.example; Mon, 06 Jul 2026 09:00:10 +0000\r\n"
        b"Received: from origin.example (origin [1.1.1.1])"
        b" by mid.example; Mon, 06 Jul 2026 09:00:00 +0000\r\n"
    )
    server = build(eml(hop=hop))['sending_server']
    assert server['ip'] == '1.1.1.1'
    assert server['enriched_ip'] == '1.1.1.1'
    assert server['ip_chain'] == ['1.1.1.1', '9.9.9.9']


def test_freemail_return_path_uses_its_own_flag_code():
    """A freemail Return-Path must not raise the Reply-To flag: the analyst
    reads these messages verbatim, and 'Reply-To points at consumer webmail'
    is factually wrong when no Reply-To header exists."""
    artifacts = build(
        BASE_HOP
        + b"From: Sender <sender@sender.com>\r\nTo: victim@company.example\r\n"
        + b"Return-Path: <bounces@gmail.com>\r\n"
        + b"Subject: x\r\nDate: Mon, 06 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n"
    )
    assert 'freemail_return_path' in codes(artifacts)
    assert 'freemail_reply_target' not in codes(artifacts)


def test_message_with_no_public_hop_is_flagged():
    hop = (
        b"Received: from localhost (localhost [127.0.0.1])"
        b" by mx.company.example; Mon, 06 Jul 2026 09:00:00 +0000\r\n"
    )
    artifacts = build(eml(hop=hop))
    assert artifacts['sending_server']['ip'] is None
    assert 'no_public_sender_ip' in codes(artifacts)


# --- reply-to / return-path ------------------------------------------------

def test_freemail_reply_to_on_corporate_sender_is_flagged():
    artifacts = build(eml(b"Reply-To: refunds@gmail.com\r\n"))
    assert 'reply_to_differs_from_sender' in codes(artifacts)
    assert 'freemail_reply_target' in codes(artifacts)


def test_subdomain_reply_to_is_not_a_mismatch():
    """Comparison is on the registered domain, so a subdomain still matches.

    Uses a real TLD on purpose: ``.example`` is reserved by RFC 2606 but is not
    a Public Suffix List entry, so tldextract cannot reduce it and falls back
    to the full host.
    """
    artifacts = build(
        BASE_HOP
        + b"From: Sender <sender@sender.com>\r\nTo: victim@company.example\r\n"
        + b"Reply-To: replies@mail.sender.com\r\n"
        + b"Subject: x\r\nDate: Mon, 06 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n"
    )
    assert 'reply_to_differs_from_sender' not in codes(artifacts)


def test_different_registered_domain_reply_to_is_a_mismatch():
    artifacts = build(
        BASE_HOP
        + b"From: Sender <sender@sender.com>\r\nTo: victim@company.example\r\n"
        + b"Reply-To: replies@attacker.com\r\n"
        + b"Subject: x\r\nDate: Mon, 06 Jul 2026 09:00:00 +0000\r\n\r\nbody\r\n"
    )
    assert 'reply_to_differs_from_sender' in codes(artifacts)


# --- resilience ------------------------------------------------------------

def test_extract_never_raises_on_garbage_headers():
    result = ArtifactExtractorService(now=lambda: NOW).extract(
        {'sender': None, 'hops': 'not-a-list', 'to': 'not-a-list'}
    )
    assert 'checklist' in result


def test_extract_handles_completely_empty_headers():
    result = ArtifactExtractorService(now=lambda: NOW).extract({})
    assert result['checklist']['sender_address'] is None
    assert result['sending_server']['ip'] is None


@pytest.mark.parametrize('key', [
    'sender', 'subject', 'recipients', 'date', 'sending_server',
    'reverse_dns', 'reply_to', 'return_path', 'message_id',
])
def test_every_artifact_declares_its_trust(key):
    assert build(eml())[key]['trust'] in {'header_claim', 'computed', 'observed'}
