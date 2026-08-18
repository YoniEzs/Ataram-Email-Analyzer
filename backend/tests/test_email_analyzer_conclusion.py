"""Tests for the conclusion (official artifacts) section, including reverse DNS.

`conclusion` is projected from the `artifacts` block, so these also pin that
the projection reports values verbatim as received. The normalised view lives
in `artifacts.checklist` and is covered by test_artifacts_contract.py.
"""

from app.services.email_analyzer import EmailAnalyzerService


def _analyzer():
    # Disable network-backed lookups; each test stubs the lookup batch.
    return EmailAnalyzerService(
        enable_whois=False,
        enable_abuseipdb=False,
        enable_virustotal=False,
        enable_auth_verification=False,
    )


def _parsed():
    return {
        "headers": {
            "sender": "Alice <alice@example.com>",
            "recipients": "bob@example.org, carol@example.org",
            "reply_to": "noreply@other.example",
            "date": "Mon, 09 Mar 2026 09:00:00 +0000",
            "subject": "Quarterly report",
            "hops": ["from mail.example.com ([8.8.8.8]) by mx.example.org"],
            "return_path": "bounce@example.com",
            "message_id": "<abc@example.com>",
            "auth_results": "",
            "auth_results_top": "",
            "dkim_signature": "",
        },
        "body_text": "hello",
        "body_html": "",
        "attachments": [],
    }


def test_conclusion_contains_official_artifacts(monkeypatch):
    analyzer = _analyzer()
    monkeypatch.setattr(
        analyzer,
        "_run_external_lookups",
        lambda *args, **kwargs: {"rdns": {"ptr_name": "dns.google", "fcrdns": "pass"}},
    )

    result = analyzer.analyze(_parsed())
    conclusion = result["conclusion"]

    assert conclusion["sender_address"] == "Alice <alice@example.com>"
    assert conclusion["subject"] == "Quarterly report"
    assert conclusion["recipients"] == "bob@example.org, carol@example.org"
    assert conclusion["date"] == "Mon, 09 Mar 2026 09:00:00 +0000"
    assert conclusion["sending_server_ip"] == "8.8.8.8"
    assert conclusion["reverse_dns"] == "dns.google"
    assert conclusion["reply_to"] == "noreply@other.example"

    # Reverse DNS also surfaces alongside the sender IP.
    assert result["sender_info"]["reverse_dns"] == "dns.google"
    assert result["sender_info"]["ip"] == "8.8.8.8"

    # The projection must not drift from the block it is derived from.
    checklist = result["artifacts"]["checklist"]
    assert checklist["sending_server_ip"] == conclusion["sending_server_ip"]
    assert checklist["reverse_dns"] == conclusion["reverse_dns"]
    assert checklist["subject"] == conclusion["subject"]


def test_reverse_dns_lookup_is_requested_for_the_sender_ip():
    analyzer = _analyzer()
    captured = {}

    def fake_lookups(sender_domain, sender_ip, dkim_domain, dkim_selector, **kwargs):
        captured["sender_ip"] = sender_ip
        return {"rdns": None}

    analyzer._run_external_lookups = fake_lookups
    result = analyzer.analyze(_parsed())

    assert captured["sender_ip"] == "8.8.8.8"
    # A missing PTR record is reported as null rather than omitted.
    assert result["conclusion"]["reverse_dns"] is None


def test_conclusion_handles_missing_headers_gracefully(monkeypatch):
    analyzer = _analyzer()
    monkeypatch.setattr(
        analyzer, "_run_external_lookups", lambda *args, **kwargs: {}
    )

    result = analyzer.analyze(
        {"headers": {}, "body_text": "", "body_html": "", "attachments": []}
    )
    conclusion = result["conclusion"]

    assert set(conclusion) == {
        "sender_address",
        "subject",
        "recipients",
        "date",
        "sending_server_ip",
        "reverse_dns",
        "reply_to",
    }
    assert conclusion["sending_server_ip"] is None
    assert conclusion["reverse_dns"] is None
