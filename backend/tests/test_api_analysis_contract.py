"""
API contract tests for /api/analyze.
"""

from io import BytesIO

from app.api import analysis as analysis_api
from app.api.openapi import API_VERSION


def test_analyze_response_includes_new_contract_fields(client, monkeypatch):
    class DummyParserService:
        def __init__(self, **kwargs):
            self.options = kwargs

        def parse_email(self, data, filename):
            return {
                "headers": {},
                "body_text": "hello",
                "body_html": "",
                "attachments": [],
            }

    class DummyAnalyzerService:
        def __init__(self, abuseipdb_key=None, whitelist_domains=None, **kwargs):
            self.abuseipdb_key = abuseipdb_key
            self.whitelist_domains = whitelist_domains or []
            self.options = kwargs

        def analyze(self, parsed_data):
            return {
                "timestamp": "2026-03-09T10:00:00",
                "conclusion": {
                    "sender_address": None,
                    "subject": None,
                    "recipients": None,
                    "date": None,
                    "sending_server_ip": None,
                    "reverse_dns": None,
                    "reply_to": None,
                },
                "headers": {},
                "authentication": {},
                "sender_info": {},
                "content": {},
                "urls": {"total_count": 0, "unique_count": 0, "suspicious_count": 0, "urls": []},
                "attachments": {"total_count": 0, "suspicious_count": 0, "attachments": []},
                "routing": {"hops": [], "hop_count": 0},
                "artifacts": {
                    "schema_version": 1,
                    "checklist": {
                        "sender_address": None,
                        "subject": None,
                        "recipients": None,
                        "date_utc": None,
                        "sending_server_ip": None,
                        "reverse_dns": None,
                        "reply_to": None,
                    },
                    "flags": [],
                    "enrichment_status": {},
                },
                "routing_forensics": {
                    "public_ips": [],
                    "hop_count": 0,
                    "originating_ip": None,
                    "timezone_offset": None,
                },
                "suspicions": [],
                "risk_assessment": {
                    "score": 0,
                    "level": "low",
                    "verdict": "NO STRONG INDICATORS DETECTED - Not a guarantee of safety",
                    "whitelist_applied": False,
                },
            }

    monkeypatch.setattr(analysis_api, "EmailParserService", DummyParserService)
    monkeypatch.setattr(analysis_api, "EmailAnalyzerService", DummyAnalyzerService)

    eml_payload = (
        b"From: sender@example.com\n"
        b"To: recipient@example.com\n"
        b"Subject: Test\n"
        b"Date: Mon, 09 Mar 2026 09:00:00 +0000\n\n"
        b"Body"
    )

    response = client.post(
        "/api/analyze",
        data={"emailfile": (BytesIO(eml_payload), "sample.eml")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert "routing_forensics" in payload
    assert "conclusion" in payload
    assert set(payload["conclusion"]) == {
        "sender_address",
        "subject",
        "recipients",
        "date",
        "sending_server_ip",
        "reverse_dns",
        "reply_to",
    }
    assert "whitelist_applied" in payload["risk_assessment"]
    assert payload["risk_assessment"]["whitelist_applied"] is False
    # metadata.version tracks API_VERSION; the two had drifted (2.0 vs 2.1)
    # and are now bumped together whenever the response shape changes.
    assert payload["metadata"]["version"] == API_VERSION
    assert "artifacts" in payload
    assert set(payload["artifacts"]["checklist"]) == {
        "sender_address", "subject", "recipients", "date_utc",
        "sending_server_ip", "reverse_dns", "reply_to",
    }


def test_analyze_preserves_missing_file_error_behavior(client):
    response = client.post("/api/analyze", data={}, content_type="multipart/form-data")

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "No file provided"


def test_analyze_preserves_invalid_file_type_error_behavior(client):
    response = client.post(
        "/api/analyze",
        data={"emailfile": (BytesIO(b"hello"), "not-email.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "Invalid file type"
