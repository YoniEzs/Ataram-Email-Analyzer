"""
Real-email functional matrix — end-to-end regression gate.

Builds realistic .eml messages and drives them through the *real* analysis
pipeline (parser → analyzer → scoring) via the Flask test client, with all
network lookups (DNS/WHOIS/AbuseIPDB/VirusTotal/auth-verification) disabled so
results are deterministic and offline. Everything that runs locally — parsing,
the header-claim trust model, URL/homograph analysis, attachment content
inspection, YARA, scoring, and hostile-input limits — is exercised for real.

Guards two properties that regressed or were under-served before:
  * forged Authentication-Results headers are never scored as trust;
  * a message whose only signal is a locally-verified malicious attachment
    (hidden executable, executable bytes under a document extension, or an
    executable inside an archive) reaches at least "medium" — it must not read
    as "NO STRONG INDICATORS DETECTED".
"""
import io
import zipfile
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime

import pytest

from app import create_app
from app.config import TestingConfig


class MatrixConfig(TestingConfig):
    """Offline, deterministic, no rate limiting for the multi-call matrix."""
    ENABLE_WHOIS = False
    ENABLE_ABUSEIPDB = False
    ENABLE_VIRUSTOTAL = False
    ENABLE_AUTH_VERIFICATION = False
    RATELIMIT_ENABLED = False


@pytest.fixture(scope="module")
def matrix_client():
    return create_app(MatrixConfig).test_client()


def _base(msg, sender, subject):
    msg["From"] = sender
    msg["To"] = "victim@example.com"
    msg["Subject"] = subject
    msg["Date"] = format_datetime(datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc))
    msg["Message-ID"] = "<test@example.com>"


def _analyze(client, data, filename="sample.eml"):
    resp = client.post(
        "/api/v1/analyze",
        data={"emailfile": (io.BytesIO(data), filename)},
        content_type="multipart/form-data",
    )
    return resp


def _categories(js):
    return {s["category"] for s in js.get("suspicions", [])}


def _zip_with(inner_name):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(inner_name, b"MZ" + b"\x90\x00" * 64)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Functional scenarios
# ---------------------------------------------------------------------------

def test_legitimate_plain_email_scores_low(matrix_client):
    m = EmailMessage()
    _base(m, "Alice <alice@example.com>", "Lunch tomorrow?")
    m["Return-Path"] = "<alice@example.com>"
    m.set_content("Hi Bob, are you free for lunch tomorrow at noon?")
    js = _analyze(matrix_client, m.as_bytes()).get_json()
    assert js["risk_assessment"]["level"] in ("low", "medium")


def test_forged_auth_results_are_not_scored_as_trust(matrix_client):
    m = EmailMessage()
    _base(m, "PayPal Security <security@paypa1.com>", "Your account has been limited")
    m["Return-Path"] = "<bounce@sketchy-mailer.ru>"
    m["Reply-To"] = "support@totally-not-paypal.tk"
    # Attacker-supplied header claiming everything passed:
    m["Authentication-Results"] = (
        "mx.local; spf=pass smtp.mailfrom=paypal.com; "
        "dkim=pass header.d=paypal.com; dmarc=pass"
    )
    m.set_content("Verify your account at http://paypa1.com/verify?login=1")
    resp = _analyze(matrix_client, m.as_bytes())
    assert resp.status_code == 200
    js = resp.get_json()
    # The forged pass headers must not grant trust nor a whitelist discount.
    assert js["risk_assessment"]["whitelist_applied"] is False
    verification = js["authentication"].get("verification") or {}
    assert verification.get("spf") != "pass"
    # The real, non-forgeable signal (domain mismatch) is still detected.
    assert "headers" in _categories(js)


def test_hebrew_phishing_with_zip_hidden_exe(matrix_client):
    m = EmailMessage()
    _base(m, "שירות לקוחות <service@bank-verify.tk>", "חשבונך יינעל - נדרשת פעולה דחופה")
    m.set_content(
        "לקוח יקר, זיהינו פעילות חשודה בחשבונך. עליך לאמת את הסיסמה שלך מיד "
        "אחרת החשבון יושעה: http://bank-verify.tk/login"
    )
    m.add_attachment(
        _zip_with("invoice.pdf.exe"),
        maintype="application", subtype="zip", filename="documents.zip",
    )
    js = _analyze(matrix_client, m.as_bytes()).get_json()
    cats = _categories(js)
    assert "attachments" in cats  # zip-hidden exe flagged
    assert "urls" in cats  # suspicious .tk TLD flagged
    atts = js["attachments"]["attachments"]
    assert any(a.get("severity") == "critical" for a in atts)
    # A phishing email carrying an executable must not read as "low".
    assert js["risk_assessment"]["level"] in ("medium", "high", "critical")


def test_ipv6_sender_ip_is_extracted(matrix_client):
    m = EmailMessage()
    _base(m, "sender@example.org", "Hello over IPv6")
    m["Received"] = (
        "from relay.example.org (relay.example.org "
        "[2001:4860:4860::8888]) by mx.local"
    )
    m.set_content("This message was relayed over IPv6.")
    js = _analyze(matrix_client, m.as_bytes()).get_json()
    ip = js["sender_info"].get("ip")
    assert ip and ":" in str(ip)


def test_homograph_url_in_html_is_flagged(matrix_client):
    m = EmailMessage()
    _base(m, "noreply@newsletter.com", "Special offer")
    m.set_content("Plain text fallback.")
    # 'pаypal' — second character is Cyrillic U+0430.
    m.add_alternative(
        '<html><body>Log in at '
        '<a href="http://pаypal.com/account">your account</a></body></html>',
        subtype="html",
    )
    js = _analyze(matrix_client, m.as_bytes()).get_json()
    assert js["urls"].get("suspicious_count", 0) > 0


@pytest.mark.parametrize("payload", [
    b"\x00\x01\x02 not an email at all " + b"\xff" * 50,
    b"From: x@y.com\r\nSubject: hi\r\n\r\n",
])
def test_hostile_input_degrades_gracefully(matrix_client, payload):
    resp = _analyze(matrix_client, payload)
    # Never a 500 — either a clean analysis or a validation rejection.
    assert resp.status_code in (200, 400)


# ---------------------------------------------------------------------------
# Scoring-adequacy gate: attachment-only threats must clear the medium floor
# ---------------------------------------------------------------------------

def _email_with_attachment(name, payload, ctype=("application", "octet-stream")):
    m = EmailMessage()
    _base(m, "x@throwaway.tk", "document")
    m.set_content("See the attached document.")
    m.add_attachment(payload, maintype=ctype[0], subtype=ctype[1], filename=name)
    return m.as_bytes()


@pytest.mark.parametrize("name,payload,ctype", [
    ("invoice.exe", b"MZ" + b"\x00" * 100, ("application", "octet-stream")),
    ("invoice.pdf", b"MZ\x90\x00" + b"\x00" * 200, ("application", "pdf")),
    ("docs.zip", _zip_with("invoice.pdf.exe"), ("application", "zip")),
])
def test_attachment_only_threat_reaches_at_least_medium(matrix_client, name, payload, ctype):
    js = _analyze(matrix_client, _email_with_attachment(name, payload, ctype)).get_json()
    ra = js["risk_assessment"]
    assert ra["level"] in ("medium", "high", "critical"), (
        f"{name} scored {ra['level']} (score={ra['score']}) — "
        f"a verified malicious attachment must not read as 'no strong indicators'"
    )
