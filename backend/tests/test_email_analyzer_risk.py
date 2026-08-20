"""
Tests for risk scoring and suspicion logic.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.services.email_analyzer import EmailAnalyzerService


def make_service(whitelist_domains=None):
    service = object.__new__(EmailAnalyzerService)
    service.whitelist_domains = whitelist_domains or []
    return service


def whois_with_age(days_old):
    created = (
        datetime.now(timezone.utc) - timedelta(days=days_old, hours=1)
    ).replace(microsecond=0, tzinfo=None)
    return {"creation_date": created.isoformat()}


@pytest.mark.parametrize(
    "age_days,expected_points",
    [
        (3, 20),
        (20, 15),
        (60, 8),
        (200, 3),
        (500, 0),
    ],
)
def test_domain_age_scoring_bands(age_days, expected_points):
    service = make_service()
    score, _, _, _ = service._calculate_risk_score(
        auth_analysis={"spf": "pass"},
        abuse_data=None,
        url_analysis={"suspicious_count": 0},
        attachment_analysis={"suspicious_count": 0, "attachments": []},
        content_analysis={"urgent_phrases": []},
        suspicions=[],
        whois_data=whois_with_age(age_days),
        sender_domain="example.com",
    )

    assert score == expected_points


def test_detects_newly_registered_domain_suspicion():
    service = make_service()
    suspicions = service._detect_suspicions(
        headers={"sender": "alice@example.com", "return_path": "", "reply_to": ""},
        abuse_data=None,
        auth_analysis={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        url_analysis={"suspicious_count": 0},
        attachment_analysis={"suspicious_count": 0},
        whois_data=whois_with_age(10),
    )

    assert any(s["category"] == "domain_age" for s in suspicions)


def test_compound_escalation_forces_critical_floor():
    service = make_service()
    suspicions = []

    score, level, _, _ = service._calculate_risk_score(
        auth_analysis={"spf": "fail"},
        abuse_data={"abuseConfidenceScore": 0},
        url_analysis={"suspicious_count": 0},
        attachment_analysis={
            "suspicious_count": 1,
            "attachments": [{"issues": ["executable_file"]}],
        },
        content_analysis={"urgent_phrases": []},
        suspicions=suspicions,
        whois_data=whois_with_age(12),
        sender_domain="attacker.example",
    )

    assert score >= 85
    assert level == "critical"
    assert any(s["category"] == "compound_escalation" for s in suspicions)


def test_whitelist_does_not_suppress_high_risk_signals():
    service = make_service(whitelist_domains=["trusted.com"])

    common_kwargs = {
        "abuse_data": {"abuseConfidenceScore": 80},
        "url_analysis": {"suspicious_count": 4},
        "attachment_analysis": {
            "suspicious_count": 2,
            "attachments": [{"issues": ["archive_file"]}],
        },
        "content_analysis": {"urgent_phrases": ["urgent", "act now", "verify your account"]},
        "suspicions": [],
        "whois_data": whois_with_age(4),
    }

    whitelisted_score, _, whitelisted_applied, _ = service._calculate_risk_score(
        auth_analysis={"spf": "pass"},
        sender_domain="trusted.com",
        verification={
            'available': True,
            'dkim': 'pass',
            'dkim_alignment_relaxed': 'pass',
        },
        **common_kwargs,
    )
    non_whitelisted_score, _, non_whitelisted_applied, _ = service._calculate_risk_score(
        auth_analysis={"spf": "pass"},
        sender_domain="untrusted.com",
        **common_kwargs,
    )

    assert whitelisted_applied is True
    assert whitelisted_score == non_whitelisted_score
    assert non_whitelisted_applied is False
    assert whitelisted_score >= 75


def test_risk_factors_break_down_the_score():
    service = make_service()
    score, _, _, factors = service._calculate_risk_score(
        auth_analysis={"spf": "fail"},
        abuse_data={"abuseConfidenceScore": 80},
        url_analysis={"suspicious_count": 2},
        attachment_analysis={"suspicious_count": 0, "attachments": []},
        content_analysis={"urgent_phrases": ["urgent", "act now"]},
        suspicions=[],
        whois_data=whois_with_age(500),
        sender_domain="example.com",
    )

    labels = {f["label"] for f in factors}
    assert "Sender IP reputation" in labels
    assert "Suspicious URLs" in labels
    assert "Urgent / pressure language" in labels
    # Points recorded on the factors add up to the (uncapped) score.
    assert sum(f["points"] for f in factors) == score
    # Zero-point signals (no attachments here) are not listed.
    assert "Suspicious attachments" not in labels
    for factor in factors:
        assert factor["severity"] in {"info", "low", "medium", "high", "critical"}


def test_whitelist_gives_small_discount_to_low_risk_mail():
    service = make_service(whitelist_domains=['trusted.com'])

    score, level, whitelist_applied, _ = service._calculate_risk_score(
        auth_analysis={'spf': 'pass'},
        abuse_data={'abuseConfidenceScore': 20},
        url_analysis={'suspicious_count': 0},
        attachment_analysis={'suspicious_count': 0, 'attachments': []},
        content_analysis={'urgent_phrases': []},
        suspicions=[],
        sender_domain='trusted.com',
        verification={
            'available': True,
            'dkim': 'pass',
            'dkim_alignment_relaxed': 'pass',
        },
    )

    assert whitelist_applied is True
    assert score == 0
    assert level == 'low'
