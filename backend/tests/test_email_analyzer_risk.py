"""
Tests for risk scoring and suspicion logic.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.services.artifact_extractor import FLAG_METADATA
from app.services.email_analyzer import (
    ARTIFACT_SCORE_CAP,
    ARTIFACT_SCORE_POINTS,
    ARTIFACT_SUSPICION_MESSAGES,
    EmailAnalyzerService,
)


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


# ---------------------------------------------------------------------------
# Artifact flag scoring
# ---------------------------------------------------------------------------


def score_with_flags(*codes):
    """Score an otherwise-clean message carrying only these artifact flags."""
    service = make_service()
    flags = [
        {
            'code': code,
            'severity': FLAG_METADATA.get(code, {}).get('severity', 'medium'),
            'trust': FLAG_METADATA.get(code, {}).get('trust', 'computed'),
        }
        for code in codes
    ]
    return service._calculate_risk_score(
        auth_analysis={'spf': 'pass'},
        abuse_data=None,
        url_analysis={'suspicious_count': 0},
        attachment_analysis={'suspicious_count': 0, 'attachments': []},
        content_analysis={'urgent_phrases': []},
        suspicions=[],
        artifacts={'flags': flags},
    )


def test_every_scored_flag_is_non_forgeable():
    """The trust model: only computed/observed evidence may move the score.

    A header_claim flag is something the attacker wrote, so scoring one would
    let a forged header raise its own verdict.
    """
    for code in ARTIFACT_SCORE_POINTS:
        trust = FLAG_METADATA.get(code, {}).get('trust')
        assert trust in {'computed', 'observed'}, (
            f'{code} scores {ARTIFACT_SCORE_POINTS[code]} points but its trust '
            f'is {trust!r} — only computed/observed flags may be scored'
        )


def test_every_scored_flag_has_analyst_wording():
    """A scored flag with no message would show as a bare code in the UI."""
    missing = [c for c in ARTIFACT_SCORE_POINTS if c not in ARTIFACT_SUSPICION_MESSAGES]
    assert not missing, f'scored flags without suspicion wording: {missing}'


def test_display_name_spoof_scores():
    """Regression: the classic display-name spoof was worth 0 points."""
    score, _, _, factors = score_with_flags('display_name_domain_mismatch')
    assert score == ARTIFACT_SCORE_POINTS['display_name_domain_mismatch']
    assert any('display name' in f['label'].lower() for f in factors)


def test_artifact_points_are_capped():
    """Header forensics alone must never dominate the verdict."""
    score, _, _, factors = score_with_flags(*ARTIFACT_SCORE_POINTS)
    assert score == ARTIFACT_SCORE_CAP
    assert sum(f['points'] for f in factors) == ARTIFACT_SCORE_CAP


def test_cap_is_spent_on_the_strongest_evidence_first():
    """Extraction order must not decide which evidence counts.

    Two 2-point flags are passed ahead of a 5-point one with a 6-point budget
    left after them; without ordering the 5-pointer would be truncated.
    """
    weak = [c for c, p in ARTIFACT_SCORE_POINTS.items() if p == 2]
    strong = [c for c, p in ARTIFACT_SCORE_POINTS.items() if p == 5]
    assert weak and strong, 'weight table changed — update this test'

    _, _, _, factors = score_with_flags(*weak, *strong)
    scored = [f['points'] for f in factors]
    # Highest-value factors are recorded first and none of them is truncated.
    assert scored == sorted(scored, reverse=True)
    assert scored[0] == 5


def test_flags_absent_from_the_weight_table_add_nothing():
    """Reported-but-unscored flags stay at zero.

    ``message_id_domain_differs_from_sender`` fires on every ESP-sent message;
    scoring it would flag most legitimate mail.
    """
    score, _, _, factors = score_with_flags(
        'message_id_domain_differs_from_sender', 'freemail_sender'
    )
    assert score == 0
    assert factors == []
