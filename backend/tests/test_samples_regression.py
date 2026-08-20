"""Regression corpus: the sample verdicts documented in samples/README.md.

`samples/README.md` publishes an exact score, level and artifact-flag set for
each shipped `.eml`. Those numbers are the first thing a new user checks, and
until now nothing enforced them — the scoring code could drift and the table
would quietly become a lie.

The expectations below are transcribed from that table and must be updated
together with it. Every lookup is disabled here because the table states its
numbers were produced in offline mode; enabling enrichment legitimately
raises some scores.
"""

from pathlib import Path

import pytest

from app.services.email_analyzer import EmailAnalyzerService
from app.services.email_parser import EmailParserService
from app.utils.cache import _cache

SAMPLES_DIR = Path(__file__).resolve().parents[2] / 'samples'

# (score, level, artifact flag codes) — from the table in samples/README.md.
# A flag set of None means the table describes the finding in prose rather
# than naming codes, so only the score and level are pinned.
DOCUMENTED = {
    '01-clean-newsletter.eml': (0, 'low', []),
    '02-display-name-spoof.eml': (11, 'low', [
        'display_name_domain_mismatch',
        'freemail_reply_target',
        'reply_prefix_without_thread_headers',
        'reply_to_differs_from_sender',
    ]),
    '03-homograph-sender.eml': (9, 'low', ['homoglyph_sender_domain']),
    '04-bcc-delivery.eml': (0, 'low', [
        'possible_bcc_delivery',
        'reply_prefix_without_thread_headers',
    ]),
    '05-zip-double-extension.eml': (25, 'medium', None),
}


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


def analyze_sample(filename):
    """Run one shipped sample through the real pipeline, fully offline."""
    raw = (SAMPLES_DIR / filename).read_bytes()
    parsed = EmailParserService().parse_email(raw, filename)
    return EmailAnalyzerService(
        enable_whois=False,
        enable_abuseipdb=False,
        enable_virustotal=False,
        enable_auth_verification=False,
        enable_reverse_dns=False,
        enable_ip_rdap=False,
        enable_asn_lookup=False,
        enable_mx_lookup=False,
        enable_spf_advisory=False,
    ).analyze(parsed)


def flag_codes(result):
    flags = result.get('artifacts', {}).get('flags') or []
    return sorted({f.get('code') for f in flags if f.get('code')})


def test_every_documented_sample_exists():
    """The table must not name a file that was renamed or deleted."""
    on_disk = {p.name for p in SAMPLES_DIR.glob('*.eml')}
    assert on_disk == set(DOCUMENTED), (
        'samples/ and the table in samples/README.md have diverged'
    )


@pytest.mark.parametrize('filename', sorted(DOCUMENTED))
def test_sample_matches_documented_score(filename):
    expected_score, expected_level, _ = DOCUMENTED[filename]
    assessment = analyze_sample(filename)['risk_assessment']
    assert assessment['score'] == expected_score, (
        f'{filename}: samples/README.md documents {expected_score}, '
        f"got {assessment['score']} — update the table or fix the scorer"
    )
    assert assessment['level'] == expected_level


@pytest.mark.parametrize('filename', sorted(DOCUMENTED))
def test_sample_matches_documented_flags(filename):
    _, _, expected_flags = DOCUMENTED[filename]
    if expected_flags is None:
        pytest.skip('table describes this sample in prose, not flag codes')
    assert flag_codes(analyze_sample(filename)) == sorted(expected_flags)


def test_clean_sample_raises_nothing():
    """The benign baseline is the false-positive canary for every new rule."""
    result = analyze_sample('01-clean-newsletter.eml')
    assert flag_codes(result) == []
    assert result['risk_assessment']['score'] == 0


def test_attachment_sample_is_flagged_critical():
    """Sample 05's table entry says 'attachment flagged critical'."""
    result = analyze_sample('05-zip-double-extension.eml')
    attachments = result['attachments']['attachments']
    assert any(a['severity'] == 'critical' for a in attachments)
