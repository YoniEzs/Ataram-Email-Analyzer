"""
Tests for URL analysis heuristics.
"""

from app.services.url_analyzer import URLAnalyzerService


def test_userinfo_at_sign_detected():
    result = URLAnalyzerService().analyze_single_url('https://paypal.com@evil.example/login')
    assert 'url_contains_at_sign' in result['issues']


def test_at_sign_in_query_is_not_flagged():
    # "?email=user@example.com" is normal — only userinfo@host is phishy.
    result = URLAnalyzerService().analyze_single_url(
        'https://example.com/unsubscribe?email=user@example.com'
    )
    assert 'url_contains_at_sign' not in result['issues']


def test_at_sign_in_query_without_path_is_not_flagged():
    result = URLAnalyzerService().analyze_single_url('http://example.com?email=a@b.co')
    assert 'url_contains_at_sign' not in result['issues']


def test_shortener_and_suspicious_tld_detected():
    service = URLAnalyzerService()
    assert 'shortened_url' in service.analyze_single_url('https://bit.ly/3xYzAbC')['issues']
    assert 'suspicious_tld' in service.analyze_single_url('https://free-prize.xyz/win')['issues']


def test_extract_urls_strips_trailing_punctuation():
    urls = URLAnalyzerService().extract_urls(
        'Visit https://example.com/page. Or see (https://other.example/x).'
    )
    assert urls == ['https://example.com/page', 'https://other.example/x']


def test_url_collection_and_display_length_are_bounded():
    service = URLAnalyzerService(max_urls=2, max_url_length=32)
    urls = service.extract_urls(
        'https://one.example/a https://two.example/b https://three.example/c'
    )
    assert len(urls) == 2

    result = service.analyze_single_url('https://example.com/' + 'x' * 100)
    assert result['truncated'] is True
    assert result['original_length'] > 32
    assert len(result['url']) == 32
    assert 'url_too_long' in result['issues']


# ---------------------------------------------------------------------------
# Security-gateway wrappers
#
# Found in QA on a real message: every link was flagged, and two of them were
# eur02.safelinks.protection.outlook.com -- the recipient's own Microsoft
# Defender protection. The tool was naming the defence as the threat and
# never inspecting the real target sitting URL-encoded inside ?url=.
# ---------------------------------------------------------------------------

SAFELINK = (
    'https://eur02.safelinks.protection.outlook.com/'
    '?url=https%3A%2F%2Fevil.example.com%2Fpay&data=05%7C01%7C'
)


def test_safelinks_is_unwrapped_to_the_real_target():
    real, wrapper = URLAnalyzerService().unwrap_url(SAFELINK)

    assert real == 'https://evil.example.com/pay'
    assert wrapper == 'Microsoft Safe Links'


def test_proofpoint_v2_substitutions_are_reversed():
    real, wrapper = URLAnalyzerService().unwrap_url(
        'https://urldefense.proofpoint.com/v2/url'
        '?u=https-3A__evil.example.com_x&d=DwMFaQ'
    )

    assert real == 'https://evil.example.com/x'
    assert wrapper == 'Proofpoint URL Defense'


def test_proofpoint_v3_target_is_extracted():
    real, _ = URLAnalyzerService().unwrap_url(
        'https://urldefense.com/v3/__https://evil.example.com/x__;!!ABC$'
    )

    assert real == 'https://evil.example.com/x'


def test_mimecast_is_named_even_though_it_cannot_be_decoded():
    """Mimecast keeps the target server-side.

    Naming the gateway still matters: it explains why the hostname is not the
    sender's, which is otherwise read as an indicator.
    """
    url = 'https://protect-eu.mimecast.com/s/AbCd123'
    real, wrapper = URLAnalyzerService().unwrap_url(url)

    assert real == url
    assert 'Mimecast' in wrapper


def test_analysis_reports_the_target_not_the_gateway():
    result = URLAnalyzerService().analyze_single_url(SAFELINK)

    # Registered domain, so example.com rather than the full host -- the
    # point is that it is no longer outlook.com, the gateway's own domain.
    assert result['domain'] == 'example.com'
    assert result['url'] == 'https://evil.example.com/pay'
    assert result['wrapper'] == 'Microsoft Safe Links'
    assert result['wrapped_original'] == SAFELINK


def test_unwrapping_is_depth_limited():
    """A hostile link could otherwise nest wrappers to spin the analyser."""
    nested = SAFELINK
    for _ in range(6):
        nested = ('https://eur02.safelinks.protection.outlook.com/?url='
                  + __import__('urllib.parse', fromlist=['quote']).quote(nested, safe=''))

    real, _ = URLAnalyzerService().unwrap_url(nested)

    assert real.startswith('http')


# ---------------------------------------------------------------------------
# domain_mismatch_with_sender is informational
# ---------------------------------------------------------------------------

def test_domain_mismatch_alone_does_not_make_a_url_suspicious():
    """It fires on every link in every legitimate bulk message.

    The ESP that sent it, the tracking links, the unsubscribe link and the
    provider's own footer all trip it. At five points each it was supplying
    most of the score on clean marketing mail.
    """
    result = URLAnalyzerService().analyze_single_url(
        'https://mailer.example.net/news', sender_domain='example.com'
    )

    assert 'domain_mismatch_with_sender' in result['issues']
    assert result['informational_issues'] == ['domain_mismatch_with_sender']
    assert result['is_suspicious'] is False


def test_a_real_indicator_still_makes_a_url_suspicious():
    result = URLAnalyzerService().analyze_single_url(
        'https://paypal.example.top/login', sender_domain='example.com'
    )

    assert result['is_suspicious'] is True
