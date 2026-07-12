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
