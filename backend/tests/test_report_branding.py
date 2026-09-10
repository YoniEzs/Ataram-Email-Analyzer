"""Ensure generated analyst reports use the active public product identity."""

from pathlib import Path


def test_runtime_brand_normalizes_legacy_print_key():
    app_js = Path(__file__).resolve().parents[2] / 'frontend' / 'src' / 'js' / 'app.js'
    text = app_js.read_text(encoding='utf-8')
    assert "'ITgalya Email Analyzer'" in text
    assert "key === 'Ataram Email Analyzer' ? 'ITgalya Email Analyzer'" in text
