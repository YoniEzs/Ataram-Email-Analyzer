"""Release metadata regression tests."""

from pathlib import Path


def test_python_support_ceiling_matches_windows_dependency_policy():
    pyproject = Path(__file__).resolve().parents[1] / 'pyproject.toml'
    text = pyproject.read_text(encoding='utf-8')
    assert 'requires-python = ">=3.11,<3.14"' in text
    assert 'Programming Language :: Python :: 3.13' in text


def test_public_readme_documents_offline_mode_and_provenance():
    readme = Path(__file__).resolve().parents[2] / 'README.md'
    text = readme.read_text(encoding='utf-8')
    assert 'ITGALYA_OFFLINE_MODE=true' in text
    assert 'gh attestation verify' in text
    assert 'ITgalya Email Analyzer' in text
