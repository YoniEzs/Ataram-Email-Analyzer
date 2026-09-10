"""Release metadata regression tests."""

from pathlib import Path

from app.api.openapi import API_VERSION, OPENAPI_SPEC


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


def test_openapi_uses_active_brand_and_documents_privacy_context():
    assert OPENAPI_SPEC['info']['title'] == 'ITgalya Email Analyzer API'
    assert OPENAPI_SPEC['info']['version'] == API_VERSION == '2.3'

    metadata = OPENAPI_SPEC['components']['schemas']['AnalysisResult']['properties']['metadata']
    assert 'offline_mode' in metadata['required']
    assert metadata['properties']['offline_mode']['type'] == 'boolean'

    domain_responses = OPENAPI_SPEC['paths']['/check/domain']['post']['responses']
    ip_responses = OPENAPI_SPEC['paths']['/check/ip']['post']['responses']
    assert domain_responses['503']['$ref'].endswith('/FeatureDisabled')
    assert ip_responses['503']['$ref'].endswith('/FeatureDisabled')
