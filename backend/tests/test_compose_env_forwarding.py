"""Guard: every network feature toggle the code reads is configurable in deploys.

The backend reads feature flags from ``os.environ`` through helpers in
``app.config``. Container/deployment manifests must forward those variables;
otherwise an operator could set a privacy toggle locally and have it silently
fall back to a network-enabled default in Docker or Render.
"""

import os
import re

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
_CONFIG_PY = os.path.join(
    os.path.dirname(__file__), '..', 'app', 'config.py'
)
_COMPOSE_FILES = ('docker-compose.yml', 'docker-compose.release.yml')

# Master privacy switch plus timeouts that matter once enrichment runs.
_PRIVACY_MASTER = frozenset({'ITGALYA_OFFLINE_MODE'})
_EXTRA_FORWARDED = frozenset(
    {'DNS_TIMEOUT', 'WHOIS_TIMEOUT', 'HTTP_TIMEOUT', 'SPF_TIMEOUT'}
)


def _enable_flags_read_by_code():
    """Every ENABLE_* env var config.py consumes.

    Config uses ``_network_feature_enabled('ENABLE_*', default)`` so the
    offline master switch can override every network feature. Keep support for
    direct ``os.environ.get`` as well so the guard survives either style.
    """
    with open(_CONFIG_PY, encoding='utf-8') as fh:
        source = fh.read()

    helper_flags = set(re.findall(
        r"_network_feature_enabled\(\s*['\"](ENABLE_[A-Z_]+)['\"]",
        source,
    ))
    direct_flags = set(re.findall(
        r"os\.environ\.get\(\s*['\"](ENABLE_[A-Z_]+)['\"]",
        source,
    ))
    flags = helper_flags | direct_flags
    assert flags, "no ENABLE_* flags found in config.py — parser out of date?"
    return flags


def _required_deployment_keys():
    return _enable_flags_read_by_code() | _PRIVACY_MASTER


def _backend_environment_keys(compose_filename):
    """Env var names under the backend service's ``environment:`` mapping.

    Parsed textually rather than via PyYAML so the test needs no dependency
    outside the standard library. The compose files use two-space service
    indentation and a mapping-form ``environment:`` block; this walks that
    block by indentation and stops at the next sibling key.
    """
    path = os.path.join(_REPO_ROOT, compose_filename)
    with open(path, encoding='utf-8') as fh:
        lines = fh.readlines()

    keys = set()
    in_backend = False
    in_env = False
    env_indent = None
    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            continue
        indent = len(raw) - len(raw.lstrip(' '))
        if indent == 2 and stripped.endswith(':'):
            # A top-level service key (backend:, frontend:, redis:).
            in_backend = stripped == 'backend:'
            in_env = False
            continue
        if in_backend and indent == 4 and stripped.rstrip() == 'environment:':
            in_env = True
            env_indent = None
            continue
        if in_backend and indent == 4 and stripped.endswith(':'):
            # A different backend sub-key (build, expose, depends_on, ...).
            in_env = False
            continue
        if in_env:
            if env_indent is None:
                env_indent = indent
            if indent < env_indent:
                in_env = False
                continue
            match = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\s*:', stripped)
            if match:
                keys.add(match.group(1))
    return keys


def test_every_network_toggle_is_forwarded_in_compose():
    required = _required_deployment_keys()
    for compose_filename in _COMPOSE_FILES:
        forwarded = _backend_environment_keys(compose_filename)
        missing = required - forwarded
        assert not missing, (
            f"{compose_filename} does not forward {sorted(missing)} to the "
            "backend container, so those privacy/network flags are stuck at "
            "their defaults there. Add them under services.backend.environment."
        )


def test_enrichment_timeouts_are_forwarded_in_compose():
    for compose_filename in _COMPOSE_FILES:
        forwarded = _backend_environment_keys(compose_filename)
        missing = _EXTRA_FORWARDED - forwarded
        assert not missing, (
            f"{compose_filename} does not forward {sorted(missing)} to the "
            "backend container."
        )


def test_env_example_documents_network_toggles():
    """.env.example documents every operator-facing privacy/network flag."""
    required = _required_deployment_keys()
    path = os.path.join(_REPO_ROOT, '.env.example')
    with open(path, encoding='utf-8') as fh:
        documented = fh.read()
    missing = {flag for flag in required if flag not in documented}
    assert not missing, (
        f".env.example does not document {sorted(missing)} — add each with "
        "its default so operators can discover the toggle."
    )


def _render_yaml_env_keys():
    """Env var names declared under the backend service's ``envVars:`` block."""
    path = os.path.join(_REPO_ROOT, 'render.yaml')
    with open(path, encoding='utf-8') as fh:
        return set(re.findall(
            r'^\s*-\s*key:\s*([A-Za-z_][A-Za-z0-9_]*)',
            fh.read(),
            re.MULTILINE,
        ))


def test_every_network_toggle_is_declared_in_render_yaml():
    """Hosted deployments must preserve the operator's disclosure controls."""
    missing = _required_deployment_keys() - _render_yaml_env_keys()
    assert not missing, (
        f"render.yaml does not declare {sorted(missing)}, so a Render "
        "deployment cannot control those network/privacy features. Add them "
        "under services[].envVars."
    )


def test_enrichment_timeouts_are_declared_in_render_yaml():
    missing = _EXTRA_FORWARDED - _render_yaml_env_keys()
    assert not missing, (
        f"render.yaml does not declare {sorted(missing)}."
    )
