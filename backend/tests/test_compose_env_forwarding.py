"""Guard: every ENABLE_* toggle the code reads is forwarded into Docker.

The backend reads its feature flags from ``os.environ``. Inside a container
those variables only exist if the compose file forwards them under the
backend service's ``environment:`` block. A flag the code reads but the
compose file omits is silently stuck at its default — e.g. setting
``ENABLE_REVERSE_DNS=false`` in ``.env`` would fail to stop the sending IP
from being disclosed to third parties. This test fails if that ever regresses.
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

# Timeouts that only matter once the enrichment lookups above run; forwarded
# alongside the ENABLE_* flags so operators can tune them in Docker too.
_EXTRA_FORWARDED = frozenset(
    {'DNS_TIMEOUT', 'WHOIS_TIMEOUT', 'HTTP_TIMEOUT', 'SPF_TIMEOUT'}
)


def _enable_flags_read_by_code():
    """Every ENABLE_* env var config.py pulls from the environment."""
    with open(_CONFIG_PY, encoding='utf-8') as fh:
        source = fh.read()
    flags = set(re.findall(r"os\.environ\.get\(\s*['\"](ENABLE_[A-Z_]+)['\"]", source))
    assert flags, "no ENABLE_* flags found in config.py — regex out of date?"
    return flags


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


def test_every_enable_flag_is_forwarded_in_compose():
    required = _enable_flags_read_by_code()
    for compose_filename in _COMPOSE_FILES:
        forwarded = _backend_environment_keys(compose_filename)
        missing = required - forwarded
        assert not missing, (
            f"{compose_filename} does not forward {sorted(missing)} to the "
            "backend container, so those flags are stuck at their defaults "
            "there. Add them under services.backend.environment."
        )


def test_enrichment_timeouts_are_forwarded_in_compose():
    for compose_filename in _COMPOSE_FILES:
        forwarded = _backend_environment_keys(compose_filename)
        missing = _EXTRA_FORWARDED - forwarded
        assert not missing, (
            f"{compose_filename} does not forward {sorted(missing)} to the "
            "backend container."
        )


def test_env_example_documents_forwarded_flags():
    """.env.example should document each ENABLE_* flag the code reads."""
    required = _enable_flags_read_by_code()
    path = os.path.join(_REPO_ROOT, '.env.example')
    with open(path, encoding='utf-8') as fh:
        documented = fh.read()
    missing = {flag for flag in required if flag not in documented}
    assert not missing, (
        f".env.example does not document {sorted(missing)} — add each with "
        "its default so operators can discover the toggle."
    )
