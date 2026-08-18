# Backend

Flask API for bounded EML/MSG parsing and heuristic email analysis.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
cp .env.example .env
python run.py
```

Production installs use `requirements-prod.txt`. Development/test tools are in
`requirements-dev.txt`; `requirements.txt` remains a compatibility wrapper.

## Checks

```bash
ruff check --no-cache app tests
mypy
pytest -q --cov=app --cov-report=term --cov-fail-under=65
pip-audit -r requirements-prod.txt
```

## Design notes

- `python-oxmsg` parses MSG files under an MIT license.
- Raw EML bytes are retained only in request memory for DKIM verification.
- SPF/DMARC header values are display-only and untrusted, including the
  advisory SPF re-evaluation behind `ENABLE_SPF_ADVISORY`.
- RDAP, DNS, AbuseIPDB, VirusTotal, reverse DNS and Team Cymru are bounded
  outbound lookups; the four IP-based ones disclose an address taken from
  `Received`, which is often your own infrastructure.
- Artifact flags are scored only when `trust` is `observed` or `computed`;
  `header_claim` flags are reported and never scored.
- `REDIS_URL` shares lookup caches; `RATELIMIT_STORAGE_URI` shares limits.
- See `.env.example`, `../PRIVACY.md` and `../SECURITY.md`.
