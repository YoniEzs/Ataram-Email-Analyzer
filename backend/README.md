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
- SPF/DMARC header values are display-only and untrusted.
- RDAP, DNS, AbuseIPDB and VirusTotal are bounded outbound lookups.
- `REDIS_URL` shares lookup caches; `RATELIMIT_STORAGE_URI` shares limits.
- See `.env.example`, `../PRIVACY.md` and `../SECURITY.md`.
