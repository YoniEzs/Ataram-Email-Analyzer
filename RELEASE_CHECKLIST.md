# Public Release Checklist

Do not make the repository public merely because the code builds. Complete the
items below for the exact candidate commit.

## 1. Source and legal

- [x] Project-authored code has an MIT license.
- [x] Runtime dependencies are indexed in `THIRD_PARTY_NOTICES.md`.
- [x] GPL `extract-msg` dependency replaced with MIT `python-oxmsg`.
- [ ] Dependency-license report reviewed for all transitive packages.
- [ ] Branding, domain and maintainer contact details approved.
- [ ] Real email samples and personal/internal documents absent from every Git
  ref and workflow artifact.

## 2. Security and privacy

- [x] No hard-coded production API endpoint or API key.
- [x] Privacy/data-flow document matches code and deployment defaults.
- [x] Header authentication claims cannot affect scoring.
- [x] Hostile-input resource limits have regression tests.
- [x] Containers run the backend as non-root and omit tests/env files.
- [ ] Gitleaks full-history workflow passes.
- [ ] CodeQL and dependency review pass after the repository is public (or with
  private-repository code scanning enabled).
- [ ] Hosting proxy/body buffering and log retention are documented by the
  operator.

## 3. Required validation

```bash
cd backend
python -m pip install -r requirements-dev.txt
ruff check --no-cache app tests
mypy
pytest -q --cov=app --cov-report=term --cov-fail-under=65
pip-audit -r requirements-prod.txt

cd ../frontend
npm ci
npm run check
npx playwright install chromium
npm run test:e2e

cd ..
docker compose config
docker compose up --build -d
curl -fsS http://localhost:3000/health
```

- [ ] Commands pass from a clean clone on Linux.
- [ ] Docker flow passes on Windows Docker Desktop.
- [ ] Backend/frontend images pass Trivy HIGH/CRITICAL-fixable scans.
- [ ] SBOMs are generated and attached to the candidate release.
- [ ] Images are signed and signatures are verified.

## 4. Functional matrix

- [ ] EML: plain text, HTML only, multipart, long headers and malformed MIME.
- [ ] MSG: body, HTML fallback, recipients and attachments.
- [ ] No optional API keys.
- [ ] AbuseIPDB only.
- [ ] VirusTotal hash lookup only.
- [ ] RDAP/DNS disabled for offline mode.
- [ ] Hebrew/RTL, JSON export and print/PDF.
- [ ] 25 MB rejection and MIME/attachment/ZIP limit failures are friendly.
- [ ] Access from another computer through the intended hostname, not localhost.

## 5. Repository settings

- [ ] Require pull requests to `main`.
- [ ] Require Backend CI, Frontend CI, Repository Quality and Security checks.
- [ ] Require branches to be current before merge.
- [ ] Block force-push and branch deletion on `main`.
- [ ] Enable Dependabot alerts/updates, secret scanning and push protection.
- [ ] Enable private vulnerability reporting.
- [ ] Archive or keep private obsolete split frontend/backend repositories.

## 6. Candidate and publication

- [ ] Merge by squash after all exact-SHA checks pass.
- [ ] Tag `v0.1.0-rc1` and publish an explicitly experimental pre-release.
- [ ] Complete at least seven days of soak testing without an unresolved P0/P1.
- [ ] Change visibility to public only after the earlier sections are complete.
- [ ] Re-run secret scanning and CodeQL after visibility changes.
- [ ] Tag `v0.1.0` only after the public candidate remains healthy.
