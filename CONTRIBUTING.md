# Contributing

Thank you for improving Ataram Email Analyzer.

## Before opening an issue

- Use synthetic or sanitized samples only.
- Never attach a real credential, API key, victim email or customer data.
- Report vulnerabilities with a private security advisory, not a public issue.
- State the version, operating system, deployment method and minimal steps to
  reproduce.

## Pull requests

1. Create a focused branch from current `main`.
2. Add or update tests for behavior changes.
3. Update the trust/privacy documentation when data flow changes.
4. Run the checks in `RELEASE_CHECKLIST.md`.
5. Open a draft PR and complete the template.

Backend code targets Python 3.11+, uses type hints and is checked by Ruff and
mypy. Frontend code is dependency-light vanilla JavaScript and must keep the
DOM contract and Playwright smoke test green.

Do not weaken resource limits, SSRF checks, escaping, container isolation or
authentication trust boundaries without a documented threat-model change.

By contributing, you agree that your project-authored contribution is licensed
under the MIT License and that you have the right to submit it. Do not copy code
under an incompatible license.
