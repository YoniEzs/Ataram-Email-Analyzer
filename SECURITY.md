# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Ataram Email Analyzer, please report it responsibly:

- **Email**: support@ataram.uk
- **GitHub**: Open a [private security advisory](https://github.com/YoniEzs/Ataram-Email-Analyzer/security/advisories/new)

Please do **not** open a public issue for security vulnerabilities.

We aim to acknowledge reports within 72 hours and to release a fix as soon as practical.

## Scope

Reports are welcome for anything in this repository, including:

- The Flask backend API (file parsing, input validation, SSRF, injection)
- The web frontend (XSS, content injection)
- CI/CD and deployment configuration

## Supported Versions

Only the latest version on the `main` branch is supported with security fixes.

## Design Notes for Researchers

- Uploaded emails are analyzed in memory and never stored permanently.
- Domains and IPs extracted from emails are validated against SSRF
  (private/reserved ranges and internal TLDs are rejected) before any
  outbound DNS/WHOIS/reputation lookups.
- API keys (e.g. AbuseIPDB) are accepted per-request or via server
  environment and are never logged or returned in responses.
