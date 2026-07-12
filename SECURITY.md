# Security Policy

## Reporting a vulnerability

Use a [private GitHub security advisory](https://github.com/YoniEzs/Ataram-Email-Analyzer/security/advisories/new).
Do not include a real victim email, credential, API key or personal data in a
public issue. A sanitized proof of concept is preferred.

We aim to acknowledge reports within 72 hours. Response and remediation times
depend on severity and maintainer availability; this is a best-effort
open-source project, not a commercial SLA.

## Supported versions

Only the newest tagged pre-release/release and the current `main` branch receive
security fixes. No stable version has been published yet.

## In scope

- EML/MSG parsing and resource exhaustion
- SSRF and unsafe outbound requests
- XSS or report injection
- API-key disclosure
- authentication-result trust and misleading verdicts
- container and CI/CD configuration
- dependency or build-chain compromise

## Security model

- Uploaded files are hostile input and are subject to size, part, attachment,
  archive and scan limits.
- `Authentication-Results`, `Received` and `Return-Path` in an uploaded file are
  attacker-controllable. Header claims do not affect scoring.
- DKIM is independently verified when enabled. SPF and full DMARC cannot be
  recreated from an uploaded file alone.
- Domains and public IPs are syntactically validated before lookups. RDAP
  redirects are restricted to public HTTPS targets.
- The API has no built-in user authentication. Rate limiting and CORS do not
  replace authentication or a WAF.
- The application does not intentionally persist messages, but infrastructure
  may buffer or log requests. See `PRIVACY.md`.

## Safe testing

Use synthetic or fully sanitized samples. Do not test a public deployment with
malware, third-party data or high request volume without explicit authorization.
