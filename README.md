# Ataram Email Analyzer

Experimental, self-hostable analysis of `.eml` and `.msg` files for phishing
and malicious-email indicators.

[![Backend CI](https://github.com/YoniEzs/Ataram-Email-Analyzer/actions/workflows/backend-ci.yml/badge.svg)](https://github.com/YoniEzs/Ataram-Email-Analyzer/actions/workflows/backend-ci.yml)
[![Frontend CI](https://github.com/YoniEzs/Ataram-Email-Analyzer/actions/workflows/frontend-ci.yml/badge.svg)](https://github.com/YoniEzs/Ataram-Email-Analyzer/actions/workflows/frontend-ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> Release status: **pre-release / experimental**. A low score means that the
> configured checks found no strong indicators. It does not prove that a
> message is legitimate or safe.

## What it does

- Parses EML and Outlook MSG files.
- Checks suspicious URLs, IDN/homograph indicators and displayed-link mismatch.
- Inspects attachment names, magic bytes, hashes and ZIP metadata without
  extracting archives.
- Runs bounded YARA scans against message and attachment bytes.
- Optionally checks sender IPs with AbuseIPDB and attachment hashes with
  VirusTotal.
- Looks up SPF, DKIM and DMARC DNS records and domain-registration data via RDAP.
- Independently verifies DKIM when raw MIME bytes are available.
- Provides an English/Hebrew interface, JSON export and printable reports.

## Authentication trust model

An uploaded email is not a trusted SMTP transaction. Every header in the file,
including the topmost `Authentication-Results`, `Received` and `Return-Path`,
can be fabricated.

- SPF/DKIM/DMARC values copied from `Authentication-Results` are shown as
  **untrusted header claims** and never affect the risk score.
- DKIM signatures are verified independently against DNS and may affect the
  score.
- SPF cannot be reconstructed reliably without the peer IP and SMTP MAIL FROM
  captured by a trusted receiving MTA.
- A complete DMARC verdict also needs trusted SPF context and the domain's
  alignment policy. The analyzer reports relaxed DKIM alignment separately.
- DNS record presence is informational; it is not proof that a particular
  message passed authentication.

## Quick start with Docker

Requirements: Docker Engine with Compose v2.

```bash
git clone https://github.com/YoniEzs/Ataram-Email-Analyzer.git
cd Ataram-Email-Analyzer
cp .env.example .env
docker compose up --build
```

Open `http://localhost:3000`. The browser uses same-origin `/api` requests;
nginx proxies them to the backend. Redis is included for shared rate limits and
lookup caches. The backend is not published directly to the host.

Optional API keys can be placed in `.env` or entered per request in the UI:

```dotenv
ABUSEIPDB_KEY=
VIRUSTOTAL_API_KEY=
ENABLE_VIRUSTOTAL=false
```

Before uploading sensitive material, read [PRIVACY.md](PRIVACY.md) and
[DISCLAIMER.md](DISCLAIMER.md).

## Development

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
python -m pip install -r requirements-dev.txt
pytest -q --cov=app --cov-fail-under=65
ruff check app tests
mypy
```

Frontend:

```bash
cd frontend
npm ci
npm run check
npx playwright install chromium
python -m http.server 8765 --directory src
# In another shell:
SMOKE_BASE_URL=http://localhost:8765 npm run test:e2e
```

For a frontend hosted separately from the backend, copy and edit
`frontend/src/runtime-config.js`:

```javascript
window.ATARAM_CONFIG = { API_BASE_URL: 'https://api.example.com' };
```

There is deliberately no fallback to an Ataram/Render server. An empty runtime
configuration always means same-origin.

## Resource limits

Defaults are designed for public-facing hostile input:

| Limit | Default |
|---|---:|
| Upload | 25 MB |
| MIME parts | 250 |
| Attachments | 100 |
| One attachment | 10 MB |
| Total attachment bytes | 20 MB |
| Text processed | 2,000,000 characters per body representation |
| URLs analyzed | 500, with 4,096 characters retained per URL |
| Bytes passed to each YARA scan | 8 MB |
| ZIP members inspected | 100 |
| ZIP declared uncompressed bytes | 200 MB |
| ZIP compression-ratio threshold | 100:1 |

All limits can be changed with the variables documented in
`backend/.env.example`. Raising them increases denial-of-service risk.

## External data flow

The backend does not intentionally persist uploaded messages in a database or
file. Hosting platforms, reverse proxies and operating systems can still buffer
requests temporarily. Optional lookups disclose limited indicators:

| Service | Data sent |
|---|---|
| DNS resolver | Sender/signing domains and selectors |
| RDAP servers | Sender domain |
| AbuseIPDB | Header-derived public IP and the configured API key |
| VirusTotal | SHA-256 attachment hashes and the configured API key; not attachment bytes |

See [PRIVACY.md](PRIVACY.md) for the full model and instructions for an offline
deployment.

## API

The versioned base path is `/api/v1`; `/api/*` remains a compatibility alias.
OpenAPI 3.0 is served at `/api/openapi.json` and `/api/v1/openapi.json`.

Primary endpoint:

```text
POST /api/v1/analyze
Content-Type: multipart/form-data
emailfile: required .eml or .msg
abuseipdb_key: optional
virustotal_key: optional
```

The API is unauthenticated by default. CORS is only a browser policy and is not
access control. Put internet-facing deployments behind an authentication layer
or WAF, use Redis-backed rate limiting, and restrict allowed origins.

## Deployment

- Docker Compose: same-origin frontend/backend and Redis, suitable for local or
  controlled self-hosting.
- Render: `render.yaml` provisions a web service and private Key Value instance;
  `autoDeployTrigger: checksPass` waits for CI.
- Separate static frontend: set `runtime-config.js` explicitly and configure
  backend `CORS_ORIGINS`.

See [CLOUDFLARE_RENDER_DEPLOYMENT.md](CLOUDFLARE_RENDER_DEPLOYMENT.md).

## Security and releases

- Vulnerabilities: [SECURITY.md](SECURITY.md)
- Contribution process: [CONTRIBUTING.md](CONTRIBUTING.md)
- Release gates: [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)
- Current roadmap: [ROADMAP.md](ROADMAP.md)
- Third-party dependencies: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

## License

Project-authored code is available under the [MIT License](LICENSE). Dependencies
keep their own licenses; review `THIRD_PARTY_NOTICES.md` before redistribution.
