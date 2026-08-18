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
- Extracts the analyst triage checklist as structured artifacts and enriches it
  with reverse DNS, ASN and registry data (see below).
- Checks suspicious URLs, IDN/homograph indicators and displayed-link mismatch.
- Inspects attachment names, magic bytes, hashes and ZIP metadata without
  extracting archives.
- Runs bounded YARA scans against message and attachment bytes.
- Optionally checks sender IPs with AbuseIPDB and attachment hashes with
  VirusTotal.
- Looks up SPF, DKIM and DMARC DNS records and domain-registration data via RDAP.
- Independently verifies DKIM when raw MIME bytes are available.
- Provides an English/Hebrew interface, JSON export, printable reports and a
  copy-for-ticket artifact block.

## Artifacts and enrichment

Every analysis returns an `artifacts` block covering the fields an analyst
records for a reported message:

| Artifact | Enrichment |
|---|---|
| Sender address | Display-name spoofing, punycode/homograph, freemail and disposable classification, optional MX |
| Subject line | Encoded-word charsets, bidi overrides, zero-width characters, reply prefix without thread headers |
| Recipients | To and Cc split out, plus BCC delivery inferred from `Delivered-To` and friends |
| Date + time | Normalised to UTC, compared against the `Received` chain for skew and backdating |
| Sending server IP | Announcing ASN, BGP prefix, allocation country and registry (Team Cymru), registry network object and abuse contact (RDAP) |
| Reverse DNS | PTR plus forward confirmation (FCrDNS), and comparison against the claimed HELO name |
| Reply-To | Mismatch against the sender's registered domain, freemail reply target |

All of it is free and keyless: Team Cymru answers over plain DNS, so ASN data
still resolves in deployments where outbound HTTPS is restricted, and a missing
RDAP answer is treated as normal rather than an error. Each source reports an
`enrichment_status` (`ok`, `disabled`, `skipped_no_public_ip`, `unavailable`,
`error`) so a blank field always says why it is blank.

### What gets scored

Every artifact and flag carries a `trust` value:

| `trust` | Meaning | Scored |
|---|---|---|
| `header_claim` | Read from the uploaded file; an attacker controls it | No |
| `computed` | A deterministic property *of* that claim — script mixing, bidi overrides, self-contradictory timestamps | Yes |
| `observed` | Re-derived from live DNS or RDAP at analysis time | Yes |

The rule is that a scored signal must be one an attacker cannot erase by
editing headers. So a failed FCrDNS check counts, because it is re-queried from
DNS; a homoglyph sender domain counts, because choosing that string is itself
the evidence. A mismatch between reverse DNS and the claimed HELO name is the
sharpest new indicator here and is deliberately **not** scored: the PTR half is
observed, but the HELO half is copied out of a forgeable `Received` header.
Artifact evidence is capped so header forensics cannot dominate a verdict, and
can only ever raise a score, never lower one.

Advisory SPF (`ENABLE_SPF_ADVISORY`, off by default) re-evaluates SPF against
the IP the `Received` chain claims and the `Return-Path` it claims. Both inputs
are attacker-controlled — forging a hop that names a legitimate provider
manufactures a `pass` — so the result is display-only, lives under
`artifacts.authentication_advisory` rather than `authentication`, and never
affects the risk score.

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

## Run it in 2 minutes

Pick whichever fits your machine — every option runs entirely locally:

**Desktop app (Windows / macOS / Linux)** — download the zip for your OS from
the [latest release](https://github.com/YoniEzs/Ataram-Email-Analyzer/releases/latest),
extract, run `AtaramEmailAnalyzer`. Your browser opens by itself. Binaries are
unsigned; verify downloads against the release's `SHA256SUMS.txt`.

**pipx** (Python 3.11+):

```bash
pipx install ataram-email-analyzer
ataram-analyzer
```

**Docker, from published images** — no build step:

```bash
curl -LO https://raw.githubusercontent.com/YoniEzs/Ataram-Email-Analyzer/main/docker-compose.release.yml
docker compose -f docker-compose.release.yml up
```

Then try the synthetic messages in [`samples/`](samples/) — each documents the
verdict it should produce.

The desktop and pipx builds bind to `127.0.0.1` only and serve the UI and API
from one process; the Docker stack is the hardened multi-container deployment
for teams.

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
| Reverse DNS | Header-derived public IP, as a PTR query |
| Team Cymru (`asn.cymru.com`) | Header-derived public IP, encoded in the DNS query name |
| RDAP servers (IP) | Header-derived public IP |

The header-derived IP is often your own infrastructure rather than a suspected
sender's. See [PRIVACY.md](PRIVACY.md) before enabling these in an environment
where your mail topology is sensitive.

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
