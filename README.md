# ITgalya Email Analyzer

Local-first phishing and malicious-email triage for `.eml` and Outlook `.msg` files.

> **Release status: v0.1.0-rc1 / Public Beta.** Analysis results are advisory. A low score means the configured checks found no strong indicators; it does not prove a message is legitimate or safe.

## What it does

ITgalya Email Analyzer turns a suspicious email file into a structured SOC/DFIR triage view without executing links or attachments.

- Parses EML and Outlook MSG files.
- Extracts sender, subject, recipients, timestamps, sending infrastructure, reverse DNS and Reply-To artifacts.
- Separates forgeable header claims from independently computed or observed evidence.
- Detects suspicious URLs, IDN/homograph domains and displayed-link mismatches.
- Inspects attachment names, magic bytes, hashes and ZIP metadata without detonating or extracting files to disk.
- Runs bounded YARA scans against message and attachment bytes.
- Independently verifies DKIM when raw MIME bytes are available.
- Performs DNS, reverse-DNS, FCrDNS, ASN/BGP and RDAP enrichment.
- Optionally checks sender IPs with AbuseIPDB and attachment hashes with VirusTotal when explicitly enabled.
- Provides English and Hebrew UI, JSON export, printable reports and copy-for-ticket artifacts.

## Local-first safety model

The desktop build binds only to `127.0.0.1`. The selected email is analyzed on the workstation running the tool.

The analyzer does not intentionally visit URLs found in the message and does not execute attachments. Optional enrichment can still disclose limited indicators such as domains, public IP addresses or attachment hashes to the documented DNS/RDAP/reputation services. Read `PRIVACY.md` before analyzing sensitive mail.

### Strict offline mode

Set `ITGALYA_OFFLINE_MODE=true` before launching the analyzer when the message must be inspected without external enrichment requests. Offline mode is a master privacy switch: DNS/SPF/DMARC/DKIM lookups, reverse DNS, WHOIS/RDAP/ASN, AbuseIPDB, VirusTotal, MX and SPF advisory lookups are disabled even if an individual feature flag is enabled.

Windows PowerShell:

```powershell
$env:ITGALYA_OFFLINE_MODE = "true"
.\ITgalyaEmailAnalyzer.exe
```

Linux/macOS:

```bash
ITGALYA_OFFLINE_MODE=true ./ITgalyaEmailAnalyzer
```

`OFFLINE_MODE=true` remains accepted as a generic compatibility alias.

## Download

Public release assets are published on the GitHub Releases page and linked from the official ITgalya Tools page:

- Product page: https://tools.itgalya.com/tools/email-analyzer/
- Releases: https://github.com/YoniEzs/Ataram-Email-Analyzer/releases

The RC1 desktop binaries are unsigned. Windows SmartScreen or macOS Gatekeeper may therefore display a first-run warning. Verify the downloaded archive against `SHA256SUMS.txt` from the same release.

Tagged desktop releases also publish GitHub build provenance attestations for the release ZIP archives. With GitHub CLI installed, a downloaded archive can be verified against this repository with:

```bash
gh attestation verify ITgalyaEmailAnalyzer-v0.1.0-rc1-windows-x64.zip --repo YoniEzs/Ataram-Email-Analyzer
```

A successful attestation verifies how the artifact was produced by GitHub Actions; it is complementary to, not a replacement for, platform code signing.

### Windows x64

Download `ITgalyaEmailAnalyzer-v0.1.0-rc1-windows-x64.zip`, extract the complete folder and run:

```text
ITgalyaEmailAnalyzer.exe
```

A browser tab opens on the local analyzer URL.

### Linux x64

```bash
./ITgalyaEmailAnalyzer/ITgalyaEmailAnalyzer
```

### macOS Apple Silicon

Download the ARM64 archive, extract it and run the bundled `ITgalyaEmailAnalyzer` binary. RC1 is not notarized, so first-run approval may be required in macOS Privacy & Security settings.

## Source checkout

Use Python 3.11, 3.12 or 3.13 on Windows. Python 3.14 is not currently supported by the pinned `yara-python` Windows dependency.

```powershell
git clone https://github.com/YoniEzs/Ataram-Email-Analyzer.git
cd Ataram-Email-Analyzer\backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-prod.txt waitress
.\.venv\Scripts\python.exe -m app.desktop
```

The desktop launcher supports the public environment names `ITGALYA_PORT` and `ITGALYA_NO_BROWSER`. Legacy `ATARAM_PORT` and `ATARAM_NO_BROWSER` remain accepted during RC1 for backward compatibility.

## Docker

For controlled/self-hosted environments:

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:3000`.

Internet-facing API deployments require their own authentication/access-control layer, reverse-proxy policy and rate limiting. CORS is not access control.

## Resource limits

Default hostile-input limits include:

| Limit | Default |
|---|---:|
| Upload | 25 MB |
| MIME parts | 250 |
| Attachments | 100 |
| One attachment | 10 MB |
| Total attachment bytes | 20 MB |
| URLs analyzed | 500 |
| Bytes passed to each YARA scan | 8 MB |
| ZIP members inspected | 100 |
| ZIP declared uncompressed bytes | 200 MB |
| ZIP compression-ratio threshold | 100:1 |

Raising these limits increases denial-of-service risk.

## Authentication trust model

An uploaded email is not a trusted SMTP transaction. Headers such as `Authentication-Results`, `Received` and `Return-Path` can be forged.

- SPF/DKIM/DMARC values copied from headers are treated as untrusted claims and do not directly establish authenticity.
- DKIM signatures can be independently verified against DNS and may affect analysis.
- SPF cannot be reliably reconstructed without trusted SMTP peer and envelope context.
- DNS record presence is informational; it does not prove a specific message passed authentication.

## Development

Backend:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
pytest -q
ruff check app tests
mypy
```

Frontend:

```bash
cd frontend
npm ci
npm run check
npx playwright install chromium
npm run test:e2e
```

Desktop builds are produced and smoke-tested on Windows x64, macOS ARM64 and Linux x64 through GitHub Actions. The smoke test starts the packaged binary, checks the health endpoint and UI, and performs a real analysis against a synthetic phishing sample.

## Security and privacy

- Privacy model: `PRIVACY.md`
- Security reporting: `SECURITY.md`
- Disclaimer: `DISCLAIMER.md`
- Third-party notices: `THIRD_PARTY_NOTICES.md`
- Manual QA: `docs/QA-GUIDE.md`
- Production hardening gates: `PRODUCTION_HARDENING.md`

## License

MIT. See `LICENSE`.
