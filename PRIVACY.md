# Privacy and Data Flow

Last updated: 2026-07-12

Ataram Email Analyzer processes potentially sensitive email evidence. This
document describes the software's intended behavior; it cannot control logging,
buffering or retention performed by your hosting provider, reverse proxy,
browser, DNS resolver or operating system.

## Upload path

The browser sends the entire selected EML or MSG file to the analysis server
shown next to **Analysis server** in the interface. The default is same-origin.
There is no hard-coded public backend fallback.

If entered, an AbuseIPDB API key is included in the multipart request. The input
uses password masking and is cleared after the request finishes. Masking and
clearing do not prevent the configured server from receiving the key.

## Intentional server-side storage

The application has no message database and does not intentionally write
message bodies or attachments to disk. It processes uploads in memory. The
application logger intentionally omits filenames, message content and API keys.

This is not a promise of zero temporary storage. For example, a reverse proxy,
container runtime, crash dump, swap subsystem or hosting platform may buffer a
request or retain operational logs. Operators are responsible for configuring
those systems and publishing their own retention policy.

The response includes the original sanitized filename. The browser stores up to
ten summary entries in `localStorage`: filename, timestamp, risk score, risk
level and verdict. Use **Clear** or clear site data to remove them. Full email
content and attachments are not placed in analysis history.

## Outbound requests

| Component | Data disclosed | Enabled by default |
|---|---|---:|
| DNS resolver | Domains, selectors and record names for SPF/DKIM/DMARC | Yes |
| RDAP | Sender domain | Yes (`ENABLE_WHOIS`) |
| AbuseIPDB | Public IP extracted from untrusted headers and API key | Only when a key is present |
| VirusTotal | Attachment SHA-256 hash and API key; never attachment bytes | No |

The bundled YARA rules, keyword analysis, attachment inspection and Public
Suffix List parsing run locally in the backend process.

## Offline or sensitive analysis

For the smallest outbound footprint:

```dotenv
ENABLE_WHOIS=false
ENABLE_ABUSEIPDB=false
ENABLE_VIRUSTOTAL=false
ENABLE_AUTH_VERIFICATION=false
```

Independent DKIM verification also performs DNS lookups, so disable it for a
strictly offline environment. Use a locally controlled DNS resolver and deploy
the frontend/backend on infrastructure whose proxy, swap, logging and backup
policies you control.

## API keys

Prefer server-side environment variables over per-request browser entry for
shared deployments. Keys are used only for the corresponding provider request
and are not returned in JSON responses. Do not assume that access logs,
observability agents or a compromised server cannot capture them.

## Operator responsibilities

Operators should:

- publish their server URL, subprocessors, region and retention policy;
- use TLS for any non-local connection;
- restrict CORS origins, while recognizing that CORS is not authentication;
- add authentication/WAF controls before exposing the API publicly;
- configure request-body logging and proxy buffering appropriately;
- comply with applicable privacy, employment and evidence-handling law.
