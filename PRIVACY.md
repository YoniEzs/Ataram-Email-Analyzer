# Privacy and Data Flow

Last updated: 2026-08-18

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
| Reverse DNS | Sending IP, as a PTR query, plus the resulting host name | Yes (`ENABLE_REVERSE_DNS`) |
| Team Cymru | Sending IP, encoded in the DNS query name | Yes (`ENABLE_ASN_LOOKUP`) |
| RDAP (IP) | Sending IP | Yes (`ENABLE_IP_RDAP`) |
| MX lookup | Sender domain | No (`ENABLE_MX_LOOKUP`) |
| Advisory SPF | Sender domain and the SPF records it references | No (`ENABLE_SPF_ADVISORY`) |

The bundled YARA rules, keyword analysis, attachment inspection, freemail and
disposable-domain lists, and Public Suffix List parsing all run locally in the
backend process.

### The sending IP is not always the attacker's

The four IP-based lookups above disclose an address taken from the message's
`Received` headers. That address is frequently **your own** infrastructure: an
internally forwarded message, an on-premises relay, a mail gateway or a VPN
egress. Enabling these lookups therefore publishes internal infrastructure
addresses to third-party DNS and RDAP operators, not only the addresses of
suspected senders. Private and reserved ranges are never queried, but a
publicly routable address belonging to your organization will be.

Weigh this against the analytical value before enabling them in an environment
where the shape of your mail infrastructure is itself sensitive.

### Exported artifacts

The artifacts block and its "Copy Artifacts" export include the envelope
recipients recovered from `Delivered-To` and related headers, which is how a
Bcc delivery is inferred. That is the analyst's own mailbox address, and it
travels with the exported text into whatever ticketing system it is pasted
into. Review the block before sharing it outside your team.

## Offline or sensitive analysis

For the smallest outbound footprint:

```dotenv
ENABLE_WHOIS=false
ENABLE_ABUSEIPDB=false
ENABLE_VIRUSTOTAL=false
ENABLE_AUTH_VERIFICATION=false
ENABLE_REVERSE_DNS=false
ENABLE_IP_RDAP=false
ENABLE_ASN_LOOKUP=false
ENABLE_MX_LOOKUP=false
ENABLE_SPF_ADVISORY=false
```

With those disabled the artifacts block is still produced in full; only its
`enrichment` fields are empty, each carrying an `enrichment_status` of
`disabled` so the report says why rather than looking like a failed lookup.

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
