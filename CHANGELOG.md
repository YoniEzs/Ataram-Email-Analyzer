# Changelog

This project follows Semantic Versioning after the first stable release.

## [Unreleased]

Nothing yet.

## [0.1.0-rc1] - 2026-08-19

First public release candidate, published as an explicitly experimental
pre-release. Verdicts are advisory; see `DISCLAIMER.md`.

### Added

- Independent DKIM verification and explicit header-claim trust metadata.
- Hebrew/RTL interface, OpenAPI v1 routes, YARA and VirusTotal hash lookups.
- Redis-backed rate limits/cache, RDAP, resource limits and ZIP-bomb detection.
- Privacy, disclaimer, community, release and third-party documentation.
- Playwright, mypy, Ruff, dependency, secret, CodeQL, SBOM and image-scan gates.
- Structured `artifacts` block covering the analyst triage checklist: sender
  address, subject, recipients, date/time, sending server IP, reverse DNS and
  Reply-To, each labelled with the trust of its source.
- Reverse DNS with forward confirmation (FCrDNS) for the sending IP.
- Keyless IP enrichment: announcing ASN, BGP prefix, allocation country and
  registry via Team Cymru over DNS, plus network object and abuse contact via
  IP RDAP.
- Per-hop `Received` parsing, with Date-vs-chain skew and ordering checks.
- To/Cc split and BCC-delivery inference from `Delivered-To` and related
  headers; `.msg` files use `PidTagRecipientType`.
- Subject checks for bidi overrides, zero-width characters, mixed encoded-word
  charsets and reply prefixes with no thread headers.
- Optional advisory SPF re-evaluation (`ENABLE_SPF_ADVISORY`, off by default).
- Optional MX lookup for the sender domain (`ENABLE_MX_LOOKUP`).
- Artifacts card in the UI and a copy-for-ticket Markdown export.
- Desktop entry point (`ataram-analyzer` / `app.desktop`): one local process
  serving UI and API on 127.0.0.1 via waitress, browser auto-opens.
- pipx/PyPI packaging (`backend/pyproject.toml`) and a PyInstaller spec plus
  release workflow producing Windows/macOS/Linux zips with checksums.
- `docker-compose.release.yml` running the published GHCR images without a
  source checkout or build step.
- `samples/`: five synthetic emails with documented expected verdicts.
- Static landing page for the project website under `site/`.

### Changed

- Browser API destination now defaults to same-origin; no owner-operated server
  is selected implicitly.
- Low-risk verdict now says “No strong indicators detected” rather than
  “Appears legitimate.”
- MSG parsing uses MIT-licensed `python-oxmsg`.
- Production and development Python dependencies are separated.
- `metadata.version` in the analysis response now tracks `API_VERSION`; the two
  had drifted apart at 2.0 and 2.1 and are both 2.2.
- The external-lookup deadline allows for reverse DNS, whose worst case is
  several sequential round-trips rather than one.
- The theme bootstrap moved from an inline script to `js/theme-init.js`: the
  desktop build serves the UI through Flask, whose CSP forbids inline scripts.
  Inline style attributes are permitted only in the desktop build via the new
  `CSP_ALLOW_INLINE_STYLE` flag; server CSP is unchanged.

### Fixed

- The desktop app no longer crashes at startup when its folder sits near a
  filesystem root. `find_webui()` built the source-checkout candidate eagerly
  with `parents[2]`, raising `IndexError` before the bundled UI could be found
  — so extracting the Windows zip straight onto `D:\` or a USB stick killed
  the app. Windows, macOS and Linux binaries are now built and smoke-tested on
  every pull request that can affect them, rather than first at release time.

- A message whose only threat is a locally-verified critical attachment (a
  hidden executable, executable bytes under a document extension, or an
  executable inside an archive) now reaches at least "medium" instead of
  reading "no strong indicators detected": the attachment score cap rose from
  15 to 40 with critical worth 25, and zip-hidden executables count as
  executables for the new-domain escalation rule. Ports the fix from the
  previously unmerged PR #16 onto the current scoring code, together with its
  end-to-end real-email regression matrix.

- DNS answers are tri-state everywhere they can be scored: an authoritative
  "no records" answer ([]) is evidence, a resolver failure (None) is not. A
  DNS outage can no longer fabricate the scored no-MX flag or make a missing
  PTR record look confirmed; reverse-DNS outages surface as an `error`
  enrichment status instead of an observation.
- The sending-server IP now always matches the oldest public Received hop;
  previously a repeated IP in the chain could shift the origin (and all its
  enrichment) onto a middle relay.
- Enrichment statuses mirror the lookup batch's actual IP fallback, so a
  lookup that ran is never reported as skipped.
- A freemail Return-Path raises its own `freemail_return_path` flag instead
  of misreporting a Reply-To that may not exist.
- YARA rules resolve to the copy bundled inside the package for pip/pipx
  installs; previously scanning was silently disabled there because the
  config evaluates before any entry point can set environment variables.

### Security

- Docker deployments honour the enrichment toggles. `docker-compose.yml` and
  `docker-compose.release.yml` forwarded only the WHOIS/AbuseIPDB/VirusTotal
  flags, so `ENABLE_REVERSE_DNS=false` (and every other enrichment toggle) had
  no effect inside the container and the sending IP was still disclosed to
  Team Cymru and RDAP. A test now derives the required set from `config.py`,
  so a new flag cannot silently go unforwarded.
- Reflected header values are bounded before they are echoed back, so a
  single oversized header can no longer inflate the response far beyond the
  size of the uploaded message.
- The backend runtime image patches fixable base-image CVEs at build time,
  so a pinned base digest that predates a Debian security update does not
  ship known-vulnerable packages.
- Authentication-Results claims never affect scoring.
- Advisory SPF results never affect scoring and are kept out of the
  `authentication` block: both of their inputs come from forgeable headers.
- Artifact signals are scored only when an attacker cannot erase them by
  editing the file, and can only raise a score, never lower one. Reverse-DNS
  versus HELO mismatch is reported but unscored, since the HELO half is a
  header claim.
- Reverse DNS refuses non-public addresses, so an internal `Received` chain
  cannot disclose RFC1918 space to a resolver.
- Default upload limit reduced to 25 MB with parser and scanner sub-limits.
- Backend container uses a multi-stage non-root runtime image.
