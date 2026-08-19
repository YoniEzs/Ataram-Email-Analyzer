# Changelog

This project follows Semantic Versioning after the first stable release.

## [Unreleased]

### Added

- `docs/QA-GUIDE.md`: a numbered manual test script covering the paths
  automation cannot reach — real Outlook `.msg` files, the browser upload
  path, real API keys, resource limits and the offline mode.
- `tests/test_samples_regression.py`: the verdicts published in
  `samples/README.md` are now enforced. They previously existed only as prose
  and could drift from the scorer with nothing failing.
- Direct tests for `app/services/ip_reputation.py`, which was mocked out of
  every existing test (29% → 91% coverage): request construction, key
  handling, response mapping, caching and failure degradation.
- Guard tests asserting `render.yaml` declares every `ENABLE_*` flag and
  timeout the code reads, matching the existing compose guards.

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

- A failure inside artifact enrichment left `checklist` and `flags` holding
  their pre-enrichment values, so a partially-merged block was summarised by
  stale derived views and returned as a confident verdict with only a log line
  to say otherwise. Both are now always rebuilt, each guarded so a rebuild
  failure cannot take down the analysis, and the failure is recorded as
  `enrichment_status.merge = 'error'` instead of passing silently.
- `render.yaml` declared none of `ENABLE_REVERSE_DNS`, `ENABLE_IP_RDAP`,
  `ENABLE_ASN_LOOKUP`, `ENABLE_MX_LOOKUP` or `ENABLE_SPF_ADVISORY`. The first
  three default to true, so a Render deployment disclosed the header-derived
  sending IP to Team Cymru and rdap.org with no way for the operator to turn
  it off — the no-disclosure mode `PRIVACY.md` documents was unreachable there.
- `npm run check` globbed `src/js/*.js` only, missing `src/runtime-config.js`
  — the one file users are instructed to hand-edit. A syntax error there
  passed CI and white-screened the app.
- The coverage floor existed only as a `--cov-fail-under` flag repeated in five
  places, so a bare `pytest` ran with no gate. It is now declared in
  `pyproject.toml` and raised from 65 to 80 against measured coverage of 87.
- `frontend-ci.yml` pinned `pytest==9.0.3` while `requirements-dev.txt` pinned
  `9.1.1`.

### Documentation

- The README advertised four ways to run the tool; three of them — the desktop
  zip, `pipx install ataram-email-analyzer` and the published-image compose
  file — cannot work, because no version has been tagged and no PyPI publish
  workflow exists. They are now marked as not yet available rather than
  presented as working instructions.
- Documented `python -m app.desktop`, which serves the UI and API from one
  process in a source checkout. It was the fastest way to run the tool and
  appeared in no document.
- `backend/README.md` sent readers to `python run.py` without saying it serves
  no UI, and neither README mentioned that a virtual environment is required
  because `pyspf` fails to build against some system setuptools.

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

## [0.1.0-rc1] - Unreleased

First public release candidate; publish only after `RELEASE_CHECKLIST.md` passes.
