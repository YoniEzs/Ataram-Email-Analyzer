# Changelog

This project follows Semantic Versioning after the first stable release.

## [Unreleased]

### Added

- Independent DKIM verification and explicit header-claim trust metadata.
- Hebrew/RTL interface, OpenAPI v1 routes, YARA and VirusTotal hash lookups.
- Redis-backed rate limits/cache, RDAP, resource limits and ZIP-bomb detection.
- Privacy, disclaimer, community, release and third-party documentation.
- Playwright, mypy, Ruff, dependency, secret, CodeQL, SBOM and image-scan gates.

### Changed

- Browser API destination now defaults to same-origin; no owner-operated server
  is selected implicitly.
- Low-risk verdict now says “No strong indicators detected” rather than
  “Appears legitimate.”
- MSG parsing uses MIT-licensed `python-oxmsg`.
- Production and development Python dependencies are separated.

### Security

- Authentication-Results claims never affect scoring.
- Default upload limit reduced to 25 MB with parser and scanner sub-limits.
- Backend container uses a multi-stage non-root runtime image.

## [0.1.0-rc1] - Unreleased

First public release candidate; publish only after `RELEASE_CHECKLIST.md` passes.
