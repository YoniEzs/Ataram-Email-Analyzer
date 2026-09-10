# ITgalya Email Analyzer — Production Hardening

This document tracks the remaining work between the public release candidate and a production-stable release.

## Release status

Current target: `v0.1.0-rc1` (Public Beta)

## Automated gates

- [x] Python lint, type checking, tests, and coverage gate.
- [x] Frontend static/DOM checks.
- [x] Backend and frontend Docker smoke tests.
- [x] Windows, Linux, and macOS desktop package builds.
- [x] Packaged desktop smoke test calls `/health`, loads the bundled UI, and performs an EML analysis.
- [x] Release archives include SHA-256 checksums.
- [ ] Desktop release archives have GitHub build provenance attestations.
- [ ] Release workflow uses least-privilege permissions per job.

## Manual gates before stable

- [ ] Run the Windows x64 packaged build on a normal Windows workstation outside CI.
- [ ] Analyze a genuine Outlook-generated `.msg` file.
- [ ] Analyze a genuine Outlook-generated `.msg` file containing at least one attachment.
- [ ] Exercise Hebrew RTL, JSON export, print/report flow, history, and clipboard functions in the packaged build.
- [ ] Confirm offline mode performs no enrichment network requests.
- [ ] Exercise optional reputation integrations with: no keys, AbuseIPDB only, VirusTotal only, both, and invalid keys.
- [ ] Review a representative set of legitimate mail for false positives and phishing mail for false negatives.

## Signing and distribution

The RC may be distributed unsigned with a prominent warning and published checksums. Stable release should not be labelled production-ready until platform signing is addressed:

- [ ] Windows Authenticode signing certificate and signing step.
- [ ] Apple Developer ID signing and notarization for macOS.
- [ ] Verify signed/notarized artifacts after download from the public release page.

## Stable release acceptance

`v0.1.0` may be marked Stable when all applicable automated gates are green on the exact release commit, the manual gates above have been recorded, signing policy is satisfied, and no unresolved P0/P1 defect remains.
