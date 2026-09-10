# v0.1.0-rc1 Release Procedure

This is the final operator sequence for the first public ITgalya Email Analyzer release candidate.

## Before tagging

1. Merge the production-hardening PR only after required CI and all three desktop package smoke builds are green.
2. Run the Windows candidate on a normal Windows workstation and analyze at least one EML file.
3. If available, analyze a genuine Outlook-generated MSG file and record the result in `PRODUCTION_HARDENING.md`.

## Tag

Tag the exact green `main` commit:

```bash
git checkout main
git pull --ff-only
git tag -a v0.1.0-rc1 -m "ITgalya Email Analyzer v0.1.0-rc1"
git push origin v0.1.0-rc1
```

Do not move or recreate a published release tag. If a release-blocking defect is found after tagging, fix it on `main` and cut the next RC instead.

## Automated release expectations

The tag must produce all of the following:

- `ITgalyaEmailAnalyzer-v0.1.0-rc1-windows-x64.zip`
- `ITgalyaEmailAnalyzer-v0.1.0-rc1-linux-x64.zip`
- `ITgalyaEmailAnalyzer-v0.1.0-rc1-macos-arm64.zip`
- `SHA256SUMS.txt`
- GitHub build-provenance attestations for the three ZIP archives

The release must be marked as a prerelease.

## Verify after download

```bash
sha256sum -c SHA256SUMS.txt
gh attestation verify ITgalyaEmailAnalyzer-v0.1.0-rc1-linux-x64.zip --repo YoniEzs/Ataram-Email-Analyzer
```

Use the platform-appropriate SHA-256 command on Windows/macOS if `sha256sum` is unavailable.

## Publish the website

Only after the release assets resolve successfully should the `tools.itgalya` Email Analyzer PR be merged. Verify the production page, each download, checksum instructions, mobile layout, and issue/source links after Cloudflare deploys the merge.
