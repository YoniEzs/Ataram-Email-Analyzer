# Roadmap

## Public-release work completed on the release-readiness branch

- [x] Treat all uploaded `Authentication-Results` values as untrusted,
  display-only claims.
- [x] Independently verify DKIM and expose relaxed signing-domain alignment.
- [x] Stop claiming that SPF/full DMARC can be reconstructed from an uploaded
  file.
- [x] Add EML/MSG, MIME-part, attachment, text, YARA and ZIP-bomb limits.
- [x] Fix MSG parsing and replace GPL-licensed `extract-msg` with MIT-licensed
  `python-oxmsg`.
- [x] Add PSL-aware domains, IPv6, IDN/homograph, magic-byte, YARA, VirusTotal
  hash and multilingual checks.
- [x] Replace blocking WHOIS sockets with bounded HTTPS RDAP requests.
- [x] Make the browser same-origin by default and remove the owner's Render URL
  fallback.
- [x] Add Redis-backed caches/rate limits to Docker and Render deployments.
- [x] Add privacy, disclaimer, security, contribution and community documents.
- [x] Add backend, frontend, dependency, secret, CodeQL, container and release
  workflow definitions.

## Gates before changing repository visibility

- [ ] All required GitHub checks pass on the exact PR head SHA.
- [ ] Full-history secret scan is clean, including closed branches and PR refs
  that GitHub will expose after publication.
- [ ] Clean Docker install succeeds on Linux and Windows Docker Desktop.
- [ ] EML and MSG samples are tested with every optional integration both off
  and on.
- [ ] A sanitized labeled corpus establishes documented false-positive and
  false-negative baselines.
- [ ] Repository rules require PRs and green checks and block force-pushes to
  `main`.
- [ ] Branding/contact links are confirmed and obsolete split frontend/backend
  repositories are archived or kept private.
- [ ] `v0.1.0-rc1` is published as experimental and completes a seven-day soak.

See `RELEASE_CHECKLIST.md` for the executable checklist.

## After v0.1.0

- Multiple DKIM-signature verification with per-signature results.
- Optional trusted-MTA ingestion format carrying SMTP peer IP, envelope sender
  and authenticated delivery metadata for real SPF/DMARC evaluation.
- A sanitized regression corpus with machine-readable expected findings.
- Authenticated multi-user deployments and per-tenant quotas.
- Structured telemetry that remains off by default and contains no email data.
