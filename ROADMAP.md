# Roadmap — Bug Fixes & Code Improvements

Living document tracking known issues and planned improvements, ordered by
priority. Items reference the actual files involved. Effort: **S** (hours),
**M** (days), **L** (a week+).

## ✅ Recently completed (code review, 2026-07)

Fixed on branch `claude/code-review-bug-fixes-wpp6u0`:

- Talisman `force_https` redirected every request with 302 in testing mode
  (broke 20 tests) — `backend/app/__init__.py`
- WHOIS lookups always failed (`python-whois` has no `timeout` kwarg →
  silent `TypeError`), disabling domain-age scoring — `whois_service.py`
- MSG parsing crashed on every file (wrong `extract_msg` API assumptions:
  `message_id`, `to`/`cc` as lists, `date` type, `htmlBody` bytes) —
  `email_parser.py`
- Whitespace-padded attachment extensions (`"invoice.exe "`) dodged the
  executable check; `hidden_extension` was unreachable; severity could be
  downgraded — `attachment_analyzer.py`
- `@` in URL query strings falsely flagged as credential-phishing URLs —
  `url_analyzer.py`
- TXT records >255 bytes (long SPF) corrupted by naive quote stripping —
  `dns_checker.py`
- Cleanups: deprecated `utcnow()`, `CORS_ORIGINS` whitespace, logs dir race
- Regression tests for all of the above (suite: 88 passing)

---

## P0 — Correctness & security bugs ✅ (completed 2026-07)

- [x] **Don't trust attacker-supplied `Authentication-Results` headers** (M)
  `email_analyzer.py::_analyze_authentication` regex-scans *all*
  `Authentication-Results` headers joined together. A crafted email can embed
  its own fake `spf=pass dkim=pass dmarc=pass` header. Use only the topmost
  header (added by the receiving server), and ideally verify the authserv-id.

- [x] **EML validation can reject valid emails** (S)
  `validators.py::validate_email_file` requires `From:`/`To:`/`Subject:`/`Date:`
  within the first 1,000 bytes. Real exports (Gmail/Outlook) often start with
  >1 KB of `Received:`/`ARC-*`/`DKIM-Signature` headers, pushing those past the
  window. Widen the window (e.g. 8 KB) or parse headers properly.

- [x] **Registered-domain extraction is wrong for ccTLDs** (S)
  `url_analyzer.py` takes the last two labels, so `example.co.uk` → `co.uk`.
  This skews `shortened_url`, `suspicious_tld`, and
  `domain_mismatch_with_sender`. Use `tldextract` (Public Suffix List).

- [x] **DKIM check queries the wrong domain and accepts any TXT** (S)
  `dns_checker.py::check_dkim` uses the *sender* domain instead of the `d=`
  domain from the `DKIM-Signature` header, and returns the first TXT record
  without checking it looks like a DKIM key (`v=DKIM1`/`p=`).

- [x] **IPv6 senders are invisible** (S)
  `extractors.py::extract_sender_ip` only matches IPv4, so mail relayed over
  IPv6 yields no sender IP (and no reputation check). Reuse the candidate
  iteration from `header_forensics.py`, which already handles both.

- [x] **Consistent JSON error responses** (S)
  413 (file too large), 404, and 500 outside the blueprint return Flask's HTML
  error pages. Register app-level JSON error handlers so the frontend never
  parses HTML.

- [x] **Detect RTL-override filename spoofing** (S)
  `attachment_analyzer.py` doesn't flag U+202E tricks like
  `"annexe_‮fdp.exe"` which displays as `annexe_exe.pdf`. Flag Unicode
  bidi control characters in filenames as critical.

## P1 — Production hardening ✅ (completed 2026-07)

Also bumped vulnerable pinned dependencies flagged by the new pip-audit
gate: flask-cors 6.0.0, python-dotenv 1.2.2, requests 2.33.0, lxml 6.1.0,
cryptography 48.0.1, pytest 9.0.3, pytest-cov 7.0.0.

- [x] **Shared storage for rate limiting and caches** (M)
  Flask-Limiter uses in-memory storage (explicit warning at startup) and
  `utils/cache.py` is per-process. With `gunicorn --workers 2` limits and
  caches are per-worker. Add Redis via `RATELIMIT_STORAGE_URI` and a cache
  backend switch; keep in-memory as the dev fallback.

- [x] **Log to stdout in production** (S)
  `app/__init__.py` writes `logs/email_analyzer.log`; on Render the filesystem
  is ephemeral and logs vanish on redeploy. Prefer stdout (picked up by the
  platform) with file logging as an opt-in.

- [x] **Parallelize external lookups** (M)
  `email_analyzer.py::analyze` runs SPF → DMARC → DKIM → WHOIS → AbuseIPDB
  sequentially; worst case adds tens of seconds per analysis. Fan out with a
  `ThreadPoolExecutor` and a global deadline.

- [x] **Supply-chain & CI hygiene** (S)
  Enable Dependabot (pip + actions + docker), add `pip-audit` to `quality-ci`,
  and a coverage floor to `backend-ci` so the new test suite doesn't erode.

- [x] **Remove `msg_object` from parser output** (S)
  `email_parser.py` returns the raw `EmailMessage` in `parsed_data`; nothing
  consumes it and it's not JSON-serializable. Drop it or use it for deeper
  analysis (see P2).

## P2 — Better detection ✅ (completed 2026-07)

The "verify authentication" item ships as an independent verification
layer (pyspf + dkimpy, ENABLE_AUTH_VERIFICATION) that cross-checks the
claimed Authentication-Results and flags contradictions as forgery.

- [x] **Real YARA scanning** (M)
  `Config.YARA_RULES_PATH` exists but is never read; `content_analyzer.py`
  only does "YARA-like" substring checks. Integrate `yara-python`, load rules
  from the configured path, scan bodies and attachment bytes.

- [x] **VirusTotal integration** (M)
  `ENABLE_VIRUSTOTAL` / `VIRUSTOTAL_API_KEY` config exists with no service
  behind it. Hash attachments (sha256) and query the VT file/URL APIs, with
  caching and strict timeouts.

- [x] **Verify authentication instead of parsing claims** (L)
  Evaluate SPF ourselves against the originating IP (`pyspf`) and verify DKIM
  signatures (`dkimpy`) using the raw message — this also mitigates the P0
  trust issue at its root.

- [x] **Attachment content inspection** (M)
  Analysis is filename-only today. Compare magic bytes against the claimed
  extension (e.g. an "invoice.pdf" that starts with `MZ`), peek inside
  archives (bounded depth/size) for executable payloads.

- [x] **Homograph & IDN detection** (S)
  Beyond the `xn--` prefix check: decode punycode, flag mixed-script and
  confusable domains (e.g. Cyrillic `а` in `pаypal.com`).

- [x] **Multi-language phishing keywords** (S)
  `content_analyzer.py` keyword lists are English-only; Hebrew (and other)
  phishing emails sail through. Move lists to data files keyed by language,
  detect language, and load the right lists (start with `he`).

- [x] **Smarter URL extraction** (S)
  Catch scheme-less URLs (`www.example.com`), extract `href` values directly
  from parsed HTML (already have BeautifulSoup), and de-duplicate against the
  regex pass.

- [x] **MSG body fallback** (S)
  `_parse_msg` leaves `body_text` empty when HTML exists; derive text from the
  HTML so language analysis always has clean input. Same for EML-only-HTML.

## P3 — Product & UX

- [ ] **OpenAPI spec + versioned API** (M)
  Publish `/api/v1` with an OpenAPI document (flask-smorest or apispec);
  freeze the response contract the frontend relies on.

- [ ] **Frontend resilience** (S)
  `api.js` fetches have no timeout — add `AbortController` (~60 s) and upload
  progress; friendlier copy for 429 responses.

- [ ] **i18n (Hebrew first)** (M)
  UI strings are hard-coded English. Add a locale layer with `he`/`en`,
  including RTL layout support.

- [ ] **Report export** (M)
  JSON export exists; add a printable/PDF report of the analysis for sharing
  with non-technical recipients.

- [ ] **Frontend tests** (M)
  Only the backend DOM-contract test guards the UI today. Add unit tests for
  `results.js` rendering and a Playwright smoke test (upload → results).

## Engineering quality (ongoing)

- [ ] Type hints everywhere + `mypy --strict` in CI (M)
- [ ] Pre-commit hooks: ruff, ruff-format, whitespace (S)
- [ ] Pin the Docker base images by digest; scan images in `docker-publish` (S)
- [ ] Decide on `SECRET_KEY`: currently required in production but no
  sessions/CSRF use it — either use it or drop the hard requirement (S)
