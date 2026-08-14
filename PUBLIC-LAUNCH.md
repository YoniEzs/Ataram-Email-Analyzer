# Going public — security checklist

Everything below assumes the deployment described in [README.md](README.md):
cloudflared → nginx → gunicorn on itgalya-app01, published at
`https://analyzer.itgalya.com`.

---

## The thing that will break the site if you miss it

Today the app is gated by Cloudflare Access, and `cloudflared/config.yml`
carries an `access:` block that makes the connector **reject any request without
a valid Access JWT for this application**:

```yaml
      access:
        required: true
        teamName: ataraxcode
        audTag:
          - 270a318a1434863bf02f27a881039a30493b9df8bea035ba7752c535443b3031
```

That block is what protects the origin from someone reaching nginx by another
route — it is deliberately *not* optional while Access is in use.

**If you delete the Access application without touching this block, every
visitor gets rejected at the connector and the site is down for everyone**,
with no error that points at the cause.

Going public is therefore a two-part change that must happen together:

1. Remove or bypass the Access application in the Cloudflare dashboard.
2. Set `required: false` in `cloudflared/config.yml` (or remove the `access:`
   block) and recreate the container:

```bash
ssh itgalya-app01 "cd ~/ataram-analyzer && sed -i 's/^        required: true/        required: false/' cloudflared/config.yml && docker compose up -d --force-recreate cloudflared"
```

Do them in that order, and expect a brief window where the app is public but
Access still has an application defined.

### What you are giving up

Access is currently the *only* authentication in the system. There is no login,
no session, no user model behind it. Once it is off, every endpoint is
anonymous-internet-facing, and the origin's protection is exactly what is listed
in the rest of this document — nothing more.

---

## Pre-launch checklist

### Must do

- [ ] **Set a real `SECRET_KEY`** in `.env`. Startup now aborts on a missing,
      short, or placeholder key, so a mistake here fails loudly rather than
      shipping a known key.
- [ ] **Confirm `TRUSTED_PROXY_COUNT=1`.** Rate limiting keys on the client IP
      derived from this. Too low and the whole internet shares one bucket; too
      high and clients can spoof `X-Forwarded-For` to get a fresh bucket per
      request. `1` is correct for cloudflared → nginx → gunicorn.
- [ ] **Leave `ENABLE_UTILITY_ENDPOINTS=false`.** The frontend never calls
      `/api/analyze/url`, `/api/check/domain` or `/api/check/ip`; each turns a
      cheap request into DNS, WHOIS or third-party traffic from this host.
- [ ] **Rebuild the backend image.** The dependency bumps close a request
      smuggling hole in gunicorn (CVE-2024-1135) that specifically targets the
      proxy-in-front topology this deployment uses:
      `docker compose build backend && docker compose up -d backend`
- [ ] **Validate the configs before restarting nginx** — the rate-limit zones
      and header block are new:
      `docker compose exec web nginx -t`
- [ ] **Verify the security headers are actually reaching the browser:**
      `curl -sI https://analyzer.itgalya.com | grep -iE 'content-security|strict-transport|x-frame|x-content'`
- [ ] **Verify rate limiting fires end to end.** Eleven rapid uploads should
      produce at least one 429.

### Strongly recommended

- [ ] **Turn on Cloudflare's own protections**, which sit in front of everything
      here and are the only thing that can absorb a volumetric attack before it
      reaches your origin: WAF managed rules, Bot Fight Mode, and a rate-limiting
      rule on `/api/analyze`.
- [ ] **Confirm Redis came up.** `docker compose ps redis` — the backend now
      depends on it for limiter storage. Limits still function without it, but
      per-worker rather than fleet-wide.
- [ ] **Decide what the abuse budget is.** A public analyzer that performs WHOIS
      and DNS lookups on demand will attract automated traffic. Watch
      `docker compose logs backend` for the first week.

### Consider

- [ ] **Lower `MAX_UPLOAD_MB`.** 50MB is generous for an email; 10–25MB covers
      essentially all real traffic and reduces what one request can cost.
- [ ] **Add an abuse contact / terms link** to the footer.
- [ ] **Switch to `gthread` workers.** The analysis path is dominated by
      blocking network I/O, and 4 sync workers means 4 concurrent requests.
      `LOOKUP_BUDGET_SECONDS` bounds the damage, but threads would absorb it
      better.
- [ ] **Hash-pin dependencies.** `requirements.txt` pins direct versions but
      transitive ones resolve freely and there is no lockfile.

---

## What was hardened, and what it protects against

| Area | Change | Without it |
|---|---|---|
| **Parse-time DoS** | `validate_header_block()` on raw bytes | **A 1.5MB .eml cost ~237s of CPU** and killed a worker. Python parses header values lazily and super-linearly, so a cap applied after parsing is too late |
| **Parse-time DoS** | `validate_mime_headers()` — sub-part headers | `validate_header_block` stops at the first blank line, so **every nested part's headers were unbounded**: a 1MB file with one 200,000-parameter sub-part `Content-Type` cost **337s CPU and 698MB RSS** while passing every other guard in 5ms |
| **Parse-time DoS** | Part counter switched to boundary delimiters | It matched two literal spellings of `Content-Type:` — but parts don't need one at all, and `CONTENT-TYPE:` dodged it. **20,000 parts counted as 1** |
| **Availability** | `MAX_FORM_MEMORY_SIZE` raised to the upload limit | Set to 64KB believing it limited form *fields*; Werkzeug applies it to the raw multipart buffer, so **every real email over ~100KB was rejected with a 413** — a security setting that broke the product's main function |
| Parse-time DoS | `.msg` header text runs the same guard | A `.msg` is an OLE container, so the raw-byte guards never applied to it: a 256KB `To:` inside a 0.53MB file cost 24.6s |
| Consistency | OLE magic is 8 bytes in both places | `is_probably_msg` tested 4 bytes while the validator tested 8, so a crafted `.eml` could take the MSG path and skip both guards |
| **Parse-time DoS** | `validate_mime_structure()` on raw bytes | A 20,000-part message cost ~14s before any traversal cap could apply |
| **Parse-time DoS** | Single MIME walk; size estimated, not decoded | Every attachment was fully base64-decoded just to call `len()` on it |
| Rate limiting | `@bp.route` made the outermost decorator | **Every limit was inert.** 14 requests against a 10/min endpoint all returned 200 |
| Rate limiting | `ProxyFix` with a trusted-hop count | All clients shared one bucket keyed on the nginx container IP |
| **Rate limiting** | nginx forwards a **single** `X-Forwarded-For` value | `$proxy_add_x_forwarded_for` appends, so ProxyFix's rightmost read returned the cloudflared address — **one global bucket again**, and one client could 429 the whole internet |
| Rate limiting | Redis-backed limiter storage | In-memory counters are per-worker, so limits were ~4x too loose |
| Rate limiting | nginx `limit_req` / `limit_conn` zones | No defence before traffic reaches Python |
| **Worker exhaustion** | `LookupBudget` — one wall-clock budget per request | DNS + chained WHOIS against attacker-chosen hosts, ~25-35s per request on 4 sync workers. Configured timeouts were dead code on this path |
| **Scoring bypass** | Whitelist cap removed outright | It was gated on the `Authentication-Results` header **inside the uploaded file** — the attacker writes it. Requiring DNS-verified SPF+DMARC did not fix it either: those are looked up for the *spoofed* domain |
| **Scoring bypass** | Risk level floored at the worst suspicion | The banner could read "low" above a list containing a critical indicator |
| **Scoring bypass** | URLs collected from the parsed DOM | A regex over raw HTML cannot see `&#104;ttp://…` or `//evil.tld`, which mail clients render as live links. Hidden links scored zero |
| Privacy | Google Fonts removed | Every anonymous page load disclosed the visitor's IP to Google |
| **Parse-time DoS** | Part counter no longer depends on knowing the boundary | RFC 2231 gives `boundary*=utf-8''SEP` and `boundary*0=`/`*1=`, all honoured by Python's parser and none matched by the regex — **193s CPU and 907MB RSS**, HTTP 200. Now counts lines beginning `--`, which no spelling can evade |
| **Parse-time DoS** | Content-* headers capped by TOKEN count, not just bytes | The cost is super-linear in parameter tokens: at an identical 16KB, `; a=b` cost 8.8s and bare `;;` cost **133s**. Byte budgets were the wrong unit |
| **Parse-time DoS** | Sub-part header budget separated from the RFC line limit | The API passed `MAX_HEADER_LINE_BYTES` (16KB), silently reinstating the limit the guard's own default rejects |
| ReDoS | `<form[^>]*>` replaced with a substring test | A body of `<form` with no `>` backtracked for **99.7s** |
| DoS | Single bounded DOM walk with a tag cap | Two `find_all(True)` passes over a deeply nested document cost **123s** |
| Worker exhaustion | Lookup timeouts clamped to the remaining budget | The budget was checked *before* each lookup but never bounded one in flight — a request held a worker 39s against an 8s budget |
| Detection | Dangerous signatures reported even with no extension | `filename="invoice"` with a PE header was cleared, because the mismatch test needed a declared extension to disagree with |
| **Test integrity** | Five vacuous assertions rewritten; mutation-checked | **306 tests passed with three security fixes reverted.** Each rewritten test was then verified to fail against a deliberately broken build |
| **Parse-time DoS** | Aggregate budget on MIME headers | A per-header cap alone was not enough: **1000 parts × a 16KB Content-Type = 652 seconds of CPU** from a 15MB upload, passing every guard in 20ms and returning HTTP 200 |
| **Parse-time DoS** | Count delimiters for **every** declared boundary | The counter read the first `boundary=` token in the header block and returned early. `Subject: boundary=DECOY` hijacked it, and a nested multipart's own boundary was never counted at all — **142s CPU and 882MB RSS** from one 20MB file |
| Parse-time DoS | `get_payload(decode=True)` instead of `get_content()` | `get_content()` re-derives the content type through an uncached header parse ~8.5× per part, multiplying the cost of any inflated header |
| **Detection** | Attachments found regardless of disposition | Analysis ran only for `Content-Disposition: attachment`, so an `.exe` sent `inline`, or with just `name=` on Content-Type, was never named, sniffed or scored |
| **Detection** | Content sniffing (magic bytes vs. declared extension) | An `.exe` named `holiday.jpg` passed every name-based check |
| **Detection** | `Content-Transfer-Encoding` parsed as a token | `base64;` or `base64 (comment)` — both legal — defeated an `== 'base64'` test and disabled sniffing |
| **Detection** | `From:` parsed with `getaddresses` | `parseaddr` returns nothing for a mailbox *list*, which RFC 5322 permits — **one extra address disabled every sender-domain check** (SPF, DMARC, WHOIS, domain age); a measured email fell from 38 to 2 |
| **Scoring** | Trusted-sender cap removed entirely | Unsound in principle: both gate inputs are attacker-chosen, and requiring DNS-verified SPF+DMARC did not help because those are looked up for the *spoofed* domain — every brand worth impersonating publishes both |
| Availability | Redis `protected-mode no` | With it on and no password, Redis refused the backend and the limiter silently fell back to per-worker counters |
| Honesty | `hop_count` reports the true total | The parser truncated before the analyzer saw the list, so a 300-hop email reported 100 hops and `hops_truncated: false` |
| **Rate limiting** | IPv6 aggregated to its /64 | **A single host owns 2^64 addresses.** Measured: 60 uploads from one /64 produced *zero* 429s. No spoofing involved, so no header check or JWT would have stopped it |
| Rate limiting | Redis failures no longer 500 the API | An unreachable Redis turned a cache blip into a total outage |
| **Detection** | Structural credential-form detection | A masked field (`-webkit-text-security:disc`) renders as a password box with none of the keywords. **A full Microsoft-365 harvester scored 0/100, "APPEARS LEGITIMATE"** |
| **Detection** | Attachment list extended; extension parsing fixed | `.lnk` (today's most common loader), `.svg`, `.url`, `.xll` and 30 more scored clean. `payload.exe.` parsed to no extension at all — and Windows strips the trailing dot on save |
| **Detection** | URL host normalised the way a browser does | `https://evil.example\.microsoft.com` parsed as *microsoft.com* in Python and as *evil.example* in every mail client. One character laundered any hostile link |
| Detection | Self-reported authentication earns no credit | Omitting the header was cheaper than admitting failure, and *claiming* a pass was cheaper still — one forged line was worth 15 points. A claim you cannot verify carries no information, so it now scores the same as silence |
| Detection | Retrieved SPF/DMARC records are scored | They were fetched, displayed, and then ignored in favour of the attacker's own header |
| Detection | Free-mail providers dropped from the whitelist | Their SPF authenticates the provider, not the sender's intent |
| Container | Upload limit 25MB; body spool moved to a sized tmpfs | Request buffering wrote 50MB bodies into a 64MB tmpfs — two concurrent uploads returned 500 (ENOSPC) |
| XSS | CSP with `script-src 'self'`, no `unsafe-inline` | Results are built from attacker-supplied email content; one escaping slip is stored XSS |
| XSS | Escaped the remaining unescaped interpolations | Severity, risk level and third-party AbuseIPDB values went into `innerHTML` raw |
| SSRF / recon | `net_guard` rejects internal names and non-public IPs | The lookup endpoints resolved `*.internal`, `127.0.0.1`, `169.254.169.254` on request |
| DoS | Caps on body size, URL/attachment/hop counts | A 50MB body ran the HTML parser and a dozen regex passes; 4 workers is the whole fleet |
| DoS | Bounded LRU cache | Unique lookups grew a dict until the worker was OOM-killed |
| Uploads | Reject NUL bytes, traversal, control chars; verify magic bytes | `evil.exe\x00.eml` passed the extension check |
| Errors | HTTP exceptions keep their status; JSON everywhere | An oversized upload reported as a 500 |
| Secrets | Removed the AbuseIPDB key field from the UI | Users typed a secret that was transmitted and then discarded unread |
| Dependencies | gunicorn, requests, cryptography, lxml, Werkzeug, flask-cors | gunicorn 21.2.0 permitted request smuggling past nginx |
| Container | Non-root, read-only rootfs, `cap_drop: ALL`, no compiler in the image | A parser bug ran as root with gcc available |
| Secrets | Startup rejects weak/placeholder `SECRET_KEY` and `CORS_ORIGINS=*` | Misconfiguration failed silently |

Correctness bugs surfaced during this work and fixed:

- **DMARC and DKIM were never detected.** The domain validator rejected
  underscore labels, so every `_dmarc.…` and `…._domainkey.…` lookup was
  refused before it was sent. Emails from domains with no DMARC policy scored
  identically to domains with `p=reject`.
- **`.msg` support was completely broken.** `m.header` returns an
  `email.message.Message`, not a string, so `parsestr()` raised `TypeError` on
  every single Outlook upload — and the raw Python error text was returned to
  the caller. Behind it sat three more: `m.message_id` (the attribute is
  `messageId`), `", ".join(m.to)` joining a string character by character, and
  `htmlBody` returning `bytes` into string concatenation.
- **Every Hebrew, Arabic or Chinese named upload was rejected.**
  `secure_filename` strips non-ASCII, reducing `דואר.eml` to `eml` — no dot —
  so the extension re-derived downstream was empty.
- **A malformed URL could 500 the request.** `urlparse`'s result was read
  outside the `try` block that produced it.
- **An unknown charset aborted the whole analysis** on a non-multipart message.

## What is still not protected

Stated plainly, because "hardened" is not "immune":

- **No authentication.** After Access is removed, anyone can submit anything.
- **No volumetric DoS protection at the origin.** Rate limits are per-IP;
  distributed traffic needs Cloudflare's rules, not this application's.
- **Uploaded email content passes through memory and, for large uploads, a tmpfs
  spool file.** It is never persisted deliberately, but "never stored" in the
  footer is a statement about intent, not an enforced guarantee.
- **Attachments are analysed by name and size only.** No content inspection, no
  AV, no sandbox. The tool reports what an attachment *claims* to be. A `.docx`
  containing a malicious payload is indistinguishable from a real one here.
- **Detection is heuristic and will always be evadable.** Five audit rounds ran
  against this code. Every one found something the previous round missed, and
  rounds three, four and five each found a *critical* flaw in a guard the
  previous round had just added. The fixes closed the specific bypasses found;
  an attacker who reads this source will find more. Treat a "low" verdict as
  *no evidence found*, never as *safe* — the verdict string says "APPEARS
  LEGITIMATE" and that wording is doing real work.
- **A passing test suite is weaker evidence than it looks.** Round five proved
  three security fixes could be reverted with all 306 tests still green. Those
  assertions were rewritten and mutation-checked, but the lesson generalises:
  when changing a guard here, revert it deliberately and confirm a test fails.
- **The guards are bounded, not free.** They add roughly 240ms to a 25MB
  upload. That is the deliberate trade: a fixed, predictable cost on every
  request in exchange for refusing the ones that would otherwise cost minutes.

### Known open items

Confirmed by audit, deliberately not fixed. None is a denial-of-service or a
code-execution path; all are detection gaps or minor hygiene.

**Detection gaps** — each is a real way to score lower than the email deserves:

- HTML smuggling (a `data:` URI download plus `atob()` in a script) is not
  detected as a delivery mechanism.
- A credential-harvesting *link* raises only a `medium` suspicion, where a
  credential *form* raises `critical`.
- An open redirect on an otherwise legitimate domain is graded `medium`.
- **Pure social engineering scores `low` and always will.** A BEC or sextortion
  email with no attachment, no link and no form contains nothing this tool
  inspects. It reads structure, not intent.

**Hygiene / privacy:**

- Gunicorn's access log records each submitter's IP. The footer says email
  *content* is never stored, which remains true, but the IP is written to the
  container's stdout log. Set `--access-logfile /dev/null` if that matters.
- A failed DNS lookup is negative-cached for 5 minutes and served to every
  other user of the instance in that window.
- The shared lookup cache is a weak timing oracle for which domains other
  users have recently analysed.
- `header_forensics` derives its hop count from the truncated list, so it can
  disagree with `routing.hop_count` on a >100-hop email.
- The frontend expires localStorage history on display rather than on write.

### What five rounds of auditing did and did not settle

Severity fell steadily: round 1 found rate limiting completely inert and
DMARC/DKIM never detected; round 5's worst finding was a parser bypass costing
193 seconds. What is left, above, is graded `medium` and below.

That trend is evidence, not proof. Three consecutive rounds found a *critical*
flaw in a guard the previous round had just added — always for the same reason:
the guard tried to agree with the parser about syntax (which boundary spelling,
which unit of measurement), and any disagreement was a bypass. The guards that
have held are the ones that need no agreement: count lines beginning `--`,
count tokens, bound raw bytes before the parser is reached.

Apply that test to any guard added here in future.
- **`.msg` uploads skip the RFC 5322 header guard** — it does not apply to an
  OLE compound file. The MIME-part guard and all analysis caps still apply, but
  the `.msg` path is less hardened than the `.eml` path.
- **The lookup budget degrades results under load.** When it is spent, SPF/DMARC/
  WHOIS come back empty and the response is marked `lookups_truncated`. The UI
  says so; automated consumers of the JSON must check that field.
