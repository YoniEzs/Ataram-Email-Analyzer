# Evaluating Ataram Email Analyzer as a SOC analyst

A hands-on guide to testing the tool against real mail and judging whether it
earns a place in your triage workflow. Written for analysts, not developers.

> **Before you upload anything real:** the message never leaves your machine for
> analysis, but the optional enrichment lookups disclose the message's *sending
> IP* to third parties (Team Cymru over DNS, `rdap.org`). That IP is often your
> own mail infrastructure. If that matters, run in the no-disclosure mode in
> §6 before testing sensitive mail. See `PRIVACY.md`.

## 1. Run it (Docker from source)

Requirements: Docker Desktop (or Engine) with Compose v2.

```bash
git clone https://github.com/YoniEzs/Ataram-Email-Analyzer.git
cd Ataram-Email-Analyzer
cp .env.example .env
docker compose up --build
```

Open <http://localhost:3000>. Stop with `Ctrl+C`, then `docker compose down`.

Warm up on the five bundled synthetic messages in `samples/` — each documents
the exact verdict it should produce (`samples/README.md`). If those match, the
pipeline is working end to end.

## 2. Get real mail to test

Your own spam/quarantine folder is the best corpus. Export a single message as
`.eml`:

- **Gmail:** open the message → ⋮ → *Show original* → *Download Original*.
- **Outlook (desktop):** drag the message to your desktop, or *File → Save As →
  Outlook Message Format* for `.msg`.
- **Outlook (web) / M365:** *… → View → View message source* / *Save as EML*.

Public real-phishing corpora for volume testing:

- **phishing_pot** (github.com/rf-peixoto/phishing_pot) — thousands of real
  phishing `.eml` samples, curated for research.
- **Nazario phishing corpus** (monkey.org/~jose/phishing/) — the classic
  academic set.

Handle these like live samples: they may carry real malicious URLs and
attachments. The analyzer never executes them, but your mail client might — work
in the browser UI, not your inbox.

## 3. The test that matters most — can you fool the trust model?

This tool's core claim is that **nothing an attacker can forge in the file is
ever scored as trust**. Try to break it:

1. Take a legitimate email you exported. Note its score.
2. Open the `.eml` in a text editor and forge the authentication verdicts:
   - Change or add `Authentication-Results: mx.you.example; spf=pass;
     dkim=pass; dmarc=pass`.
   - Add a `Received: from trusted-mailserver.microsoft.com (...)` hop.
3. Re-upload the edited file.

**Expected:** the score does **not** improve, and no field gains a green
*Observed* / verified badge from those headers. The Authentication tab should
show the SPF/DKIM/DMARC values as *untrusted header claims*. If forging headers
ever lowers the risk or manufactures trust, that's a serious finding — report it.

Then the opposite: forge *hostile* headers (a homograph From domain, a
`Reply-To` at a freemail address). Those **should** raise flags, because they are
computed properties of the attacker's own strings, not trust claims.

## 4. Cross-check the enrichment against your own tools

For a message with a public sending IP, compare the tool's output against manual
lookups. The Team Cymru origin lookup takes the IP with its **octets reversed**
(same order as a PTR query) — e.g. `198.51.100.24` becomes
`24.100.51.198.origin.asn.cymru.com`:

```bash
dig +short -x 198.51.100.24                                  # reverse DNS (PTR)
dig +short TXT 24.100.51.198.origin.asn.cymru.com            # ASN | prefix | CC | registry
whois 198.51.100.24 | grep -iE 'netname|orgname|country'
```

The tool's *Reverse DNS*, *ASN*, *BGP prefix* and *country* should match those
outputs. A forward-confirmed reverse DNS (FCrDNS) *pass/fail* is a genuine signal
an analyst can act on — verify it lines up: `dig -x` to get the PTR name, then a
forward `dig` on that name should return the original IP for a *pass*.

## 5. Read it as a ticket

On a real phish, click **Copy Artifacts** and paste into a scratch ticket. Judge
honestly: is the block complete? Would a tier-1 analyst understand the verdict
and the *why*? Is the observed-vs-claimed distinction clear once the colours are
gone? This export is the tool's main workflow output — it should stand on its own.

## 6. No-disclosure / offline run

To analyse without any outbound lookups, set these in `.env` and restart
(`docker compose down && docker compose up --build`):

```dotenv
ENABLE_WHOIS=false
ENABLE_ABUSEIPDB=false
ENABLE_VIRUSTOTAL=false
ENABLE_REVERSE_DNS=false
ENABLE_IP_RDAP=false
ENABLE_ASN_LOOKUP=false
ENABLE_MX_LOOKUP=false
ENABLE_SPF_ADVISORY=false
ENABLE_AUTH_VERIFICATION=false
```

Re-run an analysis: every enrichment row should report status `disabled`, and no
DNS/RDAP traffic should leave the host (confirm with `tcpdump`/your firewall if
you want proof). Offline, the tool still parses, extracts all seven artifacts,
inspects attachments and runs YARA — it just skips the network signals. Confirm
the score and flags still make sense.

> These toggles only take effect in Docker because the Compose file forwards
> them into the backend container. If you set one and the row still shows a live
> result, confirm you edited the `.env` next to the compose file and restarted.

## 7. Break-it ideas (robustness)

Upload these and confirm a *friendly* rejection, never a crash or hang:

- A non-email file renamed `.eml` (a PNG, a PDF).
- An empty file; a 30 MB file (should reject at the 25 MB limit with a clear
  message).
- A `.eml` with a malformed / truncated MIME structure.
- A message with a ZIP attachment (nested archives, double extensions).

Every one should return a clear message and leave the app usable.

## 8. Known honest limits (so you judge fairly)

- **SPF and DMARC are not reconstructed** from an uploaded file — the real SMTP
  peer and envelope sender aren't in the file. Only **DKIM** is cryptographically
  verified. The "advisory SPF" is a display-only recomputation from forgeable
  headers and never affects the score.
- **`.msg` (Outlook) support is real but only synthetically tested** so far —
  a genuine Outlook export is exactly the kind of file worth trying, and worth
  reporting if anything looks off.
- **URLs are never fetched and attachments are never run.** URL checks are
  string analysis only (`urllib.parse`, homograph and shortener heuristics);
  attachment checks are hashing, magic bytes and ZIP *metadata* — archives are
  never inflated to disk. So opening a live phish in this tool does not touch
  the attacker's infrastructure. The flip side is that it is **not a sandbox**:
  there is no detonation, so nothing here tells you what the payload would
  actually do when run.
- **No third-party lookup is performed for you on files or URLs.** The results
  view carries no "check this hash/URL on VirusTotal" button — copy the value
  and pivot deliberately if you want to. Submitting a sample to a public
  service is itself a disclosure, and is your decision, not the tool's.
- **A low score is never a safety guarantee** — it means no strong indicators
  were found in this file, not that the message is safe.
- Enrichment reflects the *claimed* sending IP from the `Received` chain, which
  an attacker controls; the tool labels it accordingly.

## 9. Findings template

| # | Sample / source | What you did | Expected | Actual | Severity | Notes |
|---|---|---|---|---|---|---|
|   |                 |              |          |        |          |       |

Send findings to the repository's issue tracker or your usual channel. The most
valuable ones: any case where a forged header changes the verdict, any
enrichment mismatch against your manual lookups, and any real `.msg` that parses
wrong.
