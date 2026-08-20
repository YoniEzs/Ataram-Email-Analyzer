# QA guide

A manual test script for a full hand-check of the analyzer. Work top to bottom
and record pass/fail per line. Every command here was executed and verified on
a clean checkout; where a step is expected to fail today, it says so.

Automated tests cover 87% of the backend (`385 tests`). This guide deliberately
concentrates on what automation *cannot* reach: the browser, real Outlook
files, real API keys, and the deployment paths.

---

## 0. Setup

macOS / Linux:

```bash
git clone https://github.com/YoniEzs/Ataram-Email-Analyzer.git
cd Ataram-Email-Analyzer/backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

Windows PowerShell:

```powershell
git clone https://github.com/YoniEzs/Ataram-Email-Analyzer.git
cd Ataram-Email-Analyzer\backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

On Windows, call the venv's `python.exe` directly rather than activating.
PowerShell's execution policy blocks `Activate.ps1` on a default install,
and `.venv\Scripts\activate` is cmd syntax that does nothing in PowerShell.
PowerShell 5.1 also has no `&&`, so run one line at a time.

Every `pytest` / `ruff` / `mypy` command below assumes an activated venv. On
Windows without activation, prefix each with `.\.venv\Scripts\python.exe -m`.

> A virtual environment is **required**. Installing into a system Python that
> ships a patched setuptools (Debian/Ubuntu) fails while building `pyspf`
> with `AttributeError: install_layout`. This is a packaging quirk of the
> pinned `pyspf==2.0.14`, not a repository defect.

| # | Check | Expected | Result |
|---|---|---|---|
| 0.1 | `pytest -q` | `385 passed, 1 skipped`, coverage ≥ 80% | ☐ |
| 0.2 | `ruff check app tests` | `All checks passed!` | ☐ |
| 0.3 | `mypy` | `Success: no issues found in 31 source files` | ☐ |

The one skip is in `test_samples_regression.py`: sample 05's expected findings
are described in prose rather than as flag codes, so only its score and level
are pinned. A second skip appears in `test_desktop.py` if `flask-talisman` is
not installed.

---

## 1. Launch

Run the whole tool — UI and API in one local process on `127.0.0.1`:

```bash
python -m app.desktop
```

| # | Check | Expected | Result |
|---|---|---|---|
| 1.1 | Browser opens by itself | Tab at `http://127.0.0.1:8321` | ☐ |
| 1.2 | `ATARAM_NO_BROWSER=1 python -m app.desktop` | Starts, no tab opens | ☐ |
| 1.3 | `ATARAM_PORT=9000 python -m app.desktop` | Serves on 9000 | ☐ |
| 1.4 | `curl http://127.0.0.1:8321/health` | `{"service":...,"status":"healthy"}` | ☐ |
| 1.5 | From a second machine, browse to this host's LAN IP:8321 | **Refused** — the desktop build must bind loopback only | ☐ |

Docker path:

```bash
cd .. && cp .env.example .env && docker compose up --build
```

| # | Check | Expected | Result |
|---|---|---|---|
| 1.6 | `http://localhost:3000` loads | UI renders | ☐ |
| 1.7 | Frontend waits for backend health | 10–40 s pause before frontend starts — not a hang | ☐ |
| 1.8 | `curl http://localhost:5000/health` | **Refused** — backend is not published to the host | ☐ |
| 1.9 | Docker Desktop on Windows | Same result as Linux | ☐ |

---

## 2. Sample corpus

The five files in `samples/` have documented verdicts. These are now enforced
by `backend/tests/test_samples_regression.py`, so step 0.1 already proves the
numbers — but check the UI renders them correctly.

Upload each at `http://127.0.0.1:8321`, with all enrichment **off**
(see §5 for the env block):

| # | Sample | Expected score / level | Result |
|---|---|---|---|
| 2.1 | `01-clean-newsletter.eml` | 0, low, no flags | ☐ |
| 2.2 | `02-display-name-spoof.eml` | 6, low, 4 flags | ☐ |
| 2.3 | `03-homograph-sender.eml` | 9, low, `homoglyph_sender_domain` | ☐ |
| 2.4 | `04-bcc-delivery.eml` | 0, low, 2 flags | ☐ |
| 2.5 | `05-zip-double-extension.eml` | 25, **medium**, attachment critical | ☐ |

With enrichment **on**, scores may rise and extra unscored flags such as
`ptr_helo_mismatch` appear. That is correct behaviour, not a regression.

---

## 3. Real-world input — the biggest gap

Nothing below is covered by automation. `.msg` support is real but has only
ever been tested against synthetic fixtures, and no real Outlook file exists in
the repo.

| # | Check | Expected | Result |
|---|---|---|---|
| 3.1 | A **genuine Outlook `.msg` export** | Parses; sender, subject, recipients, body and attachments all correct | ☐ |
| 3.2 | `.msg` with an attachment | Attachment listed with correct name and size | ☐ |
| 3.3 | `.msg` with HTML body only | HTML body rendered, no crash | ☐ |
| 3.4 | A real phishing `.eml` from your own mailbox | Sensible verdict, no crash | ☐ |
| 3.5 | A legitimate newsletter with many URLs | Low score — check for false positives | ☐ |
| 3.6 | EML: plain text only | Parses | ☐ |
| 3.7 | EML: HTML only | Parses | ☐ |
| 3.8 | EML: multipart/alternative | Parses | ☐ |
| 3.9 | EML with very long headers | Parses, bounded | ☐ |
| 3.10 | Deliberately malformed MIME | Degrades to a friendly 400, never a 500 | ☐ |

---

## 4. Limits and hostile input

| # | Check | Expected | Result |
|---|---|---|---|
| 4.1 | Upload a file > 25 MB | Friendly 413, not a stack trace | ☐ |
| 4.2 | Upload a `.txt` | Rejected: only `.eml`/`.msg` | ☐ |
| 4.3 | Upload an empty file | Friendly 400 | ☐ |
| 4.4 | Rename a `.exe` to `.eml` and upload | Rejected by content validation | ☐ |
| 4.5 | A zip-bomb attachment | `archive_bomb_suspected`, no memory spike | ☐ |
| 4.6 | An email with 300+ MIME parts | Bounded at 250, no hang | ☐ |
| 4.7 | Watch memory during 4.5–4.6 | No runaway growth | ☐ |

---

## 5. Offline / no-disclosure mode

Put this in `backend/.env`, restart, then re-run §2:

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

| # | Check | Expected | Result |
|---|---|---|---|
| 5.1 | Analyze any sample | Artifacts block still complete | ☐ |
| 5.2 | Enrichment fields | Each shows `disabled`, never blank | ☐ |
| 5.3 | Watch traffic (`tcpdump`, Wireshark, or pull the cable) | **Zero** outbound connections during analysis | ☐ |
| 5.4 | Same flags in `docker-compose.yml` | Honoured inside the container too | ☐ |

> 5.3 is the honest test of the privacy claim. Until the enforced offline
> switch lands, this mode is nine separate flags and only observation proves
> it. Note that DNS for the *analyzer's own* startup is unrelated — watch for
> connections during the analysis itself.

---

## 6. Optional integrations

Run each **alone**, then together.

| # | Check | Expected | Result |
|---|---|---|---|
| 6.1 | No keys at all | Full analysis, integration fields say `disabled` | ☐ |
| 6.2 | AbuseIPDB key only, via `.env` | IP reputation populated | ☐ |
| 6.3 | AbuseIPDB key only, pasted in the UI | Same result | ☐ |
| 6.4 | A deliberately **invalid** AbuseIPDB key | Degrades to no data, no crash, key not echoed in the response | ☐ |
| 6.5 | `ENABLE_VIRUSTOTAL=true` + key, on sample 05 | Hash verdict appears | ☐ |
| 6.6 | Both keys together | Both populate | ☐ |
| 6.7 | Search the server log for either key | **Not present** | ☐ |

---

## 7. Interface

| # | Check | Expected | Result |
|---|---|---|---|
| 7.1 | Language toggle → Hebrew | Full RTL, `dir="rtl"`, no clipped text | ☐ |
| 7.2 | Toggle back to English | Clean LTR | ☐ |
| 7.3 | Theme toggle | Light/dark both readable | ☐ |
| 7.4 | Drag-and-drop a file | Works as well as the file picker | ☐ |
| 7.5 | Every result tab | Renders, no console errors | ☐ |
| 7.6 | **Copy Artifacts** | Clipboard holds the full block | ☐ |
| 7.7 | **Download Report (JSON)** | Valid JSON, opens cleanly | ☐ |
| 7.8 | **Print Report** | Readable PDF, nothing cut off | ☐ |
| 7.9 | Print in Hebrew | RTL preserved | ☐ |
| 7.10 | Browser console throughout | No uncaught errors | ☐ |
| 7.11 | History panel | Persists across reload; **Clear** empties it | ☐ |
| 7.12 | Analyze with the backend stopped | Friendly "server unreachable", not a blank page | ☐ |

---

## 8. Known gaps — expect these

Not defects to report; recorded so they are not chased twice.

- **No release exists.** No git tag has been pushed, so the desktop zip, the
  PyPI/pipx package and the published Docker images are all unavailable. Only
  the source-checkout paths work. There is no PyPI publish workflow at all.
- **CodeQL and dependency-review never run** — both are gated on
  `github.event.repository.private == false` in `.github/workflows/security.yml`.
- **No end-to-end browser test.** `frontend/tests/smoke.mjs` injects a
  fabricated result object and never contacts the backend, so the upload path
  through a real browser is only covered by §2 and §7 here.
- **`npm run check` is a syntax parse only** — no linter, no type checking.
- **`.msg` support has only synthetic fixtures** — §3.1–3.3 is its first real
  test.

---

## 9. Recording results

For anything that fails, capture: the step number, the input file (redacted if
real mail), the full JSON response, and the server log lines for that request.
Backend logs go to stdout; `LOG_TO_FILE=true` also writes `logs/`.
