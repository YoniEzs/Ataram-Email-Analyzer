# Third-Party Notices

Project-authored source code is MIT licensed. Third-party packages retain their
own licenses and copyright notices. The authoritative dependency set is
`backend/requirements-prod.txt`, `backend/requirements-dev.txt` and
`frontend/package-lock.json`.

Notable direct runtime dependencies include:

| Package | Purpose | Upstream license family |
|---|---|---|
| Flask / Werkzeug | Web API | BSD |
| flask-cors | Browser CORS policy | MIT |
| flask-talisman | HTTP security headers | Apache-2.0 |
| python-oxmsg | Outlook MSG parsing | MIT |
| olefile | OLE container parsing (transitive) | BSD |
| dnspython | DNS queries | ISC |
| requests | HTTPS clients | Apache-2.0 |
| tldextract | Public Suffix List parsing | BSD |
| yara-python | YARA integration | Apache-2.0 |
| dkimpy | DKIM verification | BSD-like |
| Beautiful Soup | HTML parsing | MIT |
| lxml | HTML/XML parser | BSD |
| Gunicorn | WSGI server | MIT |
| Flask-Limiter | Rate limiting | MIT |
| redis-py | Shared cache client | MIT |
| nginx / Redis container images | Frontend proxy and cache | Upstream licenses |

This table is an index, not a substitute for the complete license texts. Release
CI generates an installed-package SBOM and license report; reviewers must check
that report before distributing binaries or container images.

The previous GPLv3 `extract-msg` dependency is intentionally not part of the
release dependency set.
