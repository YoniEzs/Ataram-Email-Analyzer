# Deployment — analyzer.itgalya.com

Runs the Ataram Email Analyzer on **itgalya-app01 (192.168.7.81)** behind a
dedicated Cloudflare Tunnel, published at `https://analyzer.itgalya.com` and
gated by Cloudflare Access with email one-time-PIN login.

## Layout

Deploy root on the host: `/home/dragon/ataram-analyzer`

```
docker-compose.yml
nginx.conf
.env                      # generated on the host — not in git
backend/                  # copy of ataram-backend
frontend/                 # copy of ataram-frontend
cloudflared/
  config.yml
  credentials.json        # tunnel secret — not in git
```

## Services

| Container | Image | Exposed | Role |
|---|---|---|---|
| `ataram-analyzer-backend` | built from `backend/Dockerfile` | `5000` (internal only) | Flask + gunicorn, 4 workers |
| `ataram-analyzer-web` | `nginx:1.27-alpine` | `80` (internal only) | serves `frontend/src`, reverse-proxies `/api/` and `/health` |
| `ataram-analyzer-cloudflared` | `cloudflare/cloudflared:latest` | — | tunnel `ataram-analyzer` |

Nothing is published to a host port. The existing `itgalya` stack already owns
80/443 on this box; this stack is reachable only through its own tunnel, on the
private `ataram-analyzer_ataram` bridge network.

**Single origin by design.** nginx serves the static frontend *and* proxies the
API, so `config.js` uses a same-origin (empty) `API_BASE_URL`. That means one
hostname, one Access application, no CORS preflight, and the Access
`CF_Authorization` cookie automatically covers the API calls the page makes.

## Tunnel

- Name: `ataram-analyzer`
- ID: `60200874-f30b-4062-b8c0-67811340916b`
- CNAME target: `60200874-f30b-4062-b8c0-67811340916b.cfargotunnel.com`

Locally managed (config file + credentials on the host), not dashboard-managed —
ingress lives in `cloudflared/config.yml`.

The cloudflared container runs as `user: "1000:1000"`. The image defaults to uid
65532, which cannot read the `0600` credentials file owned by `dragon`; running
as the owning uid avoids loosening the file mode.

## Operations

```bash
ssh itgalya-app01
cd ~/ataram-analyzer

docker compose ps
docker compose logs -f backend
docker compose logs -f cloudflared
docker compose restart backend
```

Redeploy after a code change:

```bash
docker compose build backend && docker compose up -d backend
```

Frontend files are bind-mounted, so a frontend change needs only a re-copy — no
rebuild.

## Hardening

The application-level hardening (rate limiting, CSP, input validation, upload
checks, container isolation, dependency updates) is summarised with its rationale
in [PUBLIC-LAUNCH.md](PUBLIC-LAUNCH.md). Configuration knobs are documented
inline in [.env.example](.env.example).

Validate config changes before they take effect:

```bash
docker compose exec web nginx -t
```

## Security — the origin is not protected by Access alone

Cloudflare Access is enforced **only at Cloudflare's edge**. The tunnel removes
the need for open inbound ports, but it authenticates nothing by itself. Anything
that reaches nginx by another path bypasses Access entirely:

- another host on the LAN hitting the container directly,
- a **second proxied DNS record in the same Cloudflare account** pointing at
  tunnel UUID `60200874-…`, on a hostname no Access application covers.

The fix is the `access:` origin parameter block in `cloudflared/config.yml`,
which makes cloudflared validate the Access JWT before proxying. It ships
commented out because it needs the team name and the application's AUD tag, which
only exist once the Access application has been created. **Enable it as soon as
the app exists.**

Cross-account abuse is already blocked by Cloudflare: `cfargotunnel.com` only
proxies records belonging to the same account.

## Notes / known limitations

- **Rate limiting is per-client, but per-worker.** `ProxyFix` is configured with
  `TRUSTED_PROXY_COUNT=1`, so limits key on the real client address rather than
  the nginx container IP, and a client cannot mint a fresh bucket by supplying
  its own `X-Forwarded-For`. Storage is still in-memory and therefore per
  gunicorn worker, so the effective rate is roughly 4× what is configured. Set
  `RATELIMIT_STORAGE_URI=redis://…` for a limit that holds across the fleet.
  nginx applies its own `limit_req` zones in front of all this.
- **Before removing Cloudflare Access, read
  [PUBLIC-LAUNCH.md](PUBLIC-LAUNCH.md).** The `access:` block in
  `cloudflared/config.yml` rejects requests without a valid Access JWT; deleting
  the Access application without also disabling that block takes the site down
  for everyone.
- **125 seconds is the real analysis ceiling.** Cloudflare's Proxy Read Timeout
  is 125s and is not configurable below Enterprise. The 180s timeouts in
  `nginx.conf` sit above it deliberately — they only decide who gives up second.
  A cold-cache WHOIS-heavy analysis that runs longer returns a Cloudflare 524
  regardless of origin settings.
- **Upload size.** `client_max_body_size` (nginx, 25m) is kept in sync with the
  backend's `MAX_CONTENT_LENGTH` (`MAX_UPLOAD_MB`, 25MB) and with the
  frontend's `CONFIG.MAX_FILE_SIZE`. All sit under Cloudflare's 100MB proxy
  body limit. 25MB (not 50) because buffered request bodies spool to a tmpfs
  sized for the permitted concurrency. Note Cloudflare's Proxy *Write* Timeout of 30s — not
  adjustable on any plan — governs streaming the request body to the origin.
- The frontend sends `X-Requested-With: XMLHttpRequest` and
  `credentials: 'same-origin'` on every call. Both are required behind Access:
  the first makes an expired session return 401 instead of a login redirect, the
  second is what attaches the `CF_Authorization` cookie. Don't remove them.
