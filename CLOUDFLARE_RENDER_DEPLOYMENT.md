# Cloudflare Pages + Render Deployment

This split deployment sends every selected email from the user's browser to the
Render backend. Publish that fact and your retention/subprocessor policy before
using it with real data.

## Backend on Render

1. Create a Blueprint from this repository's `render.yaml`.
2. Confirm that it creates both the web service and a private Key Value service.
3. Provide optional `ABUSEIPDB_KEY` and `VIRUSTOTAL_API_KEY` values when prompted.
4. Set `CORS_ORIGINS` to the exact Cloudflare Pages and custom-domain origins.
5. Keep `autoDeployTrigger: checksPass`; do not switch back to deploy-on-commit.
6. Confirm `/health` over HTTPS and verify Redis-backed rate limiting in logs.

`render.yaml` installs only `requirements-prod.txt`, trusts one Render reverse
proxy and references the private Key Value connection string. If the service is
moved behind a different proxy chain, update `TRUST_PROXY_COUNT` carefully.

## Frontend on Cloudflare Pages

Use `frontend/src` as the static output directory. Before deployment, edit
`frontend/src/runtime-config.js`:

```javascript
window.ATARAM_CONFIG = {
  API_BASE_URL: 'https://your-render-service.onrender.com'
};
```

Remote URLs must use HTTPS. If the value is missing or invalid, the frontend
uses same-origin and does not fall back to an Ataram-operated API.

Recommended response headers for the static site:

```text
Content-Security-Policy: default-src 'self'; connect-src 'self' https://your-render-service.onrender.com; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

## Validation

- Browser UI displays the intended Render origin next to **Analysis server**.
- A 25 MB+ upload is rejected.
- AbuseIPDB key field is masked and cleared after a request.
- Backend requests from an unlisted origin do not receive CORS permission.
- Rate limits are shared across both Gunicorn workers.
- Render deploy starts only after GitHub checks pass.

CORS is not authentication. Add an authentication gateway or WAF before making
the API broadly reachable.
