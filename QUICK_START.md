# Quick Start

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:3000`. Check the combined frontend/backend health route:

```bash
curl -fsS http://localhost:3000/health
```

Stop and remove the containers:

```bash
docker compose down
```

The browser talks to same-origin `/api/v1`. The backend is available only to
the Compose network, and Redis shares limits/cache data across workers.

## Important

- Do not upload sensitive mail until you have read `PRIVACY.md`.
- A low score is not a safety guarantee.
- Internet-facing deployments need TLS, authentication/WAF controls and a
  published retention policy.
- For a separate static frontend, set `frontend/src/runtime-config.js`
  explicitly and update backend `CORS_ORIGINS`.
