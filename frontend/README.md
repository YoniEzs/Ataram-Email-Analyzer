# Frontend

Static HTML/CSS/JavaScript UI with English/Hebrew support.

The API destination defaults to same-origin. To use a separate HTTPS backend,
edit `src/runtime-config.js`:

```javascript
window.ATARAM_CONFIG = { API_BASE_URL: 'https://api.example.com' };
```

The selected file and optional AbuseIPDB key are sent to that server. The UI
shows the destination and clears the key field after every request.

## Checks

```bash
npm ci
npm run check
npx playwright install chromium
python -m http.server 8765 --directory src
SMOKE_BASE_URL=http://localhost:8765 npm run test:e2e
```

The Docker image uses nginx to proxy `/api` and `/health` to the Compose backend.
