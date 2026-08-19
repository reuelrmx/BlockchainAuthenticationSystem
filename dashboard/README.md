# Dashboard Notes

For the HTTPS gateway demo, set the API base URL before starting the dashboard:

```bash
VITE_API_BASE_URL=https://localhost:3443 npm run dev
```

The browser must trust the local development certificate used by the backend
gateway before credentialed dashboard requests to `https://localhost:3443`
will succeed.

The local dashboard dev server can also be served over HTTPS:

```bash
DASHBOARD_HTTPS_ENABLED=true \
DASHBOARD_TLS_CERT_PATH=../backend/certs/server-cert.pem \
DASHBOARD_TLS_KEY_PATH=../backend/certs/server-key.pem \
VITE_API_BASE_URL=https://localhost:3443 \
npm run dev
```
