# Backend Gateway Notes

## Administrator Bootstrap

Create local administrator accounts with bcrypt password hashes:

```bash
npm run create-admin -- --username admin --role ADMIN --password-stdin
```

Pipe or type the password when prompted. The password is never printed by the
script, and the JSON store contains only bcrypt hashes.

## Local HTTPS

Generate a dedicated local development certificate:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/server-key.pem \
  -out certs/server-cert.pem \
  -days 30 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Then set:

```bash
HTTPS_ENABLED=true
HTTPS_PORT=3443
TLS_CERT_PATH=certs/server-cert.pem
TLS_KEY_PATH=certs/server-key.pem
ADMIN_COOKIE_SECURE=true
ADMIN_COOKIE_SAME_SITE=None
```

For curl tests, trust the certificate explicitly:

```bash
curl --cacert certs/server-cert.pem https://localhost:3443/api/health
```
