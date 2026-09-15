# SecuraIQ — TLS / reverse proxy deploy

DNS + certificate issuance are operator steps. App configs are ready under `deploy/`.

## Recommended (Caddy)

1. Point `A`/`AAAA` for `securaiq.yourdomain.com` at the host
2. Edit `deploy/Caddyfile` — replace the domain
3. Ensure SecuraIQ listens on `127.0.0.1:8080` (or compose published only to localhost via proxy)
4. Set `CORS_ORIGINS=https://securaiq.yourdomain.com`
5. Run:

```bash
caddy run --config deploy/Caddyfile
```

SSE paths (`/api/chat`, `/api/realtime`, `/api/tools/run/stream`) already flush without buffering.

## Alternative (nginx + certbot)

1. `certbot certonly --nginx -d securaiq.yourdomain.com`
2. Copy `deploy/nginx.conf.example` → site config; fix cert paths + domain
3. `nginx -t && systemctl reload nginx`

## Checklist

- [ ] HTTPS redirects from HTTP
- [ ] HSTS header present
- [ ] Chat streaming works over HTTPS
- [ ] `CORS_ORIGINS` matches the HTTPS origin (no `*`)
- [ ] App not exposed on `:8080` to the public internet (proxy only)

## Agent mTLS (optional production)

Client certificates are terminated at the reverse proxy. The app trusts
`X-SSL-Client-Verify` / `X-SSL-Client-Fingerprint` only when bound to localhost.

1. Enable enroll-time lab certs: `AGENT_MTLS_ENABLED=true` (or issue certs via your MDM/CA)
2. Install CA at `/etc/securaiq/mtls/ca.crt`
3. Use `deploy/nginx-mtls.conf.example` or `deploy/Caddyfile.mtls`
4. Set on the app:
   - `AGENT_MTLS_PROXY_VERIFY=true` — require successful client verify on agent API
   - `AGENT_MTLS_REQUIRE_FINGERPRINT_MATCH=true` — also match stored enroll fingerprint (stricter)
5. Roll out: start with nginx `ssl_verify_client optional` / Caddy `mode request`, then require

Bearer + HMAC remain valid; mTLS is additive identity at the edge.
