# Cloud / low-storage Docker

Use this when the host has little free disk. **AI runs in Docker (Ollama).** Do not set `MODEL_BACKEND=huggingface` — that downloads multi-GB weights onto the host (often `C:\Users\…\.cache\huggingface`).

## Start

```text
copy .env.example .env
# set BOOTSTRAP_ADMIN_PASSWORD and POSTGRES_PASSWORD
docker compose -f docker-compose.cloud.yml up -d
```

Open `http://127.0.0.1:8080` on this host. Other phones/PCs: set `PUBLIC_BASE_URL=http://<this-machine-lan-ip>:8080` in `.env` and open that URL — never localhost on the other device. First boot pulls `tinyllama` into the `ollama-data` volume (~0.6 GB), not a 17 GB local HF cache.

## What is in the slim package

| Included | Left out (on purpose) |
|----------|------------------------|
| App + Postgres + Redis | Local Transformers / Unsloth |
| Ollama + tinyllama | OWASP ZAP + JRE |
| nmap + nuclei binary | Baked Nuclei template pack |
| Alembic on Postgres | Host `.venv`, `dist/`, Rust `target/` |

Rebuild context is filtered by `.dockerignore`. Image: `Dockerfile.slim`.

## Lab AI on the existing compose

```text
docker compose --profile redis --profile postgres --profile ai up -d
```

Then `MODEL_BACKEND=ollama` and `OLLAMA_BASE_URL=http://ollama:11434`.

## Honesty

This is a **lab/cloud starter**, not multi-AZ HA, not EV-signed installers, and not a 5k-agent proof. Nuclei templates and ZAP stay optional (`Dockerfile` with `INSTALL_ZAP=true`).
