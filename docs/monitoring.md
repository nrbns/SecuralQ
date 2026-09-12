# SecuraIQ — Monitoring & Error Reporting

Was **Todo** in the SaaS readiness checklist (`docs/commercial-roadmap.md`). Two independent pieces, both optional and additive:

## Metrics (`GET /api/metrics`)

Standard Prometheus text exposition format — no vendor lock-in, scrape it with whatever you already run.

```
# HELP securaiq_uptime_seconds Process uptime in seconds.
# TYPE securaiq_uptime_seconds gauge
securaiq_uptime_seconds 1234.56
# HELP securaiq_http_requests_total Total HTTP requests handled.
# TYPE securaiq_http_requests_total counter
securaiq_http_requests_total{route="api/dashboard"} 42
# HELP securaiq_http_responses_total Total HTTP responses by status class.
# TYPE securaiq_http_responses_total counter
securaiq_http_responses_total{class="2xx"} 40
securaiq_http_responses_total{class="4xx"} 2
# HELP securaiq_jobs_total Background jobs by status (last 500).
# TYPE securaiq_jobs_total gauge
securaiq_jobs_total{status="done"} 12
# HELP securaiq_stream_length Redis Streams main event log length (XLEN).
# TYPE securaiq_stream_length gauge
securaiq_stream_length -1
# HELP securaiq_stream_dlq_length Redis Streams dead-letter queue length.
# TYPE securaiq_stream_dlq_length gauge
securaiq_stream_dlq_length -1
# HELP securaiq_agents_total Enrolled agents visible to local/lab scope (last 500).
# TYPE securaiq_agents_total gauge
securaiq_agents_total 3
```

Stream gauges use `-1` when Redis is not configured (lab in-process bus). With `REDIS_URL`, values reflect XLEN / pending / DLQ / lag from `stream_monitor_snapshot()`.

**Admin board:** `GET /api/admin/health` (admin role) includes `event_bus`, `agent_gateway`, and `agent_crypto` posture alongside API/DB/Redis.

**Prometheus scrape config:**

```yaml
scrape_configs:
  - job_name: securaiq
    scrape_interval: 30s
    static_configs:
      - targets: ["127.0.0.1:8080"]
    metrics_path: /api/metrics
```

If `AUTH_ENABLED=true`, `/api/metrics` requires auth like everything else under `/api/*` — either scrape from a trusted network segment, or issue a dedicated API key for Prometheus via `POST /api/auth/api-keys` and set it as a bearer token in the scrape config.

**Grafana:** point a Prometheus data source at the above and build panels off `securaiq_http_requests_total`, `securaiq_http_responses_total{class="4xx|5xx"}` (error rate), and `securaiq_jobs_total` (background queue health). No pre-built dashboard is shipped yet — the metric names above are stable to build one against.

## Error reporting (Sentry — optional)

Metrics answer "how much/how often"; error reporting answers "what broke and where" (stack traces, breadcrumbs, release correlation). Enable it with:

```env
SENTRY_DSN=https://xxxx@xxxx.ingest.sentry.io/xxxx
SENTRY_ENVIRONMENT=beta
SENTRY_TRACES_SAMPLE_RATE=0.1
```

```bash
pip install sentry-sdk
```

`app/error_reporting.py::init_error_reporting()` runs at startup and no-ops cleanly if `SENTRY_DSN` is unset or `sentry-sdk` isn't installed — this is genuinely optional, not a hidden requirement.

## What's still manual

- No pre-built Grafana dashboard JSON is shipped — build one from the metric names above.
- No alerting rules are pre-configured (e.g. "page me if 5xx rate > 5%") — that's environment-specific and belongs in your Prometheus Alertmanager / Grafana alerting config, not hardcoded into the app.
- Log aggregation beyond stdout JSON (see `docs/backup-dr.md` and `app/siem.py`) is the operator's log pipeline (Vector, Fluent Bit, Docker log driver, etc.) — SecuraIQ emits structured lines, it doesn't ship its own log shipper.
