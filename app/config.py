from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from app.paths import project_root

_PROJECT_ROOT = project_root()
_ENV_FILE = _PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # Always load .env from the repo root — not from whatever cwd started Python.
        env_file=str(_ENV_FILE) if _ENV_FILE.is_file() else None,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    model_backend: str = "ollama"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "tinyllama"
    openai_compat_base_url: str = "http://localhost:1234/v1"
    openai_compat_model: str = "local-model"
    openai_compat_api_key: str = "lm-studio"
    # Cloud OpenAI-compatible providers (AI Router)
    router_enabled: bool = True
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openrouter_api_key: str = ""
    openrouter_model: str = "openai/gpt-4o-mini"
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    together_api_key: str = ""
    together_model: str = "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"
    fireworks_api_key: str = ""
    fireworks_model: str = "accounts/fireworks/models/llama-v3p1-70b-instruct"
    router_code_model: str = "qwen/qwen2.5-coder-32b-instruct"
    router_compliance_model: str = "gpt-4o-mini"
    router_report_model: str = "gpt-4o-mini"
    router_intel_model: str = "llama-3.3-70b-versatile"
    router_cloud_model: str = "openai/gpt-4o-mini"
    ollama_coder_model: str = ""  # e.g. qwen2.5-coder:7b when pulled
    hermes_base_url: str = "http://127.0.0.1:8642/v1"
    hermes_model: str = "hermes-agent"
    hermes_api_key: str = "change-me-local-dev"
    # Stable memory scope for Hermes (X-Hermes-Session-Key); optional
    hermes_session_key: str = ""  # set in Settings / .env; no shared default
    hermes_show_tool_progress: bool = True
    hf_model: str = "Qwen/Qwen2.5-0.5B-Instruct"
    hf_token: str = ""
    # Hosted HF inference (router) — reuses hf_token, no local model download
    huggingface_api_model: str = "meta-llama/Llama-3.1-8B-Instruct"
    # Unsloth — https://github.com/unslothai/unsloth
    unsloth_model: str = "unsloth/Qwen2.5-0.5B-Instruct-bnb-4bit"
    unsloth_adapter_dir: str = "./models/securaiq-unsloth"
    unsloth_max_seq_length: int = 2048
    unsloth_load_in_4bit: bool = True
    host: str = "127.0.0.1"  # localhost-only by default; use HOST=0.0.0.0 or start -Lan for LAN
    port: int = 8080
    # lab = open local OK; production = AUTH_ENABLED required, no open bind without auth
    deployment_mode: str = "lab"
    allow_open_lan: bool = False  # if true, allow AUTH_ENABLED=false on 0.0.0.0 (never for public internet)
    session_days: int = 14
    password_reset_ttl_hours: int = 2
    chroma_persist_dir: str = "./data/chroma"
    data_dir: str = "./data"
    embedding_model: str = "all-MiniLM-L6-v2"
    # When false, knowledge files are not indexed until the user clicks Re-index (empty/fast start).
    rag_auto_ingest: bool = False
    # When true and auth is off, wipe the live workspace on each server start (nil / zero UI).
    # Previous scans are archived under data/archive first (no-loss). Default off so data persists.
    workspace_zero_start: bool = False
    # When true and HOST is 0.0.0.0, queue a discovery scan of THIS host so phones
    # load assets without a second click. Never scans other LAN devices.
    lan_auto_scan: bool = False
    # Optional Qdrant vector store (compose profile). Empty = use Chroma only.
    qdrant_url: str = ""
    qdrant_collection: str = "securaiq_knowledge"
    # Live web search for Research mode (DuckDuckGo HTML, or SearXNG if set)
    web_search_enabled: bool = True
    web_search_max_results: int = 8
    web_search_timeout_sec: float = 5.0
    searxng_url: str = ""
    # Network assess: light TCP/HTTP probes (+ nmap if installed)
    net_assess_enabled: bool = True
    net_assess_use_nmap: bool = True
    # Local security tools registry (builtins + PATH binaries)
    local_tools_enabled: bool = True
    local_tools_auto: bool = True  # auto light tools on assess / when target set
    local_tools_allow_heavy: bool = False  # nuclei/nikto/ffuf only when instructed
    # SecuraIQ Web Scanner (built-in) + optional ZAP REST API boost
    zap_api_url: str = "http://127.0.0.1:8090"
    zap_api_key: str = ""
    zap_prefer_api: bool = False  # optional ZAP daemon boost; built-in engine always runs
    # Commercial / team foundations
    auth_enabled: bool = False
    auth_allow_register: bool = False  # invite-only when auth is on; enable explicitly if needed
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""
    upload_max_mb: int = 15
    upload_quota_mb_per_user: int = 500
    # Jira integration (optional)
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project_key: str = ""
    # Notifications: in-app always on; email is optional (SMTP)
    notifications_enabled: bool = True
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = "securaiq@localhost"
    smtp_use_tls: bool = True
    # Optional threat-intel API keys (AbuseIPDB, VT, Shodan, OTX, …)
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    otx_api_key: str = ""
    urlscan_api_key: str = ""
    hibp_api_key: str = ""
    greynoise_api_key: str = ""
    pulsedive_api_key: str = ""
    malwarebazaar_api_key: str = ""
    emailrep_api_key: str = ""
    github_webhook_secret: str = ""
    gitlab_webhook_secret: str = ""
    # STIX/TAXII 2.1 — optional pull from a TAXII collection (MISP/ISAC/etc.)
    taxii_api_root: str = ""  # e.g. https://cti.example/taxii2/root
    taxii_collection_id: str = ""
    taxii_username: str = ""
    taxii_password: str = ""
    # Shared secret for lab/vendor push ingest (XDR + Wazuh webhooks).
    # Header: X-SecuraIQ-Ingest. Required when AUTH_ENABLED=true.
    ingest_webhook_secret: str = ""
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""
    servicenow_instance_url: str = ""
    servicenow_username: str = ""
    servicenow_password: str = ""
    urlhaus_api_key: str = ""  # abuse.ch Auth-Key
    # MFA / SSO (beta enterprise)
    mfa_required_for_admin: bool = False
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "http://127.0.0.1:8080/api/auth/oidc/callback"
    oidc_scopes: str = "openid profile email"
    # SCIM 2.0 user provisioning scaffold (Keycloak/Okta/Entra) — beta
    scim_enabled: bool = False
    scim_token: str = ""  # Bearer token IdPs send; required when scim_enabled
    # Infra (beta SaaS — Postgres/Redis via compose profiles)
    database_url: str = ""  # empty = SQLite at DATA_DIR/securaiq.db
    redis_url: str = ""
    # REALTIME v1 Task B — Redis Streams durable log (when REDIS_URL is set)
    redis_stream_key: str = "securaiq:events"
    redis_stream_maxlen: int = 10000  # approximate trim on XADD
    # Phase 1 durability — DLQ + pending reclaim (no-op when REDIS_URL empty)
    redis_stream_dlq_key: str = "securaiq:events:dlq"
    redis_stream_max_deliveries: int = 5  # then DLQ + XACK
    redis_stream_claim_idle_ms: int = 60000  # XAUTOCLAIM idle threshold
    realtime_replay_buffer: int = 2000  # in-process ring buffer for Last-Event-ID (lab)
    # RT-02 opt-in: Streams as authoritative multi-worker SSE fan-out (skip pub/sub).
    # Default False — keep pub/sub until operators enable Streams fanout.
    realtime_streams_fanout: bool = False
    # RT-06: prune processed event_id rows older than N days (SQLite/Postgres table).
    event_idempotency_prune_days: int = 7
    # Native agent gateway (WebSocket) + replay protection
    agent_gateway_enabled: bool = True
    agent_require_replay_protection: bool = False  # true in production: require ts+nonce
    agent_command_ttl_sec: int = 86400
    agent_command_ack_timeout_sec: int = 180
    agent_replay_max_skew_sec: int = 300
    agent_signing_key: str = ""  # HMAC for sealed commands; empty = derived lab default
    # Command seal algorithm: hmac (default) | ed25519 | both.
    # HMAC stays default so existing labs keep working. ed25519/both need keys.
    agent_command_signing_alg: str = "hmac"
    # RT-17: when True, gateway refuses unsigned seals and stamps require_verify.
    # Default False so labs keep working without production crypto ops.
    agent_require_command_signature: bool = False
    # Optional Ed25519 (REALTIME Task J) — opt-in via agent_command_signing_alg.
    # PEM or raw base64url; empty = helpers generate ephemeral keys for tests only.
    agent_ed25519_private_key: str = ""
    agent_ed25519_public_key: str = ""
    # production / DEPLOYMENT_MODE=production requires PostgreSQL (never SQLite for SaaS)
    require_postgres_in_production: bool = True
    # Security hardening
    cors_origins: str = "http://127.0.0.1:8080,http://localhost:8080"  # restrictive; use * only with LAN bind
    # Session cookie (Bearer token still supported; cookie preferred behind HTTPS)
    session_cookie_name: str = "securaiq_session"
    cookie_secure: bool = False  # set true (or auto via production) for HTTPS-only cookies
    cookie_samesite: str = "lax"  # lax | strict | none
    cookie_httponly: bool = True
    force_https_headers: bool = False  # HSTS + secure cookie defaults when true
    rate_limit_per_minute: int = 180
    rate_limit_auth_per_minute: int = 20
    rate_limit_chat_per_minute: int = 45
    # Billing / usage metering
    billing_enforcement_enabled: bool = False  # soft by default — enable once plans are real
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_pro: str = ""
    stripe_price_team: str = ""
    # Error reporting / monitoring (optional)
    sentry_dsn: str = ""
    sentry_traces_sample_rate: float = 0.1
    sentry_environment: str = "alpha"
    # SIEM / security log forwarding (optional — audit events always log locally as JSON)
    siem_forward_enabled: bool = False
    siem_forward_url: str = ""       # generic HTTP sink or Splunk HEC endpoint
    siem_hec_token: str = ""         # set if siem_forward_url is a Splunk HEC collector
    siem_syslog_host: str = ""
    siem_syslog_port: int = 514
    # XDR / EDR connectors (optional — each vendor activates only when its own
    # credentials are set; sync interval applies to all configured vendors)
    xdr_sync_interval_sec: int = 1800
    xdr_auto_create_incidents: bool = True  # critical/high detections -> incidents table
    # Prefect orchestration (optional — local asyncio jobs remain the default)
    prefect_enabled: bool = False
    prefect_api_url: str = ""  # empty = ephemeral local Prefect when enabled
    # Wazuh SIEM (manager API + optional Indexer for alert pull)
    wazuh_base_url: str = ""  # e.g. https://wazuh.example:55000
    wazuh_user: str = ""
    wazuh_password: str = ""
    wazuh_verify_ssl: bool = False
    wazuh_sync_interval_sec: int = 1800
    wazuh_indexer_url: str = ""  # e.g. https://indexer.example:9200
    wazuh_indexer_user: str = ""
    wazuh_indexer_password: str = ""
    # Open-AudIT (network inventory — cookie session API)
    openaudit_base_url: str = ""  # e.g. http://192.168.56.10
    openaudit_user: str = ""
    openaudit_password: str = ""
    openaudit_api_prefix: str = "/open-audit/index.php"
    openaudit_verify_ssl: bool = False
    openaudit_sync_interval_sec: int = 3600
    # HardeningKitty (Windows CIS / baseline audit — local PowerShell module)
    hardeningkitty_module_path: str = ""  # dir containing HardeningKitty.psm1
    hardeningkitty_list: str = ""  # optional finding list filename or absolute path
    # SonarQube / SonarCloud (SAST — live issues API + JSON import)
    sonarqube_base_url: str = ""  # e.g. https://sonar.example.com or https://sonarcloud.io
    sonarqube_token: str = ""
    sonarqube_project_key: str = ""  # optional componentKeys filter
    sonarqube_verify_ssl: bool = True
    sonarqube_sync_interval_sec: int = 3600
    sonarqube_issue_types: str = "VULNERABILITY,SECURITY_HOTSPOT,BUG"
    # TheHive case management
    thehive_base_url: str = ""
    thehive_api_key: str = ""
    thehive_verify_ssl: bool = False
    thehive_sync_interval_sec: int = 1800
    # Cloud posture (AWS Security Hub / Azure Defender for Cloud / GCP SCC)
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_region: str = "us-east-1"
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""
    azure_subscription_id: str = ""
    gcp_project_id: str = ""
    gcp_service_account_json: str = ""  # path to SA JSON
    cloud_posture_sync_interval_sec: int = 3600
    # Sophos Central (OAuth2 client credentials — id.sophos.com)
    sophos_client_id: str = ""
    sophos_client_secret: str = ""
    # CrowdStrike Falcon (OAuth2 client credentials)
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_base_url: str = "https://api.crowdstrike.com"
    # Hold open the Falcon Streaming API for real-time push instead of only
    # polling every xdr_sync_interval_sec; needs the "Event streams: Read"
    # scope on the API client. Auto-backs off to the poll job if unavailable.
    crowdstrike_streaming_enabled: bool = True
    # Sophos / SentinelOne / Defender have no Falcon-style client-held stream.
    # Near-realtime poll (default 60s) supplements the slow xdr_sync job; true
    # push without polling still works via POST /api/xdr/ingest.
    xdr_near_realtime_enabled: bool = True
    xdr_near_realtime_interval_sec: int = 60
    # Remote SSH OS patch probes (authorized lab assets — key-based SSH only)
    ssh_patch_enabled: bool = False
    ssh_patch_user: str = "root"
    ssh_patch_key_path: str = ""  # path to private key; empty = default ssh agent keys
    ssh_patch_max_hosts: int = 15
    # Scheduled software inventory sync (SIEM/XDR/inventory + rebuild)
    software_sync_auto_enabled: bool = True
    software_sync_interval_sec: int = 3600
    # SentinelOne (static API token)
    sentinelone_api_token: str = ""
    sentinelone_base_url: str = ""  # e.g. https://<tenant>.sentinelone.net
    # Microsoft Defender for Endpoint (Entra ID app registration)
    defender_tenant_id: str = ""
    defender_client_id: str = ""
    defender_client_secret: str = ""
    # Advanced hunting: auto (Graph then legacy), graph, or legacy MTP API
    # https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery
    # https://learn.microsoft.com/en-us/defender-xdr/api-advanced-hunting
    defender_hunting_api: str = "auto"


settings = Settings()


def _absolutize_relative_paths() -> None:
    """Make data/chroma/adapter paths absolute so the app works from any cwd."""
    from app.paths import resolve_path

    for name in ("data_dir", "chroma_persist_dir", "unsloth_adapter_dir"):
        raw = getattr(settings, name, None)
        if not isinstance(raw, str) or not raw.strip():
            continue
        setattr(settings, name, str(resolve_path(raw)))
    gcp = (getattr(settings, "gcp_service_account_json", "") or "").strip()
    if gcp and not gcp.startswith("{"):
        # Path to SA JSON (not inline JSON)
        try:
            setattr(settings, "gcp_service_account_json", str(resolve_path(gcp)))
        except Exception:
            pass
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)


try:
    _absolutize_relative_paths()
except Exception:
    pass


def _decrypt_secret_fields_in_place() -> None:
    """Secret fields written via Settings/env_persist may be stored as
    `enc:v1:...` (see app/secrets_crypto.py). Pydantic loads the raw string
    from .env — this decrypts it in place right after construction so the
    rest of the app only ever sees plaintext in memory.
    """
    from app.secrets_crypto import decrypt_value, is_encrypted

    for name in type(settings).model_fields:
        value = getattr(settings, name, None)
        if isinstance(value, str) and is_encrypted(value):
            setattr(settings, name, decrypt_value(value))


try:
    _decrypt_secret_fields_in_place()
except Exception:
    # Never block app startup on crypto issues (e.g. cryptography not
    # installed yet in an older venv) — worst case, an encrypted value is
    # treated as "not set" until the dependency is installed.
    pass


def cors_origin_list() -> list[str]:
    raw = (settings.cors_origins or "").strip()
    host = (settings.host or "").strip()
    open_bind = host in {"0.0.0.0", "::", "[::]"}
    # Lab LAN: phones open http://<lan-ip>:port — same-origin usually, but
    # allow * when the operator explicitly opted into open LAN.
    if raw == "*" or (open_bind and getattr(settings, "allow_open_lan", False)):
        return ["*"]
    if not raw:
        origins = [
            f"http://127.0.0.1:{settings.port}",
            f"http://localhost:{settings.port}",
        ]
    else:
        origins = [o.strip() for o in raw.split(",") if o.strip()]
    if open_bind:
        try:
            from app.platform_info import platform_info

            for url in platform_info().get("lan_urls") or []:
                if url not in origins:
                    origins.append(url)
        except Exception:
            pass
    return origins
