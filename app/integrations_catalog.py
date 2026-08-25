"""Enterprise integration catalog — orchestrate mature tools; do not rebuild them.

Status legend:
  shipped   — usable in SecuraIQ today (import, API, or live path)
  import    — JSON/CSV import adapter ready
  path      — runs when binary is on PATH (local tools)
  planned   — documented target; connector not shipped yet
  commercial — optional paid product (customer brings license)
"""

from __future__ import annotations

from typing import Any


# MVP focus (limited budget / open-source-first)
MVP_STACK: list[dict[str, str]] = [
    {"category": "AI", "tool": "Qwen + OpenRouter / Ollama", "status": "shipped"},
    {"category": "SAST", "tool": "Semgrep", "status": "import"},
    {"category": "Code quality", "tool": "SecuraIQ Code", "status": "shipped"},
    {"category": "Secrets", "tool": "Gitleaks", "status": "import"},
    {"category": "Containers / SCA", "tool": "Trivy + Grype", "status": "import"},
    {"category": "IaC", "tool": "Checkov", "status": "import"},
    {"category": "DAST", "tool": "SecuraIQ Web Scanner + Nuclei", "status": "builtin+engine"},
    {"category": "Threat intel", "tool": "MITRE + NVD + CISA KEV", "status": "shipped"},
    {"category": "SIEM", "tool": "SecuraIQ SIEM", "status": "shipped"},
    {"category": "CMDB / inventory", "tool": "Network inventory", "status": "shipped"},
    {"category": "Hardening", "tool": "HardeningKitty + CIS Downloads", "status": "shipped"},
    {"category": "Automation", "tool": "n8n via webhooks", "status": "shipped"},
    {"category": "Automation", "tool": "Prefect job flows", "status": "shipped"},
    {"category": "Case mgmt", "tool": "TheHive", "status": "shipped"},
    {"category": "Identity", "tool": "Keycloak / Authentik (OIDC)", "status": "shipped"},
    {"category": "Database", "tool": "SQLite now → PostgreSQL", "status": "partial"},
    {"category": "Vector DB", "tool": "Chroma + Qdrant profile", "status": "shipped"},
    {"category": "Storage", "tool": "Local data/ → MinIO", "status": "partial"},
    {"category": "Backend", "tool": "FastAPI", "status": "shipped"},
    {"category": "Frontend", "tool": "Mission Control (static SPA)", "status": "shipped"},
]


CATALOG: list[dict[str, Any]] = [
    # AI
    {"id": "openai", "name": "OpenAI", "category": "ai", "status": "shipped", "hint": "Cloud chat via AI Router"},
    {"id": "anthropic", "name": "Anthropic", "category": "ai", "status": "planned", "hint": "Via OpenRouter or direct API later"},
    {"id": "gemini", "name": "Google Gemini", "category": "ai", "status": "planned", "hint": "Via OpenRouter or direct API later"},
    {"id": "groq", "name": "Groq", "category": "ai", "status": "shipped", "hint": "Fast cloud inference"},
    {"id": "openrouter", "name": "OpenRouter", "category": "ai", "status": "shipped", "hint": "Many models, one key"},
    {"id": "together", "name": "Together AI", "category": "ai", "status": "shipped"},
    {"id": "fireworks", "name": "Fireworks AI", "category": "ai", "status": "shipped"},
    {"id": "huggingface_api", "name": "Hugging Face Inference Providers", "category": "ai", "status": "shipped"},
    {"id": "ollama", "name": "Ollama (Qwen/Llama/Mistral/DeepSeek/Gemma)", "category": "ai", "status": "shipped"},
    {"id": "hermes", "name": "Nous Hermes Agent", "category": "ai", "status": "shipped", "hint": "Local Hermes gateway — MODEL_BACKEND=hermes / Settings"},
    {"id": "unsloth", "name": "Unsloth (local fine-tune / inference)", "category": "ai", "status": "shipped", "hint": "Optional local Unsloth backend + train script"},
    {"id": "huggingface", "name": "Hugging Face Transformers (local)", "category": "ai", "status": "shipped", "hint": "MODEL_BACKEND=huggingface — downloads HF_MODEL locally"},
    # SAST
    {"id": "sonarqube", "name": "SecuraIQ Code", "category": "sast", "status": "shipped", "hint": "Settings → SecuraIQ Code — sync engine issues or run SecuraIQ Code / code_scan tools"},
    {"id": "openvas", "name": "SecuraIQ Network Scanner", "category": "vuln_mgmt", "status": "shipped", "hint": "Built-in OpenVAS-class live scan — no GVM install"},
    {"id": "greenbone", "name": "Greenbone / OpenVAS report", "category": "vuln_mgmt", "status": "import", "hint": "Import GVM/OpenVAS report XML — POST /api/vulnerabilities/import"},
    {"id": "semgrep", "name": "Semgrep", "category": "sast", "status": "shipped", "hint": "Import JSON"},
    {"id": "codeql", "name": "CodeQL", "category": "sast", "status": "planned"},
    {"id": "bandit", "name": "Bandit", "category": "sast", "status": "shipped", "hint": "Python SAST JSON"},
    {"id": "eslint_security", "name": "ESLint Security", "category": "sast", "status": "planned"},
    {"id": "pmd", "name": "PMD", "category": "sast", "status": "planned"},
    {"id": "spotbugs", "name": "SpotBugs", "category": "sast", "status": "planned"},
    {"id": "brakeman", "name": "Brakeman", "category": "sast", "status": "planned"},
    # SCA
    {"id": "dependency_track", "name": "Dependency-Track", "category": "sca", "status": "planned"},
    {"id": "syft", "name": "Syft", "category": "sca", "status": "planned", "hint": "SBOM → feed Grype/Trivy"},
    {"id": "grype", "name": "Grype", "category": "sca", "status": "shipped", "hint": "Import JSON"},
    {"id": "trivy", "name": "Trivy", "category": "sca", "status": "shipped", "hint": "Import JSON"},
    {"id": "owasp_dc", "name": "OWASP Dependency-Check", "category": "sca", "status": "planned"},
    # Secrets
    {"id": "gitleaks", "name": "Gitleaks", "category": "secrets", "status": "shipped", "hint": "Import JSON"},
    {"id": "trufflehog", "name": "TruffleHog", "category": "secrets", "status": "planned"},
    {"id": "gitguardian", "name": "GitGuardian", "category": "secrets", "status": "commercial"},
    # Container / K8s
    {"id": "kubescape", "name": "Kubescape", "category": "container", "status": "planned"},
    {"id": "falco", "name": "Falco", "category": "container", "status": "planned"},
    {"id": "docker_scout", "name": "Docker Scout", "category": "container", "status": "commercial"},
    {"id": "kube_bench", "name": "kube-bench", "category": "kubernetes", "status": "planned"},
    {"id": "kube_hunter", "name": "kube-hunter", "category": "kubernetes", "status": "planned"},
    # IaC
    {"id": "checkov", "name": "Checkov", "category": "iac", "status": "shipped", "hint": "Import JSON"},
    {"id": "terrascan", "name": "Terrascan", "category": "iac", "status": "planned"},
    {"id": "tfsec", "name": "tfsec", "category": "iac", "status": "planned"},
    # DAST
    {"id": "zap", "name": "SecuraIQ Web Scanner", "category": "dast", "status": "shipped", "hint": "Built-in DAST — no ZAP install; optional ZAP_PREFER_API for daemon boost"},
    {"id": "burpsuite", "name": "Burp Suite", "category": "dast", "status": "shipped", "hint": "Import Scanner XML report (Pro/Enterprise 'Save issues' or Community) — POST /api/vulnerabilities/import"},
    {"id": "nuclei", "name": "Nuclei", "category": "dast", "status": "path"},
    {"id": "nikto", "name": "Nikto", "category": "dast", "status": "path"},
    # Vuln mgmt
    {"id": "nessus", "name": "Nessus", "category": "vuln_mgmt", "status": "commercial"},
    {"id": "qualys", "name": "Qualys", "category": "vuln_mgmt", "status": "commercial"},
    {"id": "rapid7", "name": "Rapid7 InsightVM", "category": "vuln_mgmt", "status": "commercial"},
    # Threat intel
    {"id": "mitre_attack", "name": "MITRE ATT&CK", "category": "intel", "status": "shipped", "hint": "Heuristics + knowledge"},
    {"id": "mitre_d3fend", "name": "MITRE D3FEND", "category": "intel", "status": "planned"},
    {"id": "cisa_kev", "name": "CISA KEV", "category": "intel", "status": "shipped"},
    {"id": "nvd", "name": "NVD", "category": "intel", "status": "shipped"},
    {"id": "cwe", "name": "CWE", "category": "intel", "status": "partial"},
    {"id": "capec", "name": "CAPEC", "category": "intel", "status": "planned"},
    {"id": "otx", "name": "AlienVault OTX", "category": "intel", "status": "shipped", "hint": "GET /api/intel/lookup"},
    {"id": "greynoise", "name": "GreyNoise", "category": "intel", "status": "shipped", "hint": "Community IP lookup"},
    {"id": "urlscan", "name": "URLScan.io", "category": "intel", "status": "shipped"},
    {"id": "msrc", "name": "Microsoft MSRC", "category": "intel", "status": "shipped"},
    {"id": "filterlists", "name": "FilterLists", "category": "intel", "status": "shipped"},
    {"id": "phishstats", "name": "PhishStats", "category": "intel", "status": "shipped"},
    {"id": "free_apis_security", "name": "Threat intel providers", "category": "intel", "status": "shipped", "hint": "GET /api/intel/free/catalog · GET /api/intel/lookup"},
    {"id": "awesome_threat_detection", "name": "Awesome Threat Detection", "category": "intel", "status": "shipped", "hint": "0x4D31 curated hunt/detect catalog — GET /api/intel/threat-detection"},
    {"id": "virustotal", "name": "VirusTotal", "category": "intel", "status": "partial", "hint": "Set VIRUSTOTAL_API_KEY"},
    {"id": "abuseipdb", "name": "AbuseIPDB", "category": "intel", "status": "partial", "hint": "Set ABUSEIPDB_API_KEY"},
    {"id": "shodan", "name": "Shodan", "category": "intel", "status": "partial", "hint": "Set SHODAN_API_KEY"},
    {"id": "hibp", "name": "Have I Been Pwned", "category": "intel", "status": "partial", "hint": "Set HIBP_API_KEY"},
    {"id": "urlhaus", "name": "URLhaus", "category": "intel", "status": "partial", "hint": "Set URLHAUS_API_KEY"},
    {"id": "emailrep", "name": "EmailRep", "category": "intel", "status": "partial", "hint": "Set EMAILREP_API_KEY"},
    {"id": "pulsedive", "name": "Pulsedive", "category": "intel", "status": "partial", "hint": "Set PULSEDIVE_API_KEY — GET /api/intel/lookup"},
    {"id": "malwarebazaar", "name": "MalwareBazaar", "category": "intel", "status": "partial", "hint": "Set MALWAREBAZAAR_API_KEY — GET /api/intel/lookup"},
    # SIEM / SOAR / IR / EDR
    {"id": "wazuh", "name": "SecuraIQ SIEM", "category": "siem", "status": "shipped", "hint": "Settings → SecuraIQ SIEM · Tools hub Sync SIEM / chat `run wazuh sync` · SOC workspace"},
    {"id": "openaudit", "name": "Network inventory", "category": "inventory", "status": "shipped", "hint": "Settings → Network inventory — sync discovered hosts into Assets"},
    {"id": "elastic", "name": "Elastic Stack", "category": "siem", "status": "planned"},
    {"id": "graylog", "name": "Graylog", "category": "siem", "status": "planned"},
    {"id": "security_onion", "name": "Security Onion", "category": "siem", "status": "planned"},
    {"id": "shuffle", "name": "Shuffle", "category": "soar", "status": "planned"},
    {"id": "stackstorm", "name": "StackStorm", "category": "soar", "status": "planned"},
    {"id": "n8n", "name": "n8n", "category": "soar", "status": "shipped", "hint": "Outbound webhooks"},
    {"id": "prefect", "name": "Prefect", "category": "soar", "status": "shipped", "hint": "Optional PREFECT_ENABLED — wraps kev_sync / xdr_sync / report_export flows"},
    {"id": "thehive", "name": "TheHive", "category": "ir", "status": "shipped", "hint": "Case sync → Incidents"},
    {"id": "cortex", "name": "Cortex", "category": "ir", "status": "planned"},
    {"id": "sophos", "name": "Sophos Central", "category": "edr", "status": "shipped", "hint": "Set SOPHOS_CLIENT_ID/SOPHOS_CLIENT_SECRET — alerts ingested via GET /api/xdr/status"},
    {"id": "crowdstrike", "name": "CrowdStrike Falcon", "category": "edr", "status": "shipped", "hint": "Set CROWDSTRIKE_CLIENT_ID/CROWDSTRIKE_CLIENT_SECRET — detections ingested via GET /api/xdr/status"},
    {"id": "sentinelone", "name": "SentinelOne", "category": "edr", "status": "shipped", "hint": "Set SENTINELONE_API_TOKEN/SENTINELONE_BASE_URL — threats ingested via GET /api/xdr/status"},
    {"id": "defender_endpoint", "name": "Microsoft Defender for Endpoint / XDR hunting", "category": "edr", "status": "shipped", "hint": "DEFENDER_* creds — alerts, TVM patches, and KQL advanced hunting (Graph ThreatHunting.Read.All or legacy AdvancedHunting.Read.All)"},
    {"id": "velociraptor", "name": "Velociraptor", "category": "edr", "status": "planned"},
    {"id": "osquery", "name": "Osquery", "category": "edr", "status": "planned"},
    # Cloud
    {"id": "aws_security_hub", "name": "AWS Security Hub", "category": "cloud", "status": "shipped", "hint": "Needs boto3 + AWS creds, or JSON import"},
    {"id": "azure_defender", "name": "Microsoft Defender for Cloud", "category": "cloud", "status": "shipped", "hint": "Entra app + subscription"},
    {"id": "gcp_scc", "name": "Google Security Command Center", "category": "cloud", "status": "shipped", "hint": "Needs google-cloud-securitycenter + SA JSON, or JSON import"},
    # Compliance frameworks (catalogs) — ids match data/frameworks/*.json
    {"id": "iso27001", "name": "ISO/IEC 27001:2022", "category": "compliance", "status": "shipped", "hint": "Full Annex A (93)"},
    {"id": "iso27701", "name": "ISO/IEC 27701:2025", "category": "compliance", "status": "shipped", "hint": "Standalone PIMS"},
    {"id": "nist_csf", "name": "NIST CSF 2.0", "category": "compliance", "status": "shipped"},
    {"id": "nist_800_53", "name": "NIST SP 800-53 Rev. 5", "category": "compliance", "status": "shipped", "hint": "Priority moderate-oriented subset"},
    {"id": "nist_800_171", "name": "NIST SP 800-171", "category": "compliance", "status": "shipped", "hint": "CUI protection practices"},
    {"id": "cmmc_l2", "name": "CMMC 2.0 Level 2", "category": "compliance", "status": "shipped"},
    {"id": "cis_controls", "name": "CIS Controls v8.1", "category": "compliance", "status": "shipped"},
    {"id": "cis_downloads", "name": "CIS Downloads", "category": "compliance", "status": "shipped", "hint": "Official CIS Benchmarks / CIS-CAT — https://downloads.cisecurity.org/#/"},
    {"id": "hardeningkitty", "name": "HardeningKitty", "category": "hardening", "status": "shipped", "hint": "Windows CIS/baseline audit — import report CSV or run Audit locally"},
    {"id": "soc2", "name": "SOC 2 TSC", "category": "compliance", "status": "shipped", "hint": "2017 TSC / 2022 points of focus"},
    {"id": "pci_dss", "name": "PCI DSS v4.0.1", "category": "compliance", "status": "shipped"},
    {"id": "hipaa", "name": "HIPAA Security Rule", "category": "compliance", "status": "shipped"},
    {"id": "gdpr", "name": "GDPR", "category": "compliance", "status": "shipped"},
    {"id": "nis2", "name": "NIS2 Directive", "category": "compliance", "status": "shipped"},
    {"id": "owasp_asvs", "name": "OWASP ASVS 5.0", "category": "compliance", "status": "shipped"},
    {"id": "owasp_top10", "name": "OWASP Top 10:2025", "category": "compliance", "status": "shipped"},
    # Identity / platform
    {"id": "keycloak", "name": "Keycloak", "category": "identity", "status": "shipped", "hint": "OIDC via /api/auth/oidc/*"},
    {"id": "authentik", "name": "Authentik", "category": "identity", "status": "shipped", "hint": "OIDC via /api/auth/oidc/*"},
    {"id": "authelia", "name": "Authelia", "category": "identity", "status": "planned"},
    {"id": "qdrant", "name": "Qdrant", "category": "vectors", "status": "shipped"},
    {"id": "weaviate", "name": "Weaviate", "category": "vectors", "status": "planned"},
    {"id": "milvus", "name": "Milvus", "category": "vectors", "status": "planned"},
    {"id": "pgvector", "name": "pgvector", "category": "vectors", "status": "planned"},
    {"id": "postgres", "name": "PostgreSQL", "category": "database", "status": "partial", "hint": "Optional DATABASE_URL — see docs/postgres-migration.md"},
    {"id": "redis", "name": "Redis", "category": "database", "status": "partial", "hint": "Optional REDIS_URL for job/cache profiles"},
    {"id": "minio", "name": "MinIO", "category": "storage", "status": "planned"},
    {"id": "r2", "name": "Cloudflare R2", "category": "storage", "status": "planned"},
    {"id": "rabbitmq", "name": "RabbitMQ", "category": "queue", "status": "planned"},
    {"id": "kafka", "name": "Kafka", "category": "queue", "status": "planned"},
    {"id": "nats", "name": "NATS", "category": "queue", "status": "planned"},
    {"id": "grafana", "name": "Grafana", "category": "observability", "status": "planned"},
    {"id": "prometheus", "name": "Prometheus", "category": "observability", "status": "planned"},
    {"id": "loki", "name": "Loki", "category": "observability", "status": "planned"},
    {"id": "otel", "name": "OpenTelemetry", "category": "observability", "status": "planned"},
    {"id": "sentry", "name": "Sentry", "category": "observability", "status": "partial", "hint": "Set SENTRY_DSN — app/error_reporting.py"},
    # SCM / PM / Comms
    {"id": "github", "name": "GitHub (webhook)", "category": "scm", "status": "shipped", "hint": "POST /api/integrations/github/webhook"},
    {"id": "gitlab", "name": "GitLab (webhook)", "category": "scm", "status": "shipped", "hint": "POST /api/integrations/gitlab/webhook — set GITLAB_WEBHOOK_SECRET"},
    {"id": "azure_devops", "name": "Azure DevOps", "category": "scm", "status": "planned"},
    {"id": "bitbucket", "name": "Bitbucket", "category": "scm", "status": "planned"},
    {"id": "stix_taxii", "name": "STIX 2.1 / TAXII 2.1", "category": "intel", "status": "shipped", "hint": "POST /api/intel/stix/ingest · GET export · TAXII poll"},
    {"id": "redis_realtime", "name": "Redis realtime bus", "category": "queue", "status": "partial", "hint": "Set REDIS_URL + pip install redis — multi-worker SSE fan-out"},
    {"id": "jira", "name": "Jira", "category": "pm", "status": "shipped"},
    {"id": "servicenow", "name": "ServiceNow", "category": "itsm", "status": "shipped", "hint": "Set SERVICENOW_INSTANCE_URL/USERNAME/PASSWORD — POST /api/integrations/servicenow/incident"},
    {"id": "linear", "name": "Linear", "category": "pm", "status": "planned"},
    {"id": "azure_boards", "name": "Azure Boards", "category": "pm", "status": "planned"},
    {"id": "trello", "name": "Trello", "category": "pm", "status": "planned"},
    {"id": "slack", "name": "Slack (webhook)", "category": "comms", "status": "shipped", "hint": "Set SLACK_WEBHOOK_URL — auto-alerts on critical vulns/incidents, not a native OAuth app"},
    {"id": "teams", "name": "Microsoft Teams", "category": "comms", "status": "shipped", "hint": "Set TEAMS_WEBHOOK_URL (Incoming Webhook connector)"},
    {"id": "discord", "name": "Discord", "category": "comms", "status": "planned"},
    {"id": "smtp", "name": "Email (SMTP)", "category": "comms", "status": "shipped", "hint": "Set SMTP_HOST/SMTP_FROM — see app/notifications.py"},
    # Docs
    {"id": "pdf", "name": "PDF parsing / export", "category": "documents", "status": "shipped"},
    {"id": "docx", "name": "DOCX", "category": "documents", "status": "shipped"},
    {"id": "xlsx", "name": "Excel", "category": "documents", "status": "shipped"},
    {"id": "markdown", "name": "Markdown", "category": "documents", "status": "shipped"},
    {"id": "ocr", "name": "OCR", "category": "documents", "status": "planned"},
]


CATEGORY_LABELS = {
    "ai": "AI providers",
    "sast": "Secure coding (SAST)",
    "sca": "Software composition",
    "secrets": "Secret detection",
    "container": "Container security",
    "kubernetes": "Kubernetes",
    "iac": "Infrastructure as Code",
    "dast": "DAST",
    "vuln_mgmt": "Vulnerability management",
    "intel": "Threat intelligence",
    "siem": "SIEM / logs",
    "inventory": "CMDB / inventory",
    "soar": "SOAR / automation",
    "ir": "Incident response",
    "edr": "Endpoint detection",
    "cloud": "Cloud security",
    "compliance": "Compliance frameworks",
    "hardening": "Hardening / baselines",
    "identity": "Identity & access",
    "vectors": "Vector database",
    "database": "Database",
    "storage": "Object storage",
    "queue": "Message queue",
    "observability": "Monitoring",
    "scm": "SCM",
    "pm": "Project management",
    "comms": "Communication",
    "documents": "Document processing",
}

ACTIONABLE_STATUSES = frozenset({"shipped", "import", "path", "path+import", "partial"})
# JSON/CSV import adapters that actually exist in app/scanner_adapters.py
IMPORT_SCANNER_IDS = frozenset(
    {
        "sonarqube",
        "semgrep",
        "bandit",
        "grype",
        "trivy",
        "gitleaks",
        "checkov",
        "zap",
        "burp",
        "greenbone",
        "openvas",
    }
)
# PATH / runner tools — no JSON import adapter; open the Tools palette instead
PATH_TOOL_IDS = frozenset({"nuclei", "nikto"})
SCANNER_IDS = IMPORT_SCANNER_IDS | PATH_TOOL_IDS
AI_IDS = frozenset(
    {
        "openai",
        "groq",
        "openrouter",
        "together",
        "fireworks",
        "huggingface_api",
        "huggingface",
        "ollama",
        "hermes",
        "unsloth",
    }
)
INTEL_IDS = frozenset({"mitre_attack", "cisa_kev", "nvd", "cwe"})
DOC_IDS = frozenset({"pdf", "docx", "xlsx", "markdown"})
WEBHOOK_IDS = frozenset({"n8n"})


def resolve_ui_action(item: dict[str, Any]) -> dict[str, str]:
    """Map catalog entry → UI Connect target (honest: planned stays disabled)."""
    status = item.get("status") or "planned"
    iid = item.get("id") or ""
    cat = item.get("category") or ""

    if status in {"planned", "commercial"}:
        return {"kind": "planned", "label": "Planned"}

    if iid == "jira":
        return {"kind": "settings", "label": "Configure Jira", "focus": "jira"}
    if iid in WEBHOOK_IDS or (cat == "soar" and status == "shipped"):
        return {"kind": "webhooks", "label": "Add webhook"}
    if iid in AI_IDS or cat == "ai":
        return {"kind": "settings", "label": "AI settings", "focus": "ai"}
    if iid == "sonarqube":
        return {"kind": "settings", "label": "Configure SecuraIQ Code", "focus": "sonarqube"}
    if iid == "openvas":
        return {"kind": "tools", "label": "Open SecuraIQ Network Scanner"}
    if iid in PATH_TOOL_IDS or status == "path":
        return {"kind": "tools", "label": "Open tools"}
    if iid in IMPORT_SCANNER_IDS or (
        status in {"import", "path+import"}
        and cat in {"sast", "sca", "secrets", "iac", "dast", "vuln_mgmt", "container"}
    ):
        return {"kind": "workspace", "target": "vulns", "label": "Import scan"}
    if cat == "edr" and status == "shipped":
        return {"kind": "settings", "label": "Configure EDR", "focus": "xdr"}
    if iid == "servicenow" or cat == "itsm":
        return {"kind": "settings", "label": "Configure ServiceNow", "focus": "servicenow"}
    if iid in {"slack", "teams", "smtp"} or cat == "comms":
        return {"kind": "settings", "label": "Configure", "focus": "comms"}
    if iid == "wazuh" or (cat == "siem" and status == "shipped"):
        return {"kind": "settings", "label": "Configure SecuraIQ SIEM", "focus": "wazuh"}
    if iid == "thehive" or (cat == "ir" and status == "shipped"):
        return {"kind": "settings", "label": "Configure TheHive", "focus": "thehive"}
    if cat == "cloud" and status == "shipped":
        return {"kind": "settings", "label": "Configure cloud posture", "focus": "cloud"}
    if iid == "openaudit" or cat == "inventory":
        return {"kind": "settings", "label": "Configure inventory", "focus": "inventory"}
    if iid in {"hardeningkitty", "cis_downloads"} or cat == "hardening":
        return {"kind": "workspace", "target": "frameworks", "label": "Open frameworks"}
    if iid in INTEL_IDS or cat == "intel" or iid == "awesome_threat_detection" or iid == "stix_taxii":
        return {"kind": "workspace", "target": "intel", "label": "Open intel"}
    if iid == "gitlab":
        return {"kind": "settings", "label": "Configure GitLab", "focus": "gitlab"}
    if iid == "github":
        return {"kind": "settings", "label": "Configure GitHub", "focus": "github"}
    if iid == "redis_realtime":
        return {"kind": "settings", "label": "Configure Redis", "focus": "redis"}
    if cat == "compliance":
        return {"kind": "workspace", "target": "frameworks", "label": "Open frameworks"}
    if iid in DOC_IDS or cat == "documents":
        return {"kind": "workspace", "target": "evidence", "label": "Open evidence"}
    if cat == "vectors" or iid == "qdrant":
        return {"kind": "settings", "label": "Settings", "focus": "ai"}
    if status in ACTIONABLE_STATUSES:
        return {"kind": "info", "label": "Available"}
    return {"kind": "planned", "label": "Planned"}


def resolve_enterprise_action(feat: dict[str, Any]) -> dict[str, str]:
    status = feat.get("status") or "planned"
    fid = feat.get("id") or ""
    if status == "planned":
        return {"kind": "planned", "label": "Planned"}
    if fid == "orgs" or fid == "multi_tenancy" or fid == "rbac":
        return {"kind": "workspace", "target": "orgs", "label": "Open orgs"}
    if fid in {"prefect", "automation"}:
        return {"kind": "workspace", "target": "automation", "label": "Open automation"}
    if fid == "webhooks":
        return {"kind": "webhooks", "label": "Webhooks"}
    if fid == "sso":
        return {"kind": "settings", "label": "Configure SSO", "focus": "oidc"}
    if fid == "scim":
        return {"kind": "settings", "label": "Configure SCIM", "focus": "scim"}
    if fid == "mfa":
        return {"kind": "settings", "label": "Configure MFA", "focus": "mfa"}
    if fid in {"api_keys", "audit"}:
        return {
            "kind": "settings",
            "label": "Open" if fid == "api_keys" else "View audit",
            "focus": "keys" if fid == "api_keys" else "audit",
        }
    return {"kind": "info", "label": "Available"}


def catalog_payload() -> dict[str, Any]:
    enriched: list[dict[str, Any]] = []
    for raw in CATALOG:
        item = {**raw, "ui_action": resolve_ui_action(raw)}
        enriched.append(item)

    by_cat: dict[str, list[dict[str, Any]]] = {}
    for item in enriched:
        by_cat.setdefault(item["category"], []).append(item)
    groups = [
        {
            "id": cat,
            "label": CATEGORY_LABELS.get(cat, cat),
            "items": items,
        }
        for cat, items in by_cat.items()
    ]
    shipped = sum(1 for i in enriched if i["status"] in ACTIONABLE_STATUSES)
    enterprise = [
        {**f, "ui_action": resolve_enterprise_action(f)}
        for f in (
            {"id": "multi_tenancy", "name": "Multi-tenancy", "status": "shipped"},
            {"id": "rbac", "name": "RBAC", "status": "shipped"},
            {"id": "sso", "name": "SSO (OIDC)", "status": "shipped"},
            {"id": "scim", "name": "SCIM provisioning", "status": "partial"},
            {"id": "mfa", "name": "MFA (TOTP)", "status": "shipped"},
            {"id": "audit", "name": "Audit logs", "status": "shipped"},
            {"id": "api_keys", "name": "API keys", "status": "shipped"},
            {"id": "webhooks", "name": "Webhooks", "status": "shipped"},
            {"id": "automation", "name": "Workflow automation", "status": "shipped"},
            {"id": "prefect", "name": "Prefect orchestration", "status": "shipped"},
            {"id": "report_schedules", "name": "Report scheduling", "status": "planned"},
            {"id": "white_label", "name": "White-labeling", "status": "planned"},
            {"id": "orgs", "name": "Organization & projects", "status": "shipped"},
        )
    ]
    mvp = [{**m, "ui_action": _mvp_ui_action(m)} for m in MVP_STACK]
    return {
        "doctrine": "Integrate mature tools — SecuraIQ orchestrates findings, evidence, and AI; it does not replace scanners or SIEMs.",
        "mvp": mvp,
        "counts": {
            "total": len(enriched),
            "actionable": shipped,
            "planned": sum(1 for i in enriched if i["status"] == "planned"),
        },
        "groups": groups,
        "agents": [
            {"name": "SOC Analyst", "mode": "blueteam", "prompt": "Act as SOC Analyst: summarize open incidents and critical vulns, recommend next 3 actions"},
            {"name": "XDR Analyst", "mode": "xdr", "prompt": "Act as XDR Analyst: correlate endpoint, identity, email, and network signals for our open critical findings into an attack chain with verdict and response steps"},
            {"name": "Threat Hunter", "mode": "threat_hunt", "prompt": "Act as Threat Hunter: prioritize hunts from our critical findings and intel watchlist"},
            {"name": "Malware Analyst", "mode": "blueteam", "prompt": "Act as Malware Analyst: outline a safe sandboxed triage workflow for a suspicious sample (authorized lab only)"},
            {"name": "Compliance Officer", "mode": "ciso", "prompt": "Act as Compliance Officer: review framework gaps and evidence needed this week"},
            {"name": "Risk Manager", "mode": "assess", "prompt": "Act as Risk Manager: prioritize open risks with residual risk and owners"},
            {"name": "Cloud Security Architect", "mode": "assess", "prompt": "Act as Cloud Security Architect: propose hardening for our top cloud assets"},
            {"name": "Secure Code Reviewer", "mode": "assess", "prompt": "Act as Secure Code Reviewer: triage imported SAST findings and recommend remediations"},
            {"name": "DevSecOps Engineer", "mode": "blueteam", "prompt": "Act as DevSecOps Engineer: design a CI pipeline that imports Trivy/Semgrep/Gitleaks into SecuraIQ"},
            {"name": "Incident Commander", "mode": "blueteam", "prompt": "Act as Incident Commander: draft an IR runbook for our open incidents"},
            {"name": "Executive Advisor", "mode": "ciso", "prompt": "Act as Executive Advisor: draft a board-ready security posture summary"},
        ],
        "enterprise_features": enterprise,
    }


def _mvp_ui_action(m: dict[str, str]) -> dict[str, str]:
    status = m.get("status") or "planned"
    tool = (m.get("tool") or "").lower()
    cat = (m.get("category") or "").lower()
    if status == "planned":
        return {"kind": "planned", "label": "Planned"}
    if "jira" in tool:
        return {"kind": "settings", "label": "Configure", "focus": "jira"}
    if "n8n" in tool or "webhook" in tool or cat == "automation":
        return {"kind": "webhooks", "label": "Connect"}
    if cat in {"sast", "code quality", "secrets", "containers / sca", "iac", "dast"} or status in {
        "import",
        "path+import",
    }:
        return {"kind": "workspace", "target": "vulns", "label": "Import"}
    if "intel" in cat or "mitre" in tool or "kev" in tool:
        return {"kind": "workspace", "target": "intel", "label": "Open"}
    if cat == "ai" or "ollama" in tool or "openrouter" in tool:
        return {"kind": "settings", "label": "AI settings", "focus": "ai"}
    if "wazuh" in tool or cat == "siem":
        return {"kind": "settings", "label": "Configure", "focus": "wazuh"}
    if "inventory" in cat or "cmdb" in cat or "network inventory" in tool:
        return {"kind": "settings", "label": "Configure", "focus": "inventory"}
    if "hardeningkitty" in tool or "cis download" in tool or cat == "hardening":
        return {"kind": "settings", "label": "Configure", "focus": "hardening"}
    if status in ACTIONABLE_STATUSES:
        return {"kind": "info", "label": "Available"}
    return {"kind": "planned", "label": "Planned"}
