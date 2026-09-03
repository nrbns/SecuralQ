from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import Annotated, Any, Literal

from contextlib import asynccontextmanager

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from app.config import cors_origin_list, settings
from app.rate_limit import RateLimitMiddleware
from app.guardrails import check_request
from app.model_client import model_client
from app.prompts import (
    APPSEC_MODE_PROMPT,
    ASSESS_MODE_PROMPT,
    AWARENESS_MODE_PROMPT,
    BLUETEAM_MODE_PROMPT,
    CISO_MODE_PROMPT,
    CLOUD_MODE_PROMPT,
    CTF_MODE_PROMPT,
    IR_MODE_PROMPT,
    LAB_MODE_PROMPT,
    LAB_OFFENSIVE_MODE_PROMPT,
    MALWARE_ANALYSIS_MODE_PROMPT,
    PURPLE_MODE_PROMPT,
    REDTEAM_MODE_PROMPT,
    RESEARCH_MODE_PROMPT,
    SEARCH_BEHAVIOR_PROMPT,
    SYSTEM_PROMPT,
    TABLETOP_MODE_PROMPT,
    THINKING_QUALITY_PROMPT,
    THREAT_HUNT_MODE_PROMPT,
    TOOLS_BEHAVIOR_PROMPT,
    XDR_MODE_PROMPT,
)
from app.auth import AuthUser, resolve_user
from app.backends import hermes_reachable, openai_compat_reachable
from app.commercial_api import bootstrap_auth, require_user, router as commercial_router
from app.integrations_api import router as integrations_router
from app.gap_api import router as gap_router
from app.enterprise_api import router as enterprise_router
from app.ops_api import router as ops_router
from app.scans_api import router as scans_router
from app.archive_api import router as archive_router
from app.commercial_ext_api import router as commercial_ext_router
from app.platform_api import router as platform_router
from app.billing_api import router as billing_router
from app.xdr_api import router as xdr_router
from app.agents_api import router as agents_router
from app.evidence_api import router as evidence_router
from app.risk_api import router as risk_router
from app.wazuh_api import router as wazuh_router
from app.openaudit_api import router as openaudit_router
from app.hardeningkitty_api import router as hardeningkitty_router
from app.thehive_api import router as thehive_router
from app.cloud_posture_api import router as cloud_posture_router
from app.sonarqube_api import router as sonarqube_router
from app.scim_api import router as scim_router
from app.stix_api import router as stix_router
from app.commercial_ext import ensure_org_schema
from app.gap_analysis import ensure_gap_schema
from app.db import init_schema
from app.knowledge_graph import ensure_graph_schema
from app.automation import ensure_webhook_schema
from app.intel_feeds import ensure_intel_cache_schema
from app.jobs import start_background_jobs, stop_background_jobs
from app.error_reporting import init_error_reporting
from app.metrics import incr, incr_status, render_prometheus
from app.env_persist import update_env_value
from app.fine_tune.job import finetune_job, launch_unsloth_job
from app.hermes_client import fetch_hermes_status
from app.net_assess import assess_from_request, extract_targets, format_assess_context
from app.ollama_models import RECOMMENDED_MODELS, fetch_ollama_tags, list_installed_models, pull_model
from app.platform_info import platform_info
from app.probe import probe_backends
from app.rag import rag_engine
from app.settings_api import apply_settings_patch, public_settings
from app.tools import (
    format_tools_context,
    get_all_tool_versions,
    iter_security_tools,
    list_tools_status,
    run_security_tools,
)
from app.uploads import attachment_context
from app.web_search import format_search_context, web_search
from app.workspace import append_message, memory_context_raw

from app.paths import resource_root

STATIC_DIR = resource_root() / "static"


def _encode_citations(sources: list[dict]) -> str:
    """Base64-encode the citations payload so it's safe to embed inside a
    `[[citations:...]]` bracket marker in a plain-text SSE stream (raw JSON
    would contain `]` characters that break the existing marker regexes)."""
    raw = json.dumps(sources, ensure_ascii=False)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_schema()
        from app.auth import assert_safe_deployment_auth

        assert_safe_deployment_auth()
        bootstrap_auth()
        ensure_gap_schema()
        ensure_org_schema()
        from app.tenancy import ensure_tenant_schema

        ensure_tenant_schema()
        ensure_graph_schema()
        ensure_webhook_schema()
        ensure_intel_cache_schema()
        from app.openaudit import ensure_schema as ensure_openaudit_schema

        ensure_openaudit_schema()
        from app.hardeningkitty import ensure_schema as ensure_hk_schema

        ensure_hk_schema()
        from app.wazuh import ensure_schema as ensure_wazuh_schema

        ensure_wazuh_schema()
        from app.software_inventory import ensure_schema as ensure_software_schema

        ensure_software_schema()
        from app.scan_engine.models import ensure_scans_schema
        import app.scan_engine.jobs  # noqa: F401 — register scan_execute handler
        import app.combo_assessment  # noqa: F401 — register combo_assessment handler

        ensure_scans_schema()
        try:
            from app.bootstrap import bootstrap

            boot = bootstrap()
            be = boot.get("backend") or {}
            layout = boot.get("layout") or {}
            print(
                f"Data layout ready: evidence={layout.get('evidence')} archive={layout.get('archive')}"
            )
            print(f"Backend: {be.get('backend')} ({be.get('reason')})")
            if be.get("hint"):
                print(be["hint"])
        except Exception as exc:
            print(f"Data layout skipped: {exc}")
    except Exception as exc:
        print(f"DB/auth bootstrap: {exc}")
        # Hard-fail unsafe production auth misconfig
        if "AUTH_ENABLED" in str(exc) or "DEPLOYMENT_MODE" in str(exc) or "HOST=" in str(exc) or "DATABASE_URL" in str(exc):
            raise
    try:
        from app.enterprise import apply_workspace_zero_start

        apply_workspace_zero_start()
    except Exception as exc:
        print(f"Workspace zero-start skipped: {exc}")
    try:
        # Knowledge index is opt-in (Re-index) so first boot stays empty / fast
        if getattr(settings, "rag_auto_ingest", False):
            count = rag_engine.ingest_directory(force=False)
            if count:
                print(f"RAG: indexed {count} knowledge documents.")
            else:
                existing = rag_engine.document_count()
                if existing:
                    print(f"RAG: using existing index ({existing} docs).")
        else:
            existing = rag_engine.document_count()
            print(
                f"RAG: auto-ingest off ({existing} docs on disk). Use Re-index when ready."
            )
    except Exception as exc:
        print(f"RAG ingest skipped: {exc}")
    if settings.model_backend == "huggingface":
        print(f"HuggingFace backend: {settings.hf_model} (loads on first chat — no preload)")
    elif settings.model_backend == "unsloth":
        print(f"Unsloth backend: {settings.unsloth_model} (loads on first chat)")
    elif settings.model_backend == "hermes":
        print(f"Hermes backend: {settings.hermes_base_url}")
    print(f"Auth: {'ENABLED' if settings.auth_enabled else 'disabled (local open mode)'}")
    start_background_jobs()
    print("Background jobs: worker + periodic scheduler started (KEV sync every 6h).")
    try:
        from app.lan_sync import is_lan_bind, maybe_queue_lan_auto_scan, refresh_lan_assets

        if is_lan_bind():
            lan = refresh_lan_assets("local", queue_scan=False)
            print(
                f"LAN inventory: host {lan.get('this_host')} · {len(lan.get('neighbors') or [])} ARP neighbors · {lan.get('assets_upserted') or 0} assets"
            )
        auto = maybe_queue_lan_auto_scan()
        if auto.get("ok"):
            print(f"LAN auto-scan: queued {auto.get('target')} -> assets load on every device")
        elif auto.get("skipped") not in {None, "not_lan_bind", "lan_auto_scan_off"}:
            print(f"LAN auto-scan: skipped ({auto.get('skipped')})")
    except Exception as exc:
        print(f"LAN auto-scan skipped: {exc}")
    try:
        from app.realtime_bus import bind_loop

        bind_loop()
        print("Realtime bus: SSE push-on-write ready.")
    except Exception as exc:
        print(f"Realtime bus bind skipped: {exc}")
    try:
        from app import xdr_stream

        xdr_stream.start()
        print(
            "XDR live feeds: CrowdStrike stream + Sophos/SentinelOne/Defender "
            "near-realtime poll started (no-op until each vendor is configured)."
        )
    except Exception as exc:
        print(f"XDR streaming skipped: {exc}")
    if init_error_reporting():
        print(f"Error reporting: Sentry active ({settings.sentry_environment}).")
    else:
        print("Error reporting: disabled (set SENTRY_DSN to enable — see docs/monitoring.md).")
    yield
    await stop_background_jobs()
    try:
        from app import xdr_stream

        await xdr_stream.stop()
    except Exception:
        pass


app = FastAPI(title="SecuraIQ", version="1.5.0", lifespan=lifespan)

_origins = cors_origin_list()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=("*" not in _origins),
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Hermes-Session-Id", "X-Hermes-Session-Key"],
)
app.add_middleware(
    RateLimitMiddleware,
    per_minute=settings.rate_limit_per_minute,
    auth_per_minute=settings.rate_limit_auth_per_minute,
    chat_per_minute=settings.rate_limit_chat_per_minute,
)


@app.middleware("http")
async def metrics_middleware(request, call_next):
    response = await call_next(request)
    route = request.url.path
    if route.startswith("/api/"):
        # Collapse path params to keep cardinality sane (e.g. /api/jobs/{id} -> /api/jobs)
        parts = route.strip("/").split("/")
        collapsed = "/".join(p for p in parts[:3])
        incr(collapsed)
        incr_status(response.status_code)
    return response


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("X-XSS-Protection", "0")
    prod = (settings.deployment_mode or "lab").lower() in {
        "production",
        "prod",
        "commercial",
        "saas",
        "cloud",
    }
    if prod or getattr(settings, "force_https_headers", False) or getattr(settings, "cookie_secure", False):
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
    # When bound to all interfaces (LAN / Docker), relax connect-src so phones
    # and other PCs on Wi‑Fi can use SSE + fetch against this host. CSP does not
    # support CIDR wildcards reliably — use scheme allowlists for lab LAN only.
    lan_bind = (settings.host or "").strip() in {"0.0.0.0", "::", "[::]"}
    connect_src = (
        "'self' http: https: ws: wss:"
        if lan_bind and not prod
        else "'self' http://127.0.0.1:* http://localhost:* https:"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob:; "
        f"connect-src {connect_src}; "
        "frame-ancestors 'none'; "
        "base-uri 'self'",
    )
    return response

app.include_router(commercial_router)
app.include_router(integrations_router)
app.include_router(gap_router)
app.include_router(enterprise_router)
app.include_router(ops_router)
app.include_router(scans_router)
app.include_router(archive_router)
app.include_router(commercial_ext_router)
app.include_router(platform_router)
app.include_router(billing_router)
app.include_router(xdr_router)
app.include_router(wazuh_router, prefix="/api/siem")
app.include_router(wazuh_router, prefix="/api/wazuh")  # compat alias
app.include_router(agents_router)
app.include_router(evidence_router)
app.include_router(risk_router)
app.include_router(openaudit_router)
app.include_router(hardeningkitty_router)
app.include_router(thehive_router)
app.include_router(cloud_posture_router)
app.include_router(sonarqube_router, prefix="/api/code")
app.include_router(sonarqube_router, prefix="/api/sonarqube")  # compat alias
app.include_router(scim_router)
app.include_router(stix_router)

_PUBLIC_API_PREFIXES = (
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/status",
    "/api/auth/mfa/verify",
    "/api/auth/oidc/login",
    "/api/auth/oidc/callback",
    "/api/integrations/github/webhook",
    "/api/integrations/gitlab/webhook",
    "/api/billing/webhook",
    "/api/health",
    "/api/realtime",
    "/api/siem/webhook",
    "/api/wazuh/webhook",
)


@app.middleware("http")
async def require_auth_when_enabled(request, call_next):
    if not settings.auth_enabled:
        return await call_next(request)
    path = request.url.path
    if not path.startswith("/api/"):
        return await call_next(request)
    if any(path == p or path.startswith(p + "/") for p in _PUBLIC_API_PREFIXES):
        return await call_next(request)
    auth = request.headers.get("authorization")
    key = request.headers.get("x-securaiq-key") or request.headers.get("x-hackgpt-key")
    if resolve_user(auth, key):
        return await call_next(request)
    from fastapi.responses import JSONResponse

    return JSONResponse({"detail": "Authentication required"}, status_code=401)


class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str


class ChatRequest(BaseModel):
    message: str = Field(default="", max_length=16000)
    history: list[ChatMessage] = Field(default_factory=list)
    mode: Literal[
        "default",
        "ctf",
        "lab",
        "redteam",
        "blueteam",
        "malware",
        "research",
        "lab_offensive",
        "assess",
        "ciso",
        "awareness",
        "purple",
        "threat_hunt",
        "xdr",
        "ir",
        "cloud",
        "appsec",
        "tabletop",
    ] = "default"
    use_rag: bool = False
    use_web_search: bool | None = None
    use_net_assess: bool | None = None
    use_local_tools: bool | None = None
    tools: list[str] | None = None
    target: str | None = Field(default=None, max_length=253)
    authorized_target: bool = False
    engagement_id: str | None = Field(default=None, max_length=64)
    chat_id: str | None = Field(default=None, max_length=64)
    attachment_ids: list[str] = Field(default_factory=list, max_length=12)
    hermes_session_id: str | None = Field(default=None, max_length=256)
    reset_hermes_session: bool = False

    @model_validator(mode="after")
    def require_message_or_attachments(self) -> ChatRequest:
        msg = (self.message or "").strip()
        if not msg and not self.attachment_ids:
            raise ValueError("Provide a message and/or attachments")
        if not msg and self.attachment_ids:
            self.message = "Please review the attached file(s)."
        return self


class IngestResponse(BaseModel):
    documents_ingested: int


class ModelSwitchRequest(BaseModel):
    model: str = Field(min_length=1, max_length=128)


class ModelPullRequest(BaseModel):
    model: str = Field(min_length=1, max_length=128)


class BackendSwitchRequest(BaseModel):
    backend: Literal[
        "ollama",
        "openai_compat",
        "hermes",
        "unsloth",
        "huggingface",
        "huggingface_api",
        "openai",
        "openrouter",
        "groq",
        "together",
        "fireworks",
    ]


class FinetuneStartRequest(BaseModel):
    engine: Literal["unsloth"] = "unsloth"
    model: str | None = None
    output: str | None = None
    epochs: int = Field(default=1, ge=1, le=10)
    batch_size: int = Field(default=2, ge=1, le=16)


MODE_RAG_TOP_K = {
    "default": 3,
    "ctf": 3,
    "lab": 4,
    "redteam": 4,
    "blueteam": 5,
    "malware": 5,
    "research": 4,
    "lab_offensive": 5,
    "assess": 5,
    "ciso": 5,
    "awareness": 5,
    "purple": 5,
    "threat_hunt": 5,
    "xdr": 5,
    "ir": 5,
    "cloud": 5,
    "appsec": 5,
    "tabletop": 4,
}

MODE_PROMPTS = {
    "ctf": CTF_MODE_PROMPT,
    "lab": LAB_MODE_PROMPT,
    "redteam": REDTEAM_MODE_PROMPT,
    "blueteam": BLUETEAM_MODE_PROMPT,
    "malware": MALWARE_ANALYSIS_MODE_PROMPT,
    "research": RESEARCH_MODE_PROMPT,
    "lab_offensive": LAB_OFFENSIVE_MODE_PROMPT,
    "assess": ASSESS_MODE_PROMPT,
    "ciso": CISO_MODE_PROMPT,
    "awareness": AWARENESS_MODE_PROMPT,
    "purple": PURPLE_MODE_PROMPT,
    "threat_hunt": THREAT_HUNT_MODE_PROMPT,
    "xdr": XDR_MODE_PROMPT,
    "ir": IR_MODE_PROMPT,
    "cloud": CLOUD_MODE_PROMPT,
    "appsec": APPSEC_MODE_PROMPT,
    "tabletop": TABLETOP_MODE_PROMPT,
}

QUICK_PROMPTS = {
    "default": [
        "Explain OWASP Top 10 with examples",
        "How do I scope a pentest engagement?",
        "Map ATT&CK initial access to lab defenses",
        "Write a CISO one-pager on MFA gaps",
    ],
    "ctf": [
        "Web CTF enumeration checklist",
        "How do I approach a crypto CTF challenge?",
        "Privilege escalation checklist for Linux CTF",
        "Parse this JWT safely for a web challenge",
    ],
    "lab": [
        "Set up DVWA in a local VM safely",
        "sqlmap usage against my own lab target",
        "Hardening checklist after a lab compromise",
        "Juice Shop XSS lab path with fixes",
    ],
    "redteam": [
        "Metasploit workflow for Metasploitable 2",
        "BEEF hook demo in Juice Shop lab",
        "Lab phishing campaign design with GoPhish",
        "Document TTPs for an authorized purple retest",
    ],
    "blueteam": [
        "Sigma rule for suspicious LSASS access",
        "IR steps when ransomware is detected",
        "Tune alerts for failed MFA fatigue attempts",
        "Build an EDR triage checklist",
    ],
    "malware": [
        "Static analysis workflow for suspicious EXE",
        "Write a YARA rule for PowerShell download cradle",
        "Sandbox detonation checklist for a lab sample",
        "Map sample behavior to ATT&CK techniques",
    ],
    "research": [
        "Latest critical CVEs affecting Windows this month",
        "Compare Nuclei vs custom scripts for lab recon",
        "Kerberoasting technique, detection, and lab setup",
        "Public writeups for Log4Shell exploitation path",
    ],
    "lab_offensive": [
        "Full attack chain on Metasploitable 2 with detection notes",
        "Lab reverse shell + persistence on a disposable VM",
        "Kerberoasting in an authorized AD lab + Sigma detection",
        "XSS to session hijack demo in Juice Shop + fixes",
    ],
    "assess": [
        "Assess my lab host 192.168.56.101 — prioritize findings",
        "Vulnerability assessment for HTB target 10.10.10.x from open ports",
        "Map banners to CVEs and give verify + remediate steps",
        "Prioritize Greenbone findings into a 30-day patch plan",
    ],
    "ciso": [
        "Run an ISO 27001 gap analysis from our current controls narrative",
        "30/60/90 day security roadmap for a mid-size company",
        "Board briefing: ransomware risk, controls, and metrics",
        "Map our vuln backlog to ISO 27001 and CIS Controls",
    ],
    "awareness": [
        "Review this lure URL for awareness training: https://login-microsoft-secure.example/auth",
        "Check SPF and DMARC for example.com + awareness talking points",
        "Design an authorized phishing simulation with training banners",
        "Teach users 10 phishing red flags with examples",
    ],
    "purple": [
        "Purple plan: test ransomware staging detection in a lab",
        "Attack→detect→fix cycle for Kerberoasting in AD lab",
        "Validate MFA fatigue alerts with a safe inject",
        "Map our last red findings to detection coverage gaps",
    ],
    "threat_hunt": [
        "Hypothesis: living-off-the-land with rundll32 — hunt queries",
        "KQL for suspicious OAuth consent grants",
        "Sigma pack for unusual service creation",
        "Hunt for Pass-the-Hash indicators in Windows logs",
    ],
    "xdr": [
        "Correlate an EDR ransomware staging alert with identity and email signals",
        "XDR triage: suspicious PowerShell + unusual OAuth consent on same user",
        "Build an attack chain from host, IP, and hash IOCs in our SOC queue",
        "False-positive tuning for noisy XDR lateral-movement detections",
    ],
    "ir": [
        "Ransomware detected on one finance laptop — first 60 minutes",
        "Business email compromise playbook for M365",
        "Preserve evidence after a suspected insider incident",
        "Comms draft for executives during a P1 outage",
    ],
    "cloud": [
        "AWS S3 public access review checklist for our account",
        "Azure Entra ID privileged role audit steps",
        "GCP IAM overprivilege hunt for a lab project",
        "CloudTrail / Activity log detections for root key use",
    ],
    "appsec": [
        "ASVS L1 checklist for a JWT login API",
        "Review this Flask route for injection risks",
        "Burp workflow for IDOR testing on our staging app",
        "Threat model a password-reset flow",
    ],
    "tabletop": [
        "Facilitate a ransomware tabletop for the exec team",
        "Inject sequence: MFA fatigue → mailbox rule → wire fraud",
        "Score our last tabletop and build a remediation backlog",
        "Supplier breach tabletop with legal and PR roles",
    ],
}


async def _build_messages(req: ChatRequest, user_id: str = "local") -> list[dict[str, str]]:
    messages: list[dict[str, str]] | None = None
    async for kind, payload in _iter_build_messages(req, user_id=user_id):
        if kind == "messages":
            messages = payload  # type: ignore[assignment]
    assert messages is not None
    return messages


async def _iter_build_messages(req: ChatRequest, user_id: str = "local"):
    """Yield ('phase', name) then ('route', plan) then ('messages', list) for realtime UI progress."""
    from app.model_router import route_task, router_system_hint

    yield ("phase", "think")
    plan = route_task(req.message, req.mode)
    yield ("route", plan)

    system_parts = [SYSTEM_PROMPT, THINKING_QUALITY_PROMPT]
    mode_prompt = MODE_PROMPTS.get(req.mode)
    if mode_prompt:
        system_parts.append(mode_prompt)
    if settings.router_enabled:
        system_parts.append(router_system_hint(plan))

    # Threat-intel lane: light KEV snapshot (cached) when enrichment requested
    if plan.get("enrich", {}).get("threat_intel"):
        try:
            from app.intel_feeds import fetch_cisa_kev

            yield ("phase", "intel")
            kev = await fetch_cisa_kev(limit=8)
            items = kev.get("items") or []
            if items:
                lines = ["## Live CISA KEV snapshot (authorized research)", ""]
                for it in items[:8]:
                    lines.append(
                        f"- `{it.get('cve')}` — {it.get('vendor')} {it.get('product')}: {it.get('name')}"
                    )
                system_parts.append("\n".join(lines))
        except Exception:
            pass

    search_default_modes = {
        "research",
        "assess",
        "lab_offensive",
        "ciso",
        "awareness",
        "threat_hunt",
        "xdr",
        "cloud",
        "appsec",
        "ir",
        "tabletop",
    }
    do_search = (
        req.use_web_search
        if req.use_web_search is not None
        else (req.mode in search_default_modes)
    )
    search_task = None
    if do_search and settings.web_search_enabled:
        yield ("phase", "search")
        search_task = asyncio.create_task(web_search(req.message))

    targets = extract_targets(req.message, req.target)
    assess_modes = {
        "assess",
        "lab",
        "redteam",
        "ctf",
        "lab_offensive",
        "ciso",
        "purple",
        "cloud",
        "appsec",
    }
    do_assess = (
        req.use_net_assess
        if req.use_net_assess is not None
        else (req.mode == "assess" or bool(req.target) or (bool(targets) and req.mode in assess_modes))
    )
    assess_task = None
    if do_assess and settings.net_assess_enabled and (targets or req.target):
        authorized = bool(req.authorized_target) or req.mode in assess_modes
        yield ("phase", "assess")
        assess_task = asyncio.create_task(
            assess_from_request(
                req.message,
                target=req.target,
                authorized=authorized,
                allow_public=bool(req.authorized_target),
                user_id=user_id,
            )
        )

    tools_modes = {
        "assess",
        "lab",
        "redteam",
        "ctf",
        "lab_offensive",
        "ciso",
        "awareness",
        "blueteam",
        "purple",
        "threat_hunt",
        "xdr",
        "ir",
        "cloud",
        "appsec",
        "tabletop",
    }
    msg_lower = (req.message or "").lower()
    instruct_tools = any(
        k in msg_lower
        for k in (
            "run nmap", "run nikto", "run nuclei", "run zap", "use nmap", "use nuclei",
            "use zap", "use burp", "greenbone", "openvas", "acunetix", "tools:",
            "scan with", "probe with", "suite_guide", "phishing_url", "email_auth",
            "phishing", "awareness", "spf", "dmarc", "dkim", "gophish", "knowbe4",
            "review this lure", "review url", "check spf",
        )
    ) or bool(req.tools)
    awareness_tools = req.mode in {"awareness", "ciso", "blueteam", "tabletop", "ir"} or any(
        k in msg_lower for k in ("phish", "awareness", "spf", "dmarc", "dkim", "gophish")
    )
    auto_tools = settings.local_tools_auto and (
        req.mode == "assess"
        or req.mode == "awareness"
        or bool(req.target)
        or instruct_tools
        or awareness_tools
        or (bool(targets) and req.mode in tools_modes)
    )
    # Explicit tool list always runs; checkbox only gates auto selection
    do_tools = bool(req.tools) or (
        True if req.use_local_tools is True else False if req.use_local_tools is False else auto_tools
    )
    tools_payload = None
    if do_tools and not settings.local_tools_enabled:
        yield ("phase", "tools")
        system_parts.append(
            "## Local security tools\n"
            "Tools were requested but **local tools are disabled** in Settings "
            "(`LOCAL_TOOLS_ENABLED`). Enable them to run dns/ports/http probes."
        )
    elif do_tools and settings.local_tools_enabled:
        authorized = bool(req.authorized_target) or req.mode in tools_modes
        yield ("phase", "tools")
        tools_payload = {"ok": False, "runs": []}
        try:
            async for ev in iter_security_tools(
                req.message,
                target=req.target,
                tools=req.tools,
                authorized=authorized,
                allow_public=bool(req.authorized_target) or req.mode == "awareness",
                auto=not instruct_tools and not req.tools,
                include_heavy=settings.local_tools_allow_heavy or bool(req.tools) or instruct_tools,
                mode=req.mode,
                user_id=user_id,
            ):
                # Keep live marker static for the whole tools phase (UI already showed phase)
                if ev.get("event") == "done":
                    tools_payload = ev.get("payload") or tools_payload
        except Exception as exc:
            tools_payload = {"ok": False, "error": str(exc), "runs": []}

    if search_task is not None:
        try:
            search_payload = await search_task
        except Exception as exc:
            search_payload = {"query": req.message, "results": [], "provider": "error", "error": str(exc)}
        system_parts.append(SEARCH_BEHAVIOR_PROMPT)
        system_parts.append(format_search_context(search_payload))

    if assess_task is not None:
        try:
            assess_payload = await assess_task
        except Exception as exc:
            assess_payload = {"ok": False, "error": str(exc), "results": []}
        system_parts.append(ASSESS_MODE_PROMPT if req.mode != "assess" else "")
        system_parts.append(format_assess_context(assess_payload))
    elif do_assess and not (targets or req.target):
        system_parts.append(
            "## Network assessment\nNo target IP found. Ask for a lab/private IP "
            "(e.g. 192.168.x.x / 10.x) or fill the Target IP field."
        )

    if tools_payload is not None:
        system_parts.append(TOOLS_BEHAVIOR_PROMPT)
        system_parts.append(format_tools_context(tools_payload))

    if req.use_rag:
        yield ("phase", "rag")
        top_k = MODE_RAG_TOP_K.get(req.mode, 3)
        context, sources = await asyncio.to_thread(rag_engine.build_context, req.message, top_k)
        if context:
            system_parts.append(context)
        if sources:
            yield ("citations", sources)

    # Engagement memory (server-side)
    if req.engagement_id:
        mem = memory_context_raw(req.engagement_id)
        if mem:
            system_parts.append(mem)

    # Chat attachments (upload into the thread)
    if req.attachment_ids:
        yield ("phase", "rag")
        att = await asyncio.to_thread(attachment_context, user_id, list(req.attachment_ids))
        if att:
            system_parts.append(att)

    system_parts = [p for p in system_parts if p]
    messages: list[dict[str, str]] = [{"role": "system", "content": "\n\n".join(system_parts)}]
    # Keep context short for local HF / small models (big history = slow TTFT)
    hist_limit = 8 if settings.model_backend in {"huggingface", "unsloth"} else 20
    for msg in req.history[-hist_limit:]:
        messages.append({"role": msg.role, "content": msg.content})
    messages.append({"role": "user", "content": req.message})
    yield ("phase", "model")
    yield ("messages", messages)


@app.get("/api/metrics")
async def metrics():
    """Prometheus text-exposition endpoint. Scrape this instead of polling
    /api/health repeatedly for uptime dashboards — see docs/monitoring.md."""
    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(render_prometheus(), media_type="text/plain; version=0.0.4")


@app.get("/api/health")
async def health():
    installed: list[str] = []
    # Short TTL cache — /api/realtime and UI poll this often
    cache = getattr(health, "_cache", None)
    now_t = asyncio.get_event_loop().time()
    if cache and (now_t - cache.get("ts", 0)) < 12:
        return cache["payload"]

    if settings.model_backend == "ollama":
        backend_ready, installed = await fetch_ollama_tags()
        current = settings.ollama_model
        backend_status = "ready" if backend_ready and installed else "needs_model" if backend_ready else "offline"
    elif settings.model_backend in {
        "openai_compat",
        "openai",
        "openrouter",
        "groq",
        "together",
        "fireworks",
        "huggingface_api",
    }:
        from app.model_router import resolve_openai_compat_endpoint

        if settings.model_backend == "openai_compat":
            backend_ready = await openai_compat_reachable()
            current = settings.openai_compat_model
            backend_status = "ready" if backend_ready else "offline"
        else:
            _base, key, current = resolve_openai_compat_endpoint(settings.model_backend)
            backend_ready = bool(key)
            backend_status = "ready" if backend_ready else "needs_key"
    elif settings.model_backend == "hermes":
        backend_ready = await hermes_reachable()
        current = settings.hermes_model
        backend_status = "ready" if backend_ready else "offline"
    elif settings.model_backend == "unsloth":
        backend_ready = True
        current = settings.unsloth_adapter_dir if Path(settings.unsloth_adapter_dir).exists() else settings.unsloth_model
        backend_status = "ready" if model_client.unsloth_model_loaded else "loads_on_chat"
    else:
        backend_ready = True
        current = settings.hf_model
        backend_status = "ready" if model_client.hf_model_loaded else "loads_on_chat"
    payload = {
        "status": "ok",
        "backend": settings.model_backend,
        "model": current,
        "backend_ready": backend_ready,
        "backend_status": backend_status,
        "hf_model_loaded": model_client.hf_model_loaded if settings.model_backend == "huggingface" else None,
        "unsloth_model_loaded": model_client.unsloth_model_loaded if settings.model_backend == "unsloth" else None,
        "hf_token_set": bool(settings.hf_token),
        "installed_models": installed,
        "ollama_connected": backend_ready if settings.model_backend == "ollama" else None,
        "ollama_has_models": bool(installed) if settings.model_backend == "ollama" else None,
        "rag_documents": rag_engine.document_count(),
        "finetune": finetune_job.snapshot(),
        "integrations": {
            "hermes": True,
            "unsloth": True,
            "settings": True,
            "rag": True,
            "net_assess": settings.net_assess_enabled,
            "local_tools": settings.local_tools_enabled,
            "modes": list(MODE_RAG_TOP_K.keys()),
        },
    }
    try:
        from app.realtime_bus import backend_status as realtime_backend_status

        payload["realtime_bus"] = realtime_backend_status()
    except Exception:
        payload["realtime_bus"] = {"mode": "unknown"}
    try:
        from app.archive import prototype_status

        payload["prototype"] = prototype_status()
    except Exception:
        payload["prototype"] = {"ok": False}
    health._cache = {"ts": now_t, "payload": payload}
    return payload


@app.get("/api/admin/health")
async def admin_health_board(user: Annotated[AuthUser, Depends(require_user)]):
    """SecuraIQ Admin Health — green/yellow/red per subsystem."""
    if settings.auth_enabled and user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required for /api/admin/health")
    from app.admin_health import collect_admin_health

    return collect_admin_health()


class RouterPlanRequest(BaseModel):
    message: str = Field(default="general security question", max_length=8000)
    mode: str = "default"


@app.get("/api/router")
async def router_catalog():
    from app.model_router import list_providers

    return list_providers()


@app.post("/api/router/plan")
async def router_plan(req: RouterPlanRequest):
    from app.model_router import route_task

    return route_task(req.message, req.mode)


@app.get("/api/backend")
async def backend():
    return {
        "backend": settings.model_backend,
        "options": [
            "ollama",
            "openai_compat",
            "hermes",
            "unsloth",
            "huggingface",
            "huggingface_api",
            "openai",
            "openrouter",
            "groq",
            "together",
            "fireworks",
        ],
    }


@app.get("/api/backends/probe")
async def backends_probe():
    """Which AI backends are ready — used by UI auto-select."""
    return await probe_backends()


@app.post("/api/backend")
async def switch_backend(req: BackendSwitchRequest):
    settings.model_backend = req.backend
    update_env_value("MODEL_BACKEND", req.backend)
    # Backend switches must be immediately visible to health/realtime clients.
    # Otherwise the short health TTL can report the previous backend.
    if hasattr(health, "_cache"):
        delattr(health, "_cache")
    return {"backend": settings.model_backend}


@app.post("/api/models/preload")
async def preload_model():
    if settings.model_backend not in ("huggingface", "unsloth"):
        raise HTTPException(status_code=400, detail="Preload only supported with HuggingFace or Unsloth backends.")

    async def stream():
        label = settings.hf_model if settings.model_backend == "huggingface" else settings.unsloth_model
        yield f"Loading `{label}`…\n"
        try:
            if settings.model_backend == "huggingface":
                await model_client.preload_huggingface()
            else:
                await model_client.preload_unsloth()
            yield "Model ready.\n"
        except Exception as exc:
            yield f"Load failed: {exc}\n"

    return StreamingResponse(stream(), media_type="text/plain; charset=utf-8")


@app.get("/api/settings")
async def get_settings():
    return public_settings()


@app.post("/api/settings")
async def update_settings(body: dict[str, Any] = Body(default_factory=dict)):
    return apply_settings_patch(body)


@app.get("/api/platform")
async def platform():
    """OS + LAN URLs + backend capabilities for Win/Linux/macOS hosts and mobile browsers."""
    return platform_info()


@app.get("/api/hermes/status")
async def hermes_status():
    """Hermes Agent reachability, models, and /v1/capabilities."""
    return await fetch_hermes_status()


@app.get("/api/search/web")
async def api_search_web(
    q: str = Query(..., min_length=1, description="Search query"),
    limit: int = Query(8, ge=1, le=20),
):
    """Live cybersecurity web search (for UI/debug). Entity search is GET /api/search."""
    return await web_search(q.strip(), max_results=limit)


class AssessRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    message: str = ""
    authorized_target: bool = False


@app.post("/api/assess")
async def api_assess(req: AssessRequest):
    """Light authorized/lab host assessment (private ranges or owned public with confirm)."""
    if not settings.net_assess_enabled:
        raise HTTPException(status_code=400, detail="Network assess disabled")
    return await assess_from_request(
        req.message or f"assess {req.target}",
        target=req.target,
        authorized=req.authorized_target,
        allow_public=req.authorized_target,
    )


@app.get("/api/tools")
async def api_tools():
    """List built-in + PATH security tools and availability."""
    status = list_tools_status()
    status["enabled"] = settings.local_tools_enabled
    status["auto"] = settings.local_tools_auto
    status["allow_heavy"] = settings.local_tools_allow_heavy
    return status


@app.get("/api/tools/versions")
async def api_tools_versions(request: Request, refresh: bool = False):
    """SecuraIQ's own software/tool patch status: installed vs. latest
    published version for every external tool on PATH, plus SecuraIQ's own
    product version and git build info. Cached ~6h — pass ?refresh=true to
    force a fresh check."""
    payload = await get_all_tool_versions(force=refresh)
    if refresh:
        try:
            from app.realtime_bus import publish

            user = resolve_user(
                request.headers.get("authorization"),
                request.headers.get("x-securaiq-key") or request.headers.get("x-hackgpt-key"),
            )
            counts = payload.get("counts") or {}
            outdated = int(counts.get("outdated") or 0)
            publish(
                type="tool",
                kind="tool_versions",
                status="done",
                user_id=(user.id if user else "local"),
                findings=outdated,
                message=(
                    f"Local tools checked · {outdated} update(s) available"
                    if outdated
                    else "Local tools checked · all known versions current"
                ),
            )
        except Exception:
            pass
    return payload


class ToolsRunRequest(BaseModel):
    target: str | None = Field(default=None, max_length=253)
    message: str = ""
    tools: list[str] | None = None
    authorized_target: bool = False
    # Accept UI/legacy alias so Auth checkbox always maps correctly
    authorized: bool | None = None
    auto: bool = False
    engagement_id: str | None = Field(default=None, max_length=64)

    def resolved_authorized(self) -> bool:
        if self.authorized_target:
            return True
        return bool(self.authorized)


@app.post("/api/tools/run")
async def api_tools_run(req: ToolsRunRequest, request: Request):
    """Run selected security tools against an authorized/lab target."""
    if not settings.local_tools_enabled:
        raise HTTPException(status_code=400, detail="Local tools disabled")
    user = resolve_user(
        request.headers.get("authorization"),
        request.headers.get("x-securaiq-key") or request.headers.get("x-hackgpt-key"),
    )
    uid = user.id if user else "local"
    result = await run_security_tools(
        req.message or (f"run tools on {req.target}" if req.target else ""),
        target=req.target,
        tools=req.tools,
        authorized=req.resolved_authorized(),
        allow_public=req.resolved_authorized(),
        auto=req.auto and not req.tools,
        include_heavy=settings.local_tools_allow_heavy or bool(req.tools),
        user_id=uid,
        engagement_id=req.engagement_id,
    )
    result["markdown"] = format_tools_context(result)
    return result


@app.post("/api/tools/run/stream")
async def api_tools_run_stream(req: ToolsRunRequest, request: Request):
    """NDJSON realtime tool progress (lightweight builtins run in parallel)."""
    if not settings.local_tools_enabled:
        raise HTTPException(status_code=400, detail="Local tools disabled")

    message = req.message or (f"run tools on {req.target}" if req.target else "")
    user = resolve_user(
        request.headers.get("authorization"),
        request.headers.get("x-securaiq-key") or request.headers.get("x-hackgpt-key"),
    )
    uid = user.id if user else "local"

    async def ndjson():
        async for ev in iter_security_tools(
            message,
            target=req.target,
            tools=req.tools,
            authorized=req.resolved_authorized(),
            allow_public=req.resolved_authorized(),
            auto=req.auto and not req.tools,
            include_heavy=settings.local_tools_allow_heavy or bool(req.tools),
            user_id=uid,
            engagement_id=req.engagement_id,
        ):
            if ev.get("event") == "done":
                payload = dict(ev.get("payload") or {})
                payload["markdown"] = format_tools_context(payload)
                yield json.dumps({"event": "done", "payload": payload}, ensure_ascii=False) + "\n"
            else:
                yield json.dumps(ev, ensure_ascii=False) + "\n"

    return StreamingResponse(ndjson(), media_type="application/x-ndjson")


class JobEnqueueRequest(BaseModel):
    kind: Literal[
        "kev_sync",
        "report_export",
        "xdr_sync",
        "wazuh_sync",
        "openaudit_sync",
        "hardeningkitty_audit",
        "thehive_sync",
        "cloud_posture_sync",
        "sonarqube_sync",
        "scan_execute",
    ]
    payload: dict[str, Any] = Field(default_factory=dict)
    engine: Literal["auto", "local", "prefect"] = "auto"


@app.get("/api/jobs")
async def jobs_list(limit: int = 50, kind: str | None = None):
    from app.jobs import list_jobs
    from app.prefect_bridge import prefect_status

    return {"jobs": list_jobs(limit=limit, kind=kind), "prefect": prefect_status()}


@app.get("/api/jobs/{job_id}")
async def jobs_get(job_id: str):
    from app.jobs import get_job

    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.post("/api/jobs")
async def jobs_enqueue(req: JobEnqueueRequest, request: Request):
    from app.jobs import enqueue_job

    user = resolve_user(
        request.headers.get("authorization"),
        request.headers.get("x-securaiq-key") or request.headers.get("x-hackgpt-key"),
    )
    payload = dict(req.payload)
    # Assets / vulns / HK / OA / XDR jobs must land under the calling user,
    # not a silent "local" tenant when auth is on.
    payload.setdefault("user_id", user.id if user else "local")
    try:
        return enqueue_job(req.kind, payload, engine=req.engine)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/prefect/status")
async def prefect_status_api():
    from app.prefect_bridge import prefect_status

    return prefect_status()


@app.get("/api/finetune")
async def finetune_status():
    return finetune_job.snapshot()


@app.post("/api/finetune")
async def finetune_start(req: FinetuneStartRequest):
    if req.engine != "unsloth":
        raise HTTPException(status_code=400, detail="Only engine=unsloth is supported.")
    model = (req.model or settings.unsloth_model).strip()
    output = (req.output or settings.unsloth_adapter_dir).strip()
    ok = launch_unsloth_job(
        model=model,
        output=output,
        epochs=req.epochs,
        batch_size=req.batch_size,
    )
    if not ok:
        raise HTTPException(status_code=409, detail="A fine-tune job is already running.")
    return finetune_job.snapshot()


@app.get("/api/modes")
async def modes():
    return {
        "modes": list(MODE_RAG_TOP_K.keys()),
        "quick_prompts": QUICK_PROMPTS,
    }


@app.get("/api/status")
async def status():
    return {
        "rag_documents": rag_engine.document_count(),
        "rag_sources": rag_engine.list_sources(),
        "modes": list(MODE_RAG_TOP_K.keys()),
    }


@app.get("/api/models")
async def models():
    installed = await list_installed_models() if settings.model_backend == "ollama" else []
    if settings.model_backend == "ollama":
        current = settings.ollama_model
    elif settings.model_backend == "openai_compat":
        current = settings.openai_compat_model
    elif settings.model_backend in {
        "openai",
        "openrouter",
        "groq",
        "together",
        "fireworks",
        "huggingface_api",
    }:
        from app.model_router import resolve_openai_compat_endpoint

        _base, _key, current = resolve_openai_compat_endpoint(settings.model_backend)
    elif settings.model_backend == "hermes":
        current = settings.hermes_model
    elif settings.model_backend == "unsloth":
        adapter = Path(settings.unsloth_adapter_dir)
        current = str(adapter) if adapter.exists() else settings.unsloth_model
    else:
        current = settings.hf_model
    return {
        "backend": settings.model_backend,
        "current": current,
        "installed": installed,
        "recommended": RECOMMENDED_MODELS,
    }


@app.post("/api/models/switch")
async def switch_model(req: ModelSwitchRequest):
    if settings.model_backend != "ollama":
        raise HTTPException(status_code=400, detail="Model switching only supported with Ollama backend.")
    settings.ollama_model = req.model
    return {"current": settings.ollama_model}


@app.post("/api/models/pull")
async def pull_ollama_model(req: ModelPullRequest):
    if settings.model_backend != "ollama":
        raise HTTPException(status_code=400, detail="Model pull only supported with Ollama backend.")

    async def stream():
        async for line in pull_model(req.model):
            yield line

    return StreamingResponse(stream(), media_type="text/plain; charset=utf-8")


@app.post("/api/ingest")
async def ingest_knowledge() -> IngestResponse:
    count = rag_engine.ingest_directory(force=True)
    return IngestResponse(documents_ingested=count)


@app.get("/api/realtime")
async def realtime_feed():
    """Server-Sent Events: live pulse for Mission Control + workspace panels.

    Wakes immediately on realtime_bus.publish(...) (notifications, jobs, XDR,
    etc.) and still emits a heartbeat snapshot every 5s when idle.
    """

    async def event_gen():
        from app.realtime_bus import bind_loop, subscribe, unsubscribe

        tools_snap = {"available_count": 0, "count": 0}
        tools_ts = 0.0
        q = subscribe()
        try:
            bind_loop()
        except Exception:
            pass

        async def build_payload(push: dict[str, Any] | None = None) -> dict[str, Any]:
            nonlocal tools_snap, tools_ts
            now_t = asyncio.get_event_loop().time()
            if now_t - tools_ts > 60:
                tools_snap = list_tools_status()
                tools_ts = now_t
            snap = await health()

            jobs_pending = 0
            jobs_running = 0
            jobs_recent: list[dict[str, Any]] = []
            try:
                from app.jobs import list_jobs

                for j in list_jobs(limit=12):
                    st = (j.get("status") or "").lower()
                    if st == "pending":
                        jobs_pending += 1
                    elif st == "running":
                        jobs_running += 1
                    jobs_recent.append(
                        {
                            "id": j.get("id"),
                            "kind": j.get("kind"),
                            "status": st,
                            "finished_at": j.get("finished_at"),
                        }
                    )
            except Exception:
                pass

            inventory = {"configured": False, "live": True, "devices_cached": 0}
            try:
                from app.openaudit import status as oa_status

                oa = oa_status()
                inventory = {
                    "configured": bool(oa.get("configured")),
                    "live": True,
                    "devices_cached": int(oa.get("devices_cached") or 0),
                }
            except Exception:
                pass

            hardening = {"installed": False, "lists": 0, "cis_lists": 0, "last_score": None}
            try:
                from app.hardeningkitty import recent_runs, status as hk_status

                hk = hk_status()
                runs = recent_runs(1)
                hardening = {
                    "installed": bool(hk.get("installed")),
                    "lists": int(hk.get("finding_lists") or 0),
                    "cis_lists": int(hk.get("cis_lists") or 0),
                    "last_score": (runs[0].get("score") if runs else None),
                }
            except Exception:
                pass

            notif_unread = 0
            try:
                from app.notifications import unread_count

                notif_unread = int(unread_count("local") or 0)
            except Exception:
                notif_unread = 0

            kpis = {"assets": 0, "vulns_open": 0, "incidents_open": 0}
            try:
                from app.db import get_conn

                c = get_conn()
                kpis["assets"] = int(
                    (
                        c.execute(
                            "SELECT COUNT(*) AS n FROM assets WHERE user_id = ?", ("local",)
                        ).fetchone()
                        or {"n": 0}
                    )["n"]
                )
                kpis["vulns_open"] = int(
                    (
                        c.execute(
                            "SELECT COUNT(*) AS n FROM vulnerabilities WHERE user_id = ? "
                            "AND status NOT IN ('closed','resolved','mitigated')",
                            ("local",),
                        ).fetchone()
                        or {"n": 0}
                    )["n"]
                )
                kpis["incidents_open"] = int(
                    (
                        c.execute(
                            "SELECT COUNT(*) AS n FROM incidents WHERE user_id = ? "
                            "AND status NOT IN ('closed','resolved')",
                            ("local",),
                        ).fetchone()
                        or {"n": 0}
                    )["n"]
                )
            except Exception:
                pass

            payload: dict[str, Any] = {
                "ts": now_t,
                "backend": snap.get("backend"),
                "model": snap.get("model"),
                "backend_ready": snap.get("backend_ready"),
                "backend_status": snap.get("backend_status"),
                "rag_documents": snap.get("rag_documents"),
                "tools_available": tools_snap.get("available_count"),
                "tools_total": tools_snap.get("count"),
                "local_tools": settings.local_tools_enabled,
                "net_assess": settings.net_assess_enabled,
                "web_search": settings.web_search_enabled,
                "jobs_pending": jobs_pending,
                "jobs_running": jobs_running,
                "jobs_recent": jobs_recent[:8],
                "inventory": inventory,
                "hardeningkitty": hardening,
                "notifications_unread": notif_unread,
                "kpis": kpis,
                "realtime_bus": snap.get("realtime_bus"),
            }
            if push:
                payload["push"] = push
            return payload

        try:
            # Immediate snapshot so clients paint without waiting for the first tick.
            try:
                yield f"data: {json.dumps(await build_payload())}\n\n"
            except Exception as exc:
                yield f"data: {json.dumps({'error': str(exc)})}\n\n"

            while True:
                push_evt: dict[str, Any] | None = None
                try:
                    push_evt = await asyncio.wait_for(q.get(), timeout=3.0)
                    # Drain a small burst so one write storm doesn't spam SSE frames.
                    for _ in range(7):
                        try:
                            nxt = q.get_nowait()
                            if isinstance(push_evt, dict) and isinstance(nxt, dict):
                                push_evt = {**push_evt, "also": (push_evt.get("also") or []) + [nxt]}
                            else:
                                push_evt = nxt
                        except asyncio.QueueEmpty:
                            break
                except asyncio.TimeoutError:
                    push_evt = None
                try:
                    yield f"data: {json.dumps(await build_payload(push_evt))}\n\n"
                except Exception as exc:
                    yield f"data: {json.dumps({'error': str(exc)})}\n\n"
        finally:
            unsubscribe(q)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/chat")
async def chat(req: ChatRequest, request: Request):
    guard = check_request(req.message)
    if not guard.allowed:
        async def refusal_stream():
            yield guard.reason or "Request blocked."
        return StreamingResponse(refusal_stream(), media_type="text/plain; charset=utf-8")

    response_headers: dict[str, str] = {}
    user = resolve_user(
        request.headers.get("authorization"),
        request.headers.get("x-securaiq-key") or request.headers.get("x-hackgpt-key"),
    )
    uid = user.id if user else "local"

    from app.billing import check_quota_ok, record_usage

    quota_ok, quota_reason = check_quota_ok(uid)
    if not quota_ok:
        async def quota_stream():
            yield quota_reason
        return StreamingResponse(quota_stream(), media_type="text/plain; charset=utf-8")
    record_usage(uid, "chat_message")

    def _persist(role: str, content: str) -> None:
        if not req.chat_id:
            return
        try:
            append_message(uid, req.chat_id, role, content)
        except Exception:
            pass

    if settings.model_backend == "hermes":
        session_id = None if req.reset_hermes_session else (req.hermes_session_id or None)

        async def hermes_stream():
            messages = None
            collected = []
            yield "[[live:start]]"
            _persist("user", req.message if not req.attachment_ids else f"{req.message}\n\n[Attachments: {len(req.attachment_ids)} file(s)]")
            async for kind, payload in _iter_build_messages(req, user_id=uid):
                if kind == "phase":
                    yield f"[[live:{payload}]]"
                elif kind == "tool":
                    yield "[[live:tools]]"
                elif kind == "route":
                    intent = (payload or {}).get("intent") or ""
                    agent = (payload or {}).get("agent") or ""
                    if intent:
                        yield f"[[live:route:{intent}]]"
                    if agent:
                        yield f"[[router:{agent}|{intent}|{(payload or {}).get('recommended_backend') or ''}]]"
                elif kind == "citations":
                    yield f"[[citations:{_encode_citations(payload)}]]"
                elif kind == "messages":
                    messages = payload
            if not messages:
                yield "[[live:error]]"
                return
            async for token, sid in model_client.stream_chat_hermes(messages, session_id=session_id):
                if sid:
                    response_headers["X-Hermes-Session-Id"] = sid
                    yield f"[[hermes_session:{sid}]]"
                if token:
                    collected.append(token)
                    yield token
            _persist("assistant", "".join(collected))
            yield "[[live:done]]"

        return StreamingResponse(
            hermes_stream(),
            media_type="text/plain; charset=utf-8",
            headers=response_headers,
        )

    async def event_stream():
        messages = None
        route_plan = None
        collected = []
        yield "[[live:start]]"
        user_msg = req.message
        if req.attachment_ids:
            user_msg = f"{req.message}\n\n[Attachments: {len(req.attachment_ids)} file(s)]"
        _persist("user", user_msg)
        async for kind, payload in _iter_build_messages(req, user_id=uid):
            if kind == "phase":
                yield f"[[live:{payload}]]"
            elif kind == "tool":
                yield "[[live:tools]]"
            elif kind == "route":
                route_plan = payload
                intent = (payload or {}).get("intent") or ""
                agent = (payload or {}).get("agent") or ""
                if intent:
                    yield f"[[live:route:{intent}]]"
                if agent:
                    yield f"[[router:{agent}|{intent}|{(payload or {}).get('recommended_backend') or ''}]]"
            elif kind == "citations":
                yield f"[[citations:{_encode_citations(payload)}]]"
            elif kind == "messages":
                messages = payload
        if not messages:
            yield "[[live:error]]"
            return
        async for token in model_client.stream_chat(messages, route=route_plan):
            collected.append(token)
            yield token
        _persist("assistant", "".join(collected))
        yield "[[live:done]]"

    return StreamingResponse(event_stream(), media_type="text/plain; charset=utf-8")


if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
