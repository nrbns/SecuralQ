"""SecuraIQ License Service — signed org entitlements (server-side).

Commercial SaaS needs quotas and feature flags that cannot be forged by
editing a local LICENSE_KEY. This module:

* Defines plan entitlements (max_agents, features)
* Issues Ed25519-signed license payloads (private key never in agents)
* Verifies signatures and status/expiry with a grace window
* Gates new agent enrollment when LICENSE_ENFORCEMENT_ENABLED=true

Soft by default: lab/community keeps working without keys or enforcement.
Stripe remains the payment SoT; this service stores the *entitlement*
record the control plane enforces.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any

from app.config import settings
from app.db import get_conn, new_id, now, table_columns

_log = logging.getLogger("securaiq.license")

LICENSE_PLANS: dict[str, dict[str, Any]] = {
    "free": {
        "label": "Community",
        "max_agents": 5,
        "features": ["agent", "inventory", "vulnerability", "compliance"],
        "price_usd": 0,
    },
    "pro": {
        "label": "Professional",
        "max_agents": 100,
        "features": [
            "agent",
            "inventory",
            "vulnerability",
            "compliance",
            "realtime",
            "evidence",
            "remediation",
            "ai",
        ],
        "price_usd": 49,
    },
    "team": {
        "label": "Business",
        "max_agents": 500,
        "features": [
            "agent",
            "inventory",
            "vulnerability",
            "compliance",
            "realtime",
            "evidence",
            "remediation",
            "ai",
            "integrations",
        ],
        "price_usd": 199,
    },
    "enterprise": {
        "label": "Enterprise",
        "max_agents": None,  # unlimited soft
        "features": [
            "agent",
            "inventory",
            "vulnerability",
            "compliance",
            "realtime",
            "evidence",
            "remediation",
            "ai",
            "integrations",
            "sso",
            "scim",
            "audit",
        ],
        "price_usd": None,
    },
}

_DEFAULT_GRACE_DAYS = 14

# Features that remain usable in restricted (post-grace expiry) mode.
# Spec: login + visibility + evidence export; no premium write/AI/remediation.
_RESTRICTED_KEEP_FEATURES = frozenset(
    {"agent", "inventory", "vulnerability", "compliance", "evidence"}
)
_PREMIUM_WRITE_FEATURES = frozenset(
    {"remediation", "ai", "realtime", "integrations", "sso", "scim", "audit"}
)

# Lab-only ephemeral keypair when LICENSE_ED25519_* unset (same process only).
_EPHEMERAL_KEYS: dict[str, str] | None = None


def ensure_schema() -> None:
    c = get_conn()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_licenses (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT 'local',
            org_id TEXT,
            plan TEXT NOT NULL DEFAULT 'free',
            status TEXT NOT NULL DEFAULT 'active',
            max_agents INTEGER,
            features_json TEXT NOT NULL DEFAULT '[]',
            issued_at REAL NOT NULL,
            expires_at REAL,
            grace_days INTEGER NOT NULL DEFAULT 14,
            payload_json TEXT NOT NULL DEFAULT '{}',
            signature TEXT NOT NULL DEFAULT '',
            alg TEXT NOT NULL DEFAULT 'ed25519',
            kid TEXT NOT NULL DEFAULT 'license-v1',
            revoked_at REAL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    cols = table_columns(c, "securaiq_licenses")
    if cols and "grace_days" not in cols:
        c.execute("ALTER TABLE securaiq_licenses ADD COLUMN grace_days INTEGER NOT NULL DEFAULT 14")
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_licenses_org ON securaiq_licenses(org_id, status, created_at DESC)"
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_licenses_user ON securaiq_licenses(user_id, status, created_at DESC)"
    )
    c.commit()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    s = (data or "").strip()
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def _canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def license_enforcement_enabled() -> bool:
    return bool(getattr(settings, "license_enforcement_enabled", False))


def _license_private_material() -> str:
    return (getattr(settings, "license_ed25519_private_key", "") or "").strip()


def _ephemeral_keypair() -> dict[str, str]:
    global _EPHEMERAL_KEYS
    if _EPHEMERAL_KEYS is None:
        from app.agent_security import generate_ed25519_keypair

        _EPHEMERAL_KEYS = generate_ed25519_keypair()
        _log.warning(
            "LICENSE_ED25519_PRIVATE_KEY unset — using ephemeral lab key; "
            "issued licenses will not verify after restart"
        )
    return _EPHEMERAL_KEYS


def _license_public_material() -> str:
    pub = (getattr(settings, "license_ed25519_public_key", "") or "").strip()
    if pub:
        return pub
    # Fall back to agent Ed25519 public when license-specific key unset (lab).
    pub = (getattr(settings, "agent_ed25519_public_key", "") or "").strip()
    if pub:
        return pub
    # Match in-process ephemeral signer so lab issue→verify works without config.
    return _ephemeral_keypair().get("public_b64") or ""


def _sign_bytes(message: bytes) -> tuple[str, str]:
    """Return (signature_b64url, kid). Uses license key or agent Ed25519 private."""
    from app.agent_security import ed25519_sign

    priv = _license_private_material() or (getattr(settings, "agent_ed25519_private_key", "") or "").strip()
    if not priv:
        priv = _ephemeral_keypair()["private_b64"]
    sig = ed25519_sign(message, private_key=priv)
    kid = "license-v1-" + hashlib.sha256(priv.encode()).hexdigest()[:8]
    return sig, kid


def _verify_bytes(message: bytes, signature: str) -> bool:
    from app.agent_security import ed25519_verify

    pub = _license_public_material()
    if not pub:
        # Without a configured public key, accept only when enforcement is off.
        return not license_enforcement_enabled()
    return ed25519_verify(message, signature, public_key=pub)


def plan_catalog() -> dict[str, dict[str, Any]]:
    return {k: dict(v) for k, v in LICENSE_PLANS.items()}


def entitlements_for_plan(plan: str) -> dict[str, Any]:
    p = (plan or "free").strip().lower()
    if p not in LICENSE_PLANS:
        p = "free"
    base = LICENSE_PLANS[p]
    return {
        "plan": p,
        "plan_label": base["label"],
        "max_agents": base["max_agents"],
        "features": list(base["features"]),
    }


def build_license_payload(
    *,
    license_id: str,
    organization_id: str | None,
    plan: str,
    max_agents: int | None = None,
    features: list[str] | None = None,
    expires_at: float | None = None,
    grace_days: int = _DEFAULT_GRACE_DAYS,
    status: str = "active",
) -> dict[str, Any]:
    ent = entitlements_for_plan(plan)
    ts = now()
    return {
        "license_id": license_id,
        "organization_id": (organization_id or "").strip() or None,
        "plan": ent["plan"],
        "status": status,
        "max_agents": max_agents if max_agents is not None else ent["max_agents"],
        "features": list(features) if features is not None else list(ent["features"]),
        "issued_at": ts,
        "expires_at": expires_at,
        "grace_days": max(0, int(grace_days)),
    }


def sign_license_payload(payload: dict[str, Any]) -> dict[str, Any]:
    body = _canonical_payload(payload)
    sig, kid = _sign_bytes(body)
    return {"payload": payload, "alg": "ed25519", "signature": sig, "kid": kid}


def verify_signed_license(blob: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(blob, dict):
        return False, "invalid_blob"
    payload = blob.get("payload")
    sig = str(blob.get("signature") or "")
    if not isinstance(payload, dict) or not sig:
        return False, "missing_payload_or_signature"
    if not _verify_bytes(_canonical_payload(payload), sig):
        return False, "bad_signature"
    return True, "ok"


def _row_to_dict(row: Any) -> dict[str, Any]:
    d = dict(row)
    try:
        d["features"] = json.loads(d.get("features_json") or "[]")
    except Exception:
        d["features"] = []
    try:
        d["payload"] = json.loads(d.get("payload_json") or "{}")
    except Exception:
        d["payload"] = {}
    d["signed"] = {
        "payload": d.get("payload") or {},
        "alg": d.get("alg") or "ed25519",
        "signature": d.get("signature") or "",
        "kid": d.get("kid") or "license-v1",
    }
    return d


def issue_license(
    user_id: str,
    *,
    org_id: str | None = None,
    plan: str = "free",
    max_agents: int | None = None,
    features: list[str] | None = None,
    expires_at: float | None = None,
    grace_days: int = _DEFAULT_GRACE_DAYS,
) -> dict[str, Any]:
    """Create and persist a signed license for an org (or user-local scope)."""
    ensure_schema()
    ent = entitlements_for_plan(plan)
    lid = new_id()
    if not str(lid).startswith("lic_"):
        lid = f"lic_{lid}"
    payload = build_license_payload(
        license_id=lid,
        organization_id=org_id,
        plan=ent["plan"],
        max_agents=max_agents,
        features=features,
        expires_at=expires_at,
        grace_days=grace_days,
        status="active",
    )
    signed = sign_license_payload(payload)
    ts = now()
    c = get_conn()
    # Soft-revoke prior active licenses for same scope so one entitlement wins.
    if org_id:
        c.execute(
            "UPDATE securaiq_licenses SET status = 'superseded', revoked_at = ?, updated_at = ? "
            "WHERE org_id = ? AND status = 'active'",
            (ts, ts, org_id),
        )
    else:
        c.execute(
            "UPDATE securaiq_licenses SET status = 'superseded', revoked_at = ?, updated_at = ? "
            "WHERE user_id = ? AND (org_id IS NULL OR org_id = '') AND status = 'active'",
            (ts, ts, user_id),
        )
    c.execute(
        """
        INSERT INTO securaiq_licenses
        (id, user_id, org_id, plan, status, max_agents, features_json, issued_at, expires_at,
         grace_days, payload_json, signature, alg, kid, revoked_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
        """,
        (
            lid,
            user_id,
            (org_id or "").strip() or None,
            payload["plan"],
            payload.get("max_agents"),
            json.dumps(payload.get("features") or []),
            payload["issued_at"],
            payload.get("expires_at"),
            int(payload.get("grace_days") or _DEFAULT_GRACE_DAYS),
            json.dumps(payload),
            signed["signature"],
            signed["alg"],
            signed["kid"],
            ts,
            ts,
        ),
    )
    c.commit()
    lic = get_license(user_id, lid) or {}
    _publish_license_updated(
        user_id,
        org_id=org_id,
        action="issue",
        payload={**lic, "license_id": lic.get("id"), "mode": "active"},
    )
    return lic


def get_license(user_id: str, license_id: str) -> dict[str, Any] | None:
    ensure_schema()
    row = get_conn().execute(
        "SELECT * FROM securaiq_licenses WHERE id = ?", (license_id,)
    ).fetchone()
    if not row:
        return None
    d = _row_to_dict(row)
    if d.get("user_id") != user_id and user_id != "local":
        # Org-scoped visibility: allow if same org membership — best-effort.
        try:
            from app.tenancy import user_org_ids

            orgs = set(user_org_ids(user_id) or [])
            if d.get("org_id") and d["org_id"] in orgs:
                return d
        except Exception:
            pass
        return None
    return d


def get_active_license(user_id: str, *, org_id: str | None = None) -> dict[str, Any] | None:
    ensure_schema()
    c = get_conn()
    oid = (org_id or "").strip()
    if oid:
        row = c.execute(
            "SELECT * FROM securaiq_licenses WHERE org_id = ? AND status = 'active' "
            "ORDER BY created_at DESC LIMIT 1",
            (oid,),
        ).fetchone()
    else:
        row = c.execute(
            "SELECT * FROM securaiq_licenses WHERE user_id = ? AND status = 'active' "
            "AND (org_id IS NULL OR org_id = '') ORDER BY created_at DESC LIMIT 1",
            (user_id,),
        ).fetchone()
    return _row_to_dict(row) if row else None


def effective_entitlements(user_id: str, *, org_id: str | None = None) -> dict[str, Any]:
    """Resolve entitlements from active signed license, else billing plan defaults."""
    lic = get_active_license(user_id, org_id=org_id)
    if lic:
        mode = license_operational_mode(lic)
        payload = lic.get("payload") or {}
        raw_features = list(payload.get("features") or lic.get("features") or [])
        features, blocked = _apply_mode_to_features(raw_features, mode)
        # status_ok True only while fully active (not grace/restricted) for enroll gates
        status_ok = mode["mode"] in ("active", "warning", "critical") and mode["status_reason"] == "active"
        return {
            "source": "signed_license",
            "license_id": lic.get("id"),
            "plan": payload.get("plan") or lic.get("plan"),
            "plan_label": LICENSE_PLANS.get(payload.get("plan") or lic.get("plan") or "free", {}).get(
                "label", lic.get("plan")
            ),
            "max_agents": payload.get("max_agents", lic.get("max_agents")),
            "features": features,
            "features_blocked": blocked,
            "features_licensed": raw_features,
            "status_ok": status_ok,
            "status_reason": mode["status_reason"],
            "mode": mode["mode"],
            "warning_level": mode["warning_level"],
            "days_remaining": mode["days_remaining"],
            "expires_at": mode.get("expires_at") or payload.get("expires_at") or lic.get("expires_at"),
            "grace_until": mode.get("grace_until"),
            "grace_days": payload.get("grace_days") or lic.get("grace_days"),
            "allow_new_enrollment": mode["allow_new_enrollment"],
            "allow_premium_writes": mode["allow_premium_writes"],
            "allow_agent_checkin": mode["allow_agent_checkin"],
            "enforcement_enabled": license_enforcement_enabled(),
            "signed": lic.get("signed"),
        }
    # Fallback: user billing plan (messages) + license plan agent defaults
    try:
        from app.billing import get_user_plan

        plan = get_user_plan(user_id)
    except Exception:
        plan = "free"
    ent = entitlements_for_plan(plan)
    return {
        "source": "plan_default",
        "license_id": None,
        "plan": ent["plan"],
        "plan_label": ent["plan_label"],
        "max_agents": ent["max_agents"],
        "features": ent["features"],
        "features_blocked": [],
        "features_licensed": ent["features"],
        "status_ok": True,
        "status_reason": "plan_default",
        "mode": "active",
        "warning_level": "none",
        "days_remaining": None,
        "expires_at": None,
        "grace_until": None,
        "grace_days": _DEFAULT_GRACE_DAYS,
        "allow_new_enrollment": True,
        "allow_premium_writes": True,
        "allow_agent_checkin": True,
        "enforcement_enabled": license_enforcement_enabled(),
        "signed": None,
    }


def validate_license(user_id: str, *, org_id: str | None = None) -> dict[str, Any]:
    """Online validation response for dashboard / agent periodic check.

    Local registry/config may cache this payload — never trust local cache as SoT.
    """
    from app.activation_cache import build_activation_cache_payload

    ent = effective_entitlements(user_id, org_id=org_id)
    agents = count_active_agents(user_id, org_id=org_id)
    valid = ent.get("mode") not in ("revoked",) and (
        ent.get("allow_agent_checkin", True) or not license_enforcement_enabled()
    )
    # Soft: when enforcement off, always valid for continuity.
    if not license_enforcement_enabled():
        valid = True
    cache = build_activation_cache_payload(ent, agents_current=agents, org_id=org_id)
    out = {
        "valid": valid,
        "validated_at": now(),
        "revalidate_after_sec": 86400,
        "offline_grace_sec": int((ent.get("grace_days") or _DEFAULT_GRACE_DAYS) * 86400),
        **ent,
        "agents_current": agents,
        "activation_cache": cache,
        "message": _validate_message(ent),
    }
    _publish_license_updated(user_id, org_id=org_id, action="validate", payload=out)
    return out


def _publish_license_updated(
    user_id: str,
    *,
    org_id: str | None = None,
    action: str = "updated",
    payload: dict[str, Any] | None = None,
) -> None:
    try:
        from app.realtime_bus import publish

        body = payload or {}
        publish(
            type="license.updated",
            event_type="license.updated",
            user_id=user_id,
            org_id=org_id,
            action=action,
            mode=body.get("mode"),
            plan=body.get("plan"),
            license_id=body.get("license_id") or body.get("id"),
            valid=body.get("valid"),
            days_remaining=body.get("days_remaining"),
        )
    except Exception:
        pass


def _validate_message(ent: dict[str, Any]) -> str:
    mode = ent.get("mode") or "none"
    if mode == "revoked":
        return "License revoked — agent authentication rejected."
    if mode == "restricted":
        return (
            "License expired — restricted mode: visibility and evidence export remain; "
            "new premium scans, remediation, and AI are disabled. Renew to restore full entitlements."
        )
    if mode == "grace":
        return "License expired but inside grace window — renew soon; new agent enrollment is blocked."
    if mode in ("warning", "critical"):
        days = ent.get("days_remaining")
        return f"License active — {days} day(s) remaining. Renew before expiry."
    return "License active."


def issue_trial_license(
    user_id: str,
    *,
    org_id: str | None = None,
    plan: str = "pro",
    days: int = 30,
) -> dict[str, Any]:
    """Issue a signed N-day trial (default 30) — commercial activation experience."""
    days = max(1, min(int(days), 365))
    return issue_license(
        user_id,
        org_id=org_id,
        plan=plan,
        expires_at=now() + days * 86400,
        grace_days=_DEFAULT_GRACE_DAYS,
    )


def require_premium_feature(user_id: str, feature: str, *, org_id: str | None = None) -> None:
    """Raise ValueError with upgrade-oriented message when feature blocked."""
    if not license_enforcement_enabled():
        return
    ent = effective_entitlements(user_id, org_id=org_id)
    if not ent.get("allow_premium_writes") and feature.lower() in _PREMIUM_WRITE_FEATURES:
        raise ValueError(
            f"License restricted ({ent.get('mode')}): feature `{feature}` unavailable. "
            "Renew your subscription to restore premium capabilities."
        )
    if feature.lower() not in {str(f).lower() for f in (ent.get("features") or [])}:
        if ent.get("mode") in ("restricted", "revoked", "grace") and feature.lower() in _PREMIUM_WRITE_FEATURES:
            raise ValueError(
                f"License {ent.get('mode')}: feature `{feature}` unavailable. Upgrade or renew."
            )


def evaluate_license_status(lic: dict[str, Any], *, at: float | None = None) -> tuple[bool, str]:
    """Return (ok_for_new_enroll, reason). Expired+grace → ok False for new enroll."""
    mode = license_operational_mode(lic, at=at)
    reason = mode["status_reason"]
    return bool(mode["allow_new_enrollment"]), reason


def license_operational_mode(lic: dict[str, Any] | None, *, at: float | None = None) -> dict[str, Any]:
    """Classify license lifecycle for UI + enforcement (never brick agents on soft expiry).

    Modes:
      active | warning | critical | grace | restricted | revoked | none
    """
    ts = float(at if at is not None else now())
    out: dict[str, Any] = {
        "mode": "none",
        "status_reason": "none",
        "days_remaining": None,
        "expires_at": None,
        "grace_until": None,
        "allow_new_enrollment": True,
        "allow_premium_writes": True,
        "allow_agent_checkin": True,
        "warning_level": "none",  # none|warning|critical
    }
    if not lic:
        return out

    status = (lic.get("status") or "").lower()
    if status in ("revoked", "superseded") or lic.get("revoked_at"):
        out.update(
            {
                "mode": "revoked",
                "status_reason": status if status in ("revoked", "superseded") else "revoked",
                "allow_new_enrollment": False,
                "allow_premium_writes": False,
                "allow_agent_checkin": False,
                "warning_level": "critical",
            }
        )
        return out

    signed = lic.get("signed")
    if isinstance(signed, dict) and signed.get("signature"):
        ok, reason = verify_signed_license(signed)
        if not ok and license_enforcement_enabled():
            out.update(
                {
                    "mode": "revoked",
                    "status_reason": reason,
                    "allow_new_enrollment": False,
                    "allow_premium_writes": False,
                    "allow_agent_checkin": False,
                    "warning_level": "critical",
                }
            )
            return out

    payload = lic.get("payload") if isinstance(lic.get("payload"), dict) else lic
    exp = payload.get("expires_at") if isinstance(payload, dict) else lic.get("expires_at")
    grace_days = int(
        (payload.get("grace_days") if isinstance(payload, dict) else None)
        or lic.get("grace_days")
        or _DEFAULT_GRACE_DAYS
    )
    if exp is None or exp == "":
        out.update({"mode": "active", "status_reason": "active", "warning_level": "none"})
        return out
    try:
        exp_f = float(exp)
    except (TypeError, ValueError):
        out.update({"mode": "active", "status_reason": "active"})
        return out

    out["expires_at"] = exp_f
    grace_until = exp_f + grace_days * 86400
    out["grace_until"] = grace_until
    days_left = (exp_f - ts) / 86400.0
    out["days_remaining"] = round(days_left, 2)

    if ts <= exp_f:
        warning = "none"
        if days_left <= 3:
            warning = "critical"
        elif days_left <= 14:
            warning = "warning"
        mode = "critical" if warning == "critical" else ("warning" if warning == "warning" else "active")
        out.update(
            {
                "mode": mode,
                "status_reason": "active",
                "warning_level": warning,
                "allow_new_enrollment": True,
                "allow_premium_writes": True,
                "allow_agent_checkin": True,
            }
        )
        return out

    if ts <= grace_until:
        # Grace: existing agents continue; block new enrollment; premium still on.
        out.update(
            {
                "mode": "grace",
                "status_reason": "expired_grace",
                "days_remaining": round((grace_until - ts) / 86400.0, 2),
                "warning_level": "critical",
                "allow_new_enrollment": False,
                "allow_premium_writes": True,
                "allow_agent_checkin": True,
            }
        )
        return out

    # Past grace: restricted visibility — do NOT stop agents / revoke check-ins.
    out.update(
        {
            "mode": "restricted",
            "status_reason": "expired",
            "days_remaining": round((exp_f - ts) / 86400.0, 2),
            "warning_level": "critical",
            "allow_new_enrollment": False,
            "allow_premium_writes": False,
            "allow_agent_checkin": True,
        }
    )
    return out


def _apply_mode_to_features(features: list[str], mode: dict[str, Any]) -> tuple[list[str], list[str]]:
    feats = [str(f) for f in (features or [])]
    if mode.get("mode") == "revoked":
        return [], feats
    if mode.get("mode") == "restricted" or not mode.get("allow_premium_writes", True):
        allowed = [f for f in feats if f.lower() in _RESTRICTED_KEEP_FEATURES]
        blocked = [f for f in feats if f.lower() not in _RESTRICTED_KEEP_FEATURES]
        if not allowed:
            allowed = sorted(_RESTRICTED_KEEP_FEATURES)
        return allowed, blocked
    return feats, []


def count_active_agents(user_id: str, *, org_id: str | None = None) -> int:
    ensure_schema()
    from app.agents import ensure_schema as ensure_agents

    ensure_agents()
    c = get_conn()
    oid = (org_id or "").strip()
    if oid:
        row = c.execute(
            "SELECT COUNT(*) AS n FROM securaiq_agents WHERE org_id = ? AND revoked = 0",
            (oid,),
        ).fetchone()
    else:
        row = c.execute(
            "SELECT COUNT(*) AS n FROM securaiq_agents WHERE user_id = ? AND revoked = 0 "
            "AND (org_id IS NULL OR org_id = '')",
            (user_id,),
        ).fetchone()
    return int((row["n"] if row else 0) or 0)


def check_agent_enrollment_allowed(
    user_id: str,
    *,
    org_id: str | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Server-side enroll gate. Soft-allow when enforcement off."""
    ent = effective_entitlements(user_id, org_id=org_id)
    current = count_active_agents(user_id, org_id=org_id)
    ent["agents_current"] = current
    max_a = ent.get("max_agents")
    if not license_enforcement_enabled():
        return True, "enforcement_off", ent
    if not ent.get("allow_new_enrollment", ent.get("status_ok")):
        return False, f"license_{ent.get('status_reason') or ent.get('mode') or 'invalid'}", ent
    if max_a is None:
        return True, "unlimited", ent
    try:
        limit = int(max_a)
    except (TypeError, ValueError):
        return True, "unlimited", ent
    if current >= limit:
        return False, f"agent_quota_exceeded:{current}/{limit}", ent
    return True, "ok", ent


def has_feature(user_id: str, feature: str, *, org_id: str | None = None) -> bool:
    ent = effective_entitlements(user_id, org_id=org_id)
    feats = {str(f).lower() for f in (ent.get("features") or [])}
    return feature.lower() in feats


def check_feature(
    user_id: str,
    feature: str,
    *,
    org_id: str | None = None,
) -> dict[str, Any]:
    ent = effective_entitlements(user_id, org_id=org_id)
    allowed = has_feature(user_id, feature, org_id=org_id)
    if license_enforcement_enabled() and not ent.get("allow_premium_writes"):
        if feature.lower() in _PREMIUM_WRITE_FEATURES:
            allowed = False
    if license_enforcement_enabled() and ent.get("mode") == "revoked":
        allowed = False
    return {
        "feature": feature,
        "allowed": allowed,
        "plan": ent.get("plan"),
        "mode": ent.get("mode"),
        "status_ok": ent.get("status_ok"),
        "status_reason": ent.get("status_reason"),
        "enforcement_enabled": license_enforcement_enabled(),
        "message": None
        if allowed
        else f"Feature `{feature}` unavailable in mode={ent.get('mode')} ({ent.get('status_reason')})",
    }


def revoke_license(user_id: str, license_id: str) -> dict[str, Any] | None:
    """Mark a license revoked. Existing agents keep credentials until gateway rejects
    only if policy requires — enrollment is blocked immediately via status."""
    ensure_schema()
    lic = get_license(user_id, license_id)
    if not lic:
        # Allow global admin path via get by id
        row = get_conn().execute(
            "SELECT * FROM securaiq_licenses WHERE id = ?", (license_id,)
        ).fetchone()
        if not row:
            return None
        lic = _row_to_dict(row)
    ts = now()
    c = get_conn()
    c.execute(
        "UPDATE securaiq_licenses SET status = 'revoked', revoked_at = ?, updated_at = ? WHERE id = ?",
        (ts, ts, license_id),
    )
    c.commit()
    out = get_conn().execute(
        "SELECT * FROM securaiq_licenses WHERE id = ?", (license_id,)
    ).fetchone()
    d = _row_to_dict(out) if out else None
    if d:
        _publish_license_updated(
            user_id,
            org_id=d.get("org_id"),
            action="revoke",
            payload={**d, "license_id": d.get("id"), "mode": "revoked", "valid": False},
        )
    return d
