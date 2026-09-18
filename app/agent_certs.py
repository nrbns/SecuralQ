"""Optional per-agent client certificates (mTLS foundations).

Lab/default: bearer+HMAC remains authoritative. When AGENT_MTLS_ENABLED=true,
enrollment can issue a short-lived self-signed client cert stored on the agent
row. Full reverse-proxy mTLS termination is an ops deployment step (nginx/Caddy
client auth) — this module provides identity material + issue/renew/rotate/revoke.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any

from app.config import settings
from app.db import get_conn, new_id, now


def proxy_client_headers_from_map(headers: Any) -> tuple[str | None, str | None]:
    """Read nginx/Caddy client-cert headers from a mapping or Starlette Headers."""
    if headers is None:
        return None, None
    get = getattr(headers, "get", None)
    if not callable(get):
        return None, None
    verify = get("X-SSL-Client-Verify") or get("x-ssl-client-verify")
    fp = get("X-SSL-Client-Fingerprint") or get("x-ssl-client-fingerprint")
    return (str(verify) if verify is not None else None), (str(fp) if fp is not None else None)


def enforce_proxy_mtls(
    agent: dict[str, Any],
    *,
    client_verify: str | None = None,
    client_fingerprint: str | None = None,
    headers: Any = None,
) -> str | None:
    """Return error detail if proxy mTLS fails; None when OK / enforcement off."""
    if client_verify is None and client_fingerprint is None and headers is not None:
        client_verify, client_fingerprint = proxy_client_headers_from_map(headers)
    return verify_proxy_client_cert(
        agent,
        client_verify=client_verify,
        client_fingerprint=client_fingerprint,
    )


def mtls_enabled() -> bool:
    return bool(getattr(settings, "agent_mtls_enabled", False))


def mtls_proxy_verify_enabled() -> bool:
    return bool(getattr(settings, "agent_mtls_proxy_verify", False))


def verify_proxy_client_cert(
    agent: dict[str, Any],
    *,
    client_verify: str | None,
    client_fingerprint: str | None,
) -> str | None:
    """Return error string if proxy mTLS headers fail when enforcement is on.

    Expects nginx/Caddy to set X-SSL-Client-Verify and X-SSL-Client-Fingerprint
    after terminating client TLS. App must only be reachable via that proxy.

    Revoked fingerprints are always rejected when a fingerprint is presented,
    even if proxy verify is otherwise off (lab rollout safety).
    """
    got = (client_fingerprint or "").strip().lower().replace(":", "")
    if got and is_fingerprint_revoked(got):
        return "Client certificate revoked"

    if not mtls_proxy_verify_enabled():
        return None
    verify = (client_verify or "").strip().upper()
    # nginx: SUCCESS; Caddy may send "true" / "1" / "SUCCESS"
    ok_values = {"SUCCESS", "TRUE", "1", "OK", "YES"}
    if verify not in ok_values:
        return "Client certificate required (proxy mTLS verify failed)"
    if not getattr(settings, "agent_mtls_require_fingerprint_match", False):
        return None
    expected = (agent.get("certificate_fingerprint") or "").strip().lower().replace(":", "")
    if not expected:
        # Enrolled without cert — allow during rollout unless fingerprint required globally
        return None
    if not got or got != expected:
        return "Client certificate fingerprint mismatch"
    return None


def ensure_cert_columns() -> None:
    from app.db import table_columns

    c = get_conn()
    cols = table_columns(c, "securaiq_agents")
    additions = {
        "certificate_pem": "TEXT NOT NULL DEFAULT ''",
        "certificate_fingerprint": "TEXT NOT NULL DEFAULT ''",
        "certificate_expires_at": "REAL",
        "certificate_issued_at": "REAL",
        "certificate_public_key_pem": "TEXT NOT NULL DEFAULT ''",
        "certificate_revoked_at": "REAL",
        "certificate_serial": "TEXT NOT NULL DEFAULT ''",
    }
    for name, typedef in additions.items():
        if cols and name not in cols:
            try:
                c.execute(f"ALTER TABLE securaiq_agents ADD COLUMN {name} {typedef}")
            except Exception:
                pass
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS securaiq_agent_cert_revocations (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            serial TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            revoked_at REAL NOT NULL,
            revoked_by TEXT NOT NULL DEFAULT ''
        )
        """
    )
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_agent_cert_rev_fp "
        "ON securaiq_agent_cert_revocations(fingerprint)"
    )
    c.commit()


def is_fingerprint_revoked(fingerprint: str) -> bool:
    fp = (fingerprint or "").strip().lower().replace(":", "")
    if not fp:
        return False
    ensure_cert_columns()
    c = get_conn()
    row = c.execute(
        "SELECT 1 FROM securaiq_agent_cert_revocations WHERE fingerprint = ? LIMIT 1",
        (fp,),
    ).fetchone()
    return bool(row)


def _record_revocation(
    agent_id: str,
    *,
    fingerprint: str,
    serial: str = "",
    reason: str = "",
    revoked_by: str = "",
) -> None:
    fp = (fingerprint or "").strip().lower().replace(":", "")
    if not fp:
        return
    ensure_cert_columns()
    c = get_conn()
    c.execute(
        """
        INSERT INTO securaiq_agent_cert_revocations
        (id, agent_id, fingerprint, serial, reason, revoked_at, revoked_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (new_id(), agent_id, fp, serial or "", reason or "", now(), revoked_by or ""),
    )
    c.commit()


def issue_agent_client_certificate(agent_id: str, *, days: int = 60) -> dict[str, Any]:
    """Issue a lab self-signed client cert for the agent. Returns PEMs once."""
    ensure_cert_columns()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    days = max(7, min(int(days), 365))
    key = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"securaiq-agent-{agent_id[:16]}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecuraIQ"),
        ]
    )
    now_dt = dt.datetime.utcnow()
    serial = x509.random_serial_number()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now_dt - dt.timedelta(minutes=1))
        .not_valid_after(now_dt + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, algorithm=None)
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    issued = now()
    expires = issued + days * 86400
    serial_hex = format(int(serial), "x")
    c = get_conn()
    c.execute(
        """
        UPDATE securaiq_agents
        SET certificate_pem = ?, certificate_fingerprint = ?,
            certificate_expires_at = ?, certificate_issued_at = ?,
            certificate_public_key_pem = ?, certificate_revoked_at = NULL,
            certificate_serial = ?
        WHERE id = ?
        """,
        (cert_pem, fp, expires, issued, pub_pem, serial_hex, agent_id),
    )
    c.commit()
    return {
        "agent_id": agent_id,
        "certificate_pem": cert_pem,
        "private_key_pem": key_pem,  # returned ONCE — not re-readable as private key
        "fingerprint": fp,
        "serial": serial_hex,
        "expires_at": expires,
        "issued_at": issued,
        "note": (
            "Lab self-signed client cert. Terminate mTLS at the reverse proxy; "
            "bearer/HMAC remains valid during rollout."
        ),
    }


def revoke_agent_certificate(
    agent_id: str,
    *,
    reason: str = "revoked",
    revoked_by: str = "",
) -> dict[str, Any]:
    """Revoke current device cert (fingerprint denylist + clear active fields)."""
    ensure_cert_columns()
    c = get_conn()
    row = c.execute(
        "SELECT certificate_fingerprint, certificate_serial FROM securaiq_agents WHERE id = ?",
        (agent_id,),
    ).fetchone()
    if not row:
        return {"ok": False, "error": "agent_not_found"}
    fp = (row["certificate_fingerprint"] if hasattr(row, "keys") else row[0]) or ""
    serial = (row["certificate_serial"] if hasattr(row, "keys") else (row[1] if len(row) > 1 else "")) or ""
    fp = str(fp).strip()
    if fp:
        _record_revocation(
            agent_id,
            fingerprint=fp,
            serial=str(serial),
            reason=reason,
            revoked_by=revoked_by,
        )
    ts = now()
    c.execute(
        """
        UPDATE securaiq_agents
        SET certificate_pem = '', certificate_fingerprint = '',
            certificate_public_key_pem = '', certificate_serial = '',
            certificate_revoked_at = ?, certificate_expires_at = NULL
        WHERE id = ?
        """,
        (ts, agent_id),
    )
    c.commit()
    return {"ok": True, "agent_id": agent_id, "revoked_fingerprint": fp or None, "revoked_at": ts}


def rotate_agent_client_certificate(
    agent_id: str,
    *,
    days: int | None = None,
    reason: str = "rotation",
    rotated_by: str = "",
) -> dict[str, Any]:
    """Revoke current cert (if any) and issue a new short-lived client cert."""
    ensure_cert_columns()
    prev = revoke_agent_certificate(agent_id, reason=reason, revoked_by=rotated_by)
    d = int(days) if days is not None else int(getattr(settings, "agent_mtls_cert_days", 60) or 60)
    issued = issue_agent_client_certificate(agent_id, days=d)
    return {
        "ok": True,
        "rotated": True,
        "previous": prev,
        "mtls": {
            "certificate_pem": issued.get("certificate_pem"),
            "private_key_pem": issued.get("private_key_pem"),
            "fingerprint": issued.get("fingerprint"),
            "serial": issued.get("serial"),
            "expires_at": issued.get("expires_at"),
            "issued_at": issued.get("issued_at"),
            "note": issued.get("note"),
        },
    }


def renew_agent_client_certificate(
    agent_id: str,
    *,
    days: int | None = None,
    force: bool = False,
    renew_before_sec: int = 7 * 86400,
    renewed_by: str = "",
) -> dict[str, Any]:
    """Renew if expiring soon (or ``force``). Same as rotate when renewal is due."""
    ensure_cert_columns()
    c = get_conn()
    row = c.execute(
        "SELECT certificate_fingerprint, certificate_expires_at FROM securaiq_agents WHERE id = ?",
        (agent_id,),
    ).fetchone()
    if not row:
        return {"ok": False, "error": "agent_not_found"}
    fp = (row["certificate_fingerprint"] if hasattr(row, "keys") else row[0]) or ""
    exp = row["certificate_expires_at"] if hasattr(row, "keys") else row[1]
    ts = now()
    try:
        exp_f = float(exp) if exp is not None else 0.0
    except (TypeError, ValueError):
        exp_f = 0.0
    due = force or not fp or exp_f <= 0 or exp_f <= ts + max(0, int(renew_before_sec))
    if not due:
        return {
            "ok": True,
            "renewed": False,
            "reason": "not_due",
            "expires_at": exp_f,
            "fingerprint": str(fp),
        }
    out = rotate_agent_client_certificate(
        agent_id,
        days=days,
        reason="renewal" if not force else "forced_renewal",
        rotated_by=renewed_by,
    )
    out["renewed"] = True
    return out


def agent_cert_summary(agent: dict[str, Any] | None) -> dict[str, Any] | None:
    if not agent:
        return None
    fp = (agent.get("certificate_fingerprint") or "").strip()
    revoked_at = agent.get("certificate_revoked_at")
    if not fp and not revoked_at:
        return None
    return {
        "fingerprint": fp or None,
        "expires_at": agent.get("certificate_expires_at"),
        "issued_at": agent.get("certificate_issued_at"),
        "serial": agent.get("certificate_serial") or "",
        "revoked_at": revoked_at,
        "has_certificate": bool(fp),
        "revoked": bool(revoked_at) and not fp,
    }


def fleet_mtls_status() -> dict[str, Any]:
    """#248 — fleet-wide mTLS readiness (CA material + enforcement flags)."""
    from pathlib import Path

    ca_dir = Path(settings.data_dir) / "mtls"
    ca_cert = ca_dir / "ca.crt"
    ca_key = ca_dir / "ca.key"
    ca_ready = ca_cert.is_file() and ca_key.is_file()
    if mtls_enabled() and not ca_ready:
        try:
            _ensure_lab_ca(ca_dir)
            ca_ready = ca_cert.is_file() and ca_key.is_file()
        except Exception as exc:
            return {
                "enabled": True,
                "ca_ready": False,
                "error": str(exc)[:200],
                "proxy_verify": mtls_proxy_verify_enabled(),
            }
    enrolled = 0
    with_cert = 0
    try:
        from app.db import table_columns

        cols = table_columns(get_conn(), "securaiq_agents")
        if cols:
            enrolled = int(
                get_conn()
                .execute("SELECT COUNT(*) AS n FROM securaiq_agents WHERE COALESCE(revoked,0)=0")
                .fetchone()["n"]
            )
            if "certificate_fingerprint" in cols:
                with_cert = int(
                    get_conn()
                    .execute(
                        "SELECT COUNT(*) AS n FROM securaiq_agents WHERE COALESCE(revoked,0)=0 "
                        "AND COALESCE(certificate_fingerprint,'') != ''"
                    )
                    .fetchone()["n"]
                )
    except Exception:
        pass
    return {
        "enabled": mtls_enabled(),
        "ca_ready": ca_ready,
        "ca_path": str(ca_cert) if ca_ready else None,
        "proxy_verify": mtls_proxy_verify_enabled(),
        "require_fingerprint_match": bool(getattr(settings, "agent_mtls_require_fingerprint_match", False)),
        "agents_enrolled": enrolled,
        "agents_with_client_cert": with_cert,
        "ready_for_proxy_enforce": mtls_enabled() and ca_ready,
    }


def _ensure_lab_ca(ca_dir: Path) -> None:
    """Create a lab self-signed CA if missing (cryptography)."""
    from pathlib import Path as _P

    ca_dir = _P(ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    cert_path = ca_dir / "ca.crt"
    key_path = ca_dir / "ca.key"
    if cert_path.is_file() and key_path.is_file():
        return
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecuraIQ Lab Agent CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.utcnow() - dt.timedelta(minutes=1))
        .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
