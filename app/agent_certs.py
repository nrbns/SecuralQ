"""Optional per-agent client certificates (mTLS foundations).

Lab/default: bearer+HMAC remains authoritative. When AGENT_MTLS_ENABLED=true,
enrollment can issue a short-lived self-signed client cert stored on the agent
row. Full reverse-proxy mTLS termination is an ops deployment step (nginx/Caddy
client auth) — this module provides identity material + schema only.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any

from app.config import settings
from app.db import get_conn, now


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
    """
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
    got = (client_fingerprint or "").strip().lower().replace(":", "")
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
    }
    for name, typedef in additions.items():
        if cols and name not in cols:
            try:
                c.execute(f"ALTER TABLE securaiq_agents ADD COLUMN {name} {typedef}")
            except Exception:
                pass
    c.commit()


def issue_agent_client_certificate(agent_id: str, *, days: int = 60) -> dict[str, Any]:
    """Issue a lab self-signed client cert for the agent. Returns PEMs once."""
    ensure_cert_columns()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
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
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
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
    c = get_conn()
    c.execute(
        """
        UPDATE securaiq_agents
        SET certificate_pem = ?, certificate_fingerprint = ?,
            certificate_expires_at = ?, certificate_issued_at = ?,
            certificate_public_key_pem = ?
        WHERE id = ?
        """,
        (cert_pem, fp, expires, issued, pub_pem, agent_id),
    )
    c.commit()
    return {
        "agent_id": agent_id,
        "certificate_pem": cert_pem,
        "private_key_pem": key_pem,  # returned ONCE to enroll response — not re-readable
        "fingerprint": fp,
        "expires_at": expires,
        "issued_at": issued,
        "note": (
            "Lab self-signed client cert. Terminate mTLS at the reverse proxy; "
            "bearer/HMAC remains valid during rollout."
        ),
    }


def agent_cert_summary(agent: dict[str, Any] | None) -> dict[str, Any] | None:
    if not agent:
        return None
    fp = (agent.get("certificate_fingerprint") or "").strip()
    if not fp:
        return None
    return {
        "fingerprint": fp,
        "expires_at": agent.get("certificate_expires_at"),
        "issued_at": agent.get("certificate_issued_at"),
        "has_certificate": True,
    }
