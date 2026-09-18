"""SAML 2.0 SP scaffold (#256) — metadata + fail-closed ACS with XML-DSig verify.

Production login requires:
  1. SAML_ENABLED=true
  2. SAML_IDP_X509_CERT (IdP signing certificate PEM)
  3. Optional dependency ``signxml`` (``pip install -r requirements-saml.txt``)

Without signature verification this module **never** returns accepted=True.
A lab-only receipt mode (SAML_ALLOW_UNVERIFIED_LAB=true) may audit the POST
but still refuses to accept the assertion for login.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Any
from xml.sax.saxutils import escape

from app.config import settings
from app.db import audit

_log = logging.getLogger("securaiq.saml")

_NAMEID_RE = re.compile(
    r"<(?:[\w-]+:)?NameID\b[^>]*>([^<]+)</(?:[\w-]+:)?NameID>",
    re.IGNORECASE | re.DOTALL,
)
_ISSUER_RE = re.compile(
    r"<(?:[\w-]+:)?Issuer\b[^>]*>([^<]+)</(?:[\w-]+:)?Issuer>",
    re.IGNORECASE | re.DOTALL,
)
_STATUS_RE = re.compile(
    r"<(?:[\w-]+:)?StatusCode\b[^>]*\bValue\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


def enabled() -> bool:
    return bool(getattr(settings, "saml_enabled", False))


def allow_unverified_lab() -> bool:
    return bool(getattr(settings, "saml_allow_unverified_lab", False))


def idp_cert_pem() -> str:
    return str(getattr(settings, "saml_idp_x509_cert", "") or "").strip()


def signature_backend_available() -> bool:
    try:
        import signxml  # noqa: F401

        return True
    except Exception:
        return False


def production_ready() -> bool:
    return enabled() and bool(idp_cert_pem()) and signature_backend_available()


def status() -> dict[str, Any]:
    return {
        "protocol": "saml2",
        "enabled": enabled(),
        "sp_entity_id": (getattr(settings, "saml_sp_entity_id", None) or "http://127.0.0.1:8080/saml/metadata"),
        "acs_url": (getattr(settings, "saml_acs_url", None) or "http://127.0.0.1:8080/api/auth/saml/acs"),
        "idp_entity_id": (getattr(settings, "saml_idp_entity_id", None) or "") or None,
        "idp_sso_url": (getattr(settings, "saml_idp_sso_url", None) or "") or None,
        "idp_cert_configured": bool(idp_cert_pem()),
        "signature_backend": "signxml" if signature_backend_available() else None,
        "signature_verification_required": True,
        "allow_unverified_lab": allow_unverified_lab(),
        "production_ready": production_ready(),
        "note": (
            "ACS fail-closed: assertions are never accepted without XML-DSig verification. "
            "Set SAML_IDP_X509_CERT and install signxml before wiring a real IdP. "
            "SAML_ALLOW_UNVERIFIED_LAB only audits receipts — it does not accept login."
        ),
    }


def sp_metadata() -> str:
    st = status()
    eid = escape(st["sp_entity_id"])
    acs = escape(st["acs_url"])
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{eid}">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="{acs}" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""


def _decode_response(raw: str) -> bytes:
    cleaned = "".join(raw.split())
    try:
        return base64.b64decode(cleaned, validate=False)
    except Exception as exc:
        raise ValueError(f"SAMLResponse is not valid base64: {exc}") from exc


def _extract_claims(xml_bytes: bytes) -> dict[str, str | None]:
    text = xml_bytes.decode("utf-8", errors="replace")
    nameid = None
    m = _NAMEID_RE.search(text)
    if m:
        nameid = m.group(1).strip()
    issuer = None
    m = _ISSUER_RE.search(text)
    if m:
        issuer = m.group(1).strip()
    status_code = None
    m = _STATUS_RE.search(text)
    if m:
        status_code = m.group(1).strip()
    return {"nameid": nameid, "issuer": issuer, "status_code": status_code}


def verify_saml_response(raw_b64: str, *, idp_cert: str | None = None) -> dict[str, Any]:
    """Verify XML-DSig on a base64 SAMLResponse using IdP X.509 cert.

    Raises ValueError when verification cannot be completed successfully.
    """
    cert = (idp_cert if idp_cert is not None else idp_cert_pem()).strip()
    if not cert:
        raise ValueError(
            "SAML_IDP_X509_CERT is required for signature verification — "
            "refusing unverified assertion"
        )
    if not signature_backend_available():
        raise ValueError(
            "signxml is not installed — cannot verify SAML signatures. "
            "Install with: pip install -r requirements-saml.txt"
        )
    try:
        from lxml import etree
        from signxml import XMLVerifier
    except Exception as exc:
        raise ValueError(f"signxml/lxml import failed: {exc}") from exc

    xml_bytes = _decode_response(raw_b64)
    try:
        root = etree.fromstring(xml_bytes)
        verified = XMLVerifier().verify(root, x509_cert=cert)
    except Exception as exc:
        raise ValueError(f"SAML signature verification failed: {exc}") from exc

    signed_root = getattr(verified, "signed_xml", None)
    if signed_root is None:
        signed_root = root
    signed_bytes = etree.tostring(signed_root)
    claims = _extract_claims(signed_bytes if isinstance(signed_bytes, bytes) else xml_bytes)

    expected_idp = (getattr(settings, "saml_idp_entity_id", None) or "").strip()
    if expected_idp and claims.get("issuer") and claims["issuer"] != expected_idp:
        raise ValueError(
            f"SAML Issuer mismatch: got {claims['issuer']!r}, expected {expected_idp!r}"
        )

    status_code = claims.get("status_code") or ""
    if status_code and not status_code.endswith(":Success"):
        raise ValueError(f"SAML StatusCode is not Success: {status_code}")

    if not claims.get("nameid"):
        raise ValueError("Verified SAMLResponse missing NameID — refusing login")

    return {
        "ok": True,
        "verified_signature": True,
        "nameid": claims["nameid"],
        "issuer": claims.get("issuer"),
        "status_code": status_code or None,
        "signed_xml_tag": str(getattr(signed_root, "tag", "")),
    }


def receive_acs(payload: dict[str, Any], *, actor: str | None = None) -> dict[str, Any]:
    """ACS handler — fail closed unless signature verifies.

    Never returns accepted=True without verified_signature=True.
    """
    if not enabled():
        raise ValueError("SAML is disabled (set SAML_ENABLED=true)")
    raw = (payload.get("SAMLResponse") or payload.get("saml_response") or "").strip()
    if len(raw) < 8:
        raise ValueError("SAMLResponse required")

    audit(
        "saml_acs_received",
        actor,
        {
            "bytes": len(raw),
            "relay_state": bool(payload.get("RelayState")),
            "idp_cert_configured": bool(idp_cert_pem()),
            "signature_backend": signature_backend_available(),
        },
    )

    try:
        verified = verify_saml_response(raw)
        audit(
            "saml_acs_verified",
            actor,
            {
                "verified_signature": True,
                "nameid": verified.get("nameid"),
                "issuer": verified.get("issuer"),
            },
        )
        return {
            "ok": True,
            "accepted": True,
            "verified_signature": True,
            "nameid": verified.get("nameid"),
            "issuer": verified.get("issuer"),
            "detail": verified,
            "note": "Assertion signature verified against SAML_IDP_X509_CERT",
        }
    except ValueError as exc:
        msg = str(exc)
        if allow_unverified_lab():
            audit(
                "saml_acs_lab_receipt_only",
                actor,
                {"error": msg[:200], "accepted": False},
            )
            return {
                "ok": True,
                "accepted": False,
                "verified_signature": False,
                "lab_receipt_only": True,
                "error": msg,
                "note": (
                    "Lab receipt recorded only — assertion NOT accepted for login. "
                    "Configure SAML_IDP_X509_CERT + signxml for production SSO."
                ),
            }
        audit("saml_acs_rejected", actor, {"error": msg[:200]})
        raise ValueError(
            f"SAML assertion rejected (fail-closed): {msg}. "
            "Set SAML_IDP_X509_CERT and install signxml, or use "
            "SAML_ALLOW_UNVERIFIED_LAB=true for receipt-only lab testing "
            "(still does not accept login)."
        ) from exc
