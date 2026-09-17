"""SAML 2.0 SP scaffold (#256) — metadata + ACS stub.

Full assertion crypto needs pysaml2/xmlsec in production IdP integration.
This module is real enough for config/status/metadata export and ACS receipt logging.
"""

from __future__ import annotations

from typing import Any
from xml.sax.saxutils import escape

from app.config import settings
from app.db import audit


def enabled() -> bool:
    return bool(getattr(settings, "saml_enabled", False))


def status() -> dict[str, Any]:
    return {
        "protocol": "saml2",
        "enabled": enabled(),
        "sp_entity_id": (getattr(settings, "saml_sp_entity_id", None) or "http://127.0.0.1:8080/saml/metadata"),
        "acs_url": (getattr(settings, "saml_acs_url", None) or "http://127.0.0.1:8080/api/auth/saml/acs"),
        "idp_entity_id": (getattr(settings, "saml_idp_entity_id", None) or "") or None,
        "idp_sso_url": (getattr(settings, "saml_idp_sso_url", None) or "") or None,
        "note": "Enable SAML_ENABLED + IdP metadata for production SSO",
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


def receive_acs(payload: dict[str, Any], *, actor: str | None = None) -> dict[str, Any]:
    """Lab ACS: accept SAMLResponse presence and audit; no signature verify without xmlsec."""
    if not enabled():
        raise ValueError("SAML is disabled (set SAML_ENABLED=true)")
    raw = (payload.get("SAMLResponse") or payload.get("saml_response") or "").strip()
    if len(raw) < 8:
        raise ValueError("SAMLResponse required")
    audit("saml_acs_received", actor, {"bytes": len(raw), "relay_state": bool(payload.get("RelayState"))})
    return {
        "ok": True,
        "accepted": True,
        "verified_signature": False,
        "note": "Install IdP-signed assertion verification (xmlsec) before production SSO",
    }
