"""SAML ACS signature verification — real crypto round-trip (#256)."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from tests._http_test_utils import configure_isolated_settings

signxml = pytest.importorskip("signxml")
pytest.importorskip("lxml")
pytest.importorskip("cryptography")


def _lab_idp_material():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lab-idp")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return key_pem, cert_pem


def _signed_saml_b64(*, key_pem: str, cert_pem: str, nameid: str = "alice@lab.local", issuer: str = "https://idp.lab"):
    from lxml import etree
    from signxml import XMLSigner
    import signxml as sx

    xml = f"""<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
 ID="_r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject><saml:NameID>{nameid}</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>"""
    root = etree.fromstring(xml.encode())
    signed = XMLSigner(method=sx.methods.enveloped).sign(root, key=key_pem, cert=cert_pem)
    return base64.b64encode(etree.tostring(signed)).decode("ascii")


def test_saml_verify_accepts_signed_assertion(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app import saml_scaffold
    from app.config import settings

    key_pem, cert_pem = _lab_idp_material()
    monkeypatch.setattr(settings, "saml_enabled", True, raising=False)
    monkeypatch.setattr(settings, "saml_idp_x509_cert", cert_pem, raising=False)
    monkeypatch.setattr(settings, "saml_idp_entity_id", "https://idp.lab", raising=False)

    b64 = _signed_saml_b64(key_pem=key_pem, cert_pem=cert_pem)
    out = saml_scaffold.receive_acs({"SAMLResponse": b64})
    assert out["accepted"] is True
    assert out["verified_signature"] is True
    assert out["nameid"] == "alice@lab.local"


def test_saml_verify_rejects_wrong_cert(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app import saml_scaffold
    from app.config import settings

    key_pem, cert_pem = _lab_idp_material()
    _k2, other_cert = _lab_idp_material()
    monkeypatch.setattr(settings, "saml_enabled", True, raising=False)
    monkeypatch.setattr(settings, "saml_idp_x509_cert", other_cert, raising=False)

    b64 = _signed_saml_b64(key_pem=key_pem, cert_pem=cert_pem)
    with pytest.raises(ValueError, match="fail-closed|verification failed|signature"):
        saml_scaffold.receive_acs({"SAMLResponse": b64})


def test_saml_login_issues_session_for_matching_user(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app import saml_scaffold
    from app.auth import login_via_saml_nameid, register_user
    from app.config import settings

    key_pem, cert_pem = _lab_idp_material()
    register_user("alice", "password12345", email="alice@lab.local")
    monkeypatch.setattr(settings, "saml_enabled", True, raising=False)
    monkeypatch.setattr(settings, "saml_idp_x509_cert", cert_pem, raising=False)

    b64 = _signed_saml_b64(key_pem=key_pem, cert_pem=cert_pem)
    acs = saml_scaffold.receive_acs({"SAMLResponse": b64})
    assert acs["accepted"] is True
    user, token = login_via_saml_nameid(acs["nameid"])  # type: ignore[misc]
    assert user.username == "alice"
    assert len(token) > 20
