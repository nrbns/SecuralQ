"""KMS / envelope encryption facade (#257).

Default: local Fernet via secrets_crypto (lab). Optional AWS KMS when
KMS_PROVIDER=aws and KMS_KEY_ID is set (boto3). Never logs plaintext.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

from app.config import settings

_log = logging.getLogger("securaiq.kms")


def provider() -> str:
    return (getattr(settings, "kms_provider", None) or "local").strip().lower()


def status() -> dict[str, Any]:
    p = provider()
    return {
        "provider": p,
        "key_id": (getattr(settings, "kms_key_id", None) or "")[:80] or None,
        "ready": p == "local" or bool(getattr(settings, "kms_key_id", "")),
    }


def encrypt(plaintext: str | bytes) -> dict[str, Any]:
    raw = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
    p = provider()
    if p == "aws":
        try:
            return _aws_encrypt(raw)
        except Exception as exc:
            _log.warning("AWS KMS encrypt failed (%s); falling back to local", exc)
    from app.secrets_crypto import encrypt_value

    token = encrypt_value(raw.decode("utf-8") if isinstance(plaintext, str) else base64.b64encode(raw).decode("ascii"))
    return {"ciphertext": token, "provider": "local", "alg": "fernet"}


def decrypt(blob: str | dict[str, Any]) -> bytes:
    if isinstance(blob, dict):
        ct = blob.get("ciphertext") or ""
        prov = blob.get("provider") or provider()
    else:
        ct = blob
        prov = "aws" if str(blob).startswith("kms:aws:") else "local"
    if prov == "aws" or str(ct).startswith("kms:aws:"):
        try:
            return _aws_decrypt(str(ct))
        except Exception as exc:
            _log.warning("AWS KMS decrypt failed: %s", exc)
            raise
    from app.secrets_crypto import decrypt_value

    plain = decrypt_value(str(ct))
    try:
        return base64.b64decode(plain)
    except Exception:
        return plain.encode("utf-8")


def _aws_encrypt(raw: bytes) -> dict[str, Any]:
    import boto3

    key_id = (getattr(settings, "kms_key_id", None) or "").strip()
    if not key_id:
        raise RuntimeError("KMS_KEY_ID required for aws provider")
    client = boto3.client("kms", region_name=getattr(settings, "kms_region", None) or "us-east-1")
    out = client.encrypt(KeyId=key_id, Plaintext=raw)
    ct = base64.b64encode(out["CiphertextBlob"]).decode("ascii")
    return {"ciphertext": f"kms:aws:{ct}", "provider": "aws", "alg": "aws-kms", "key_id": key_id}


def _aws_decrypt(token: str) -> bytes:
    import boto3

    raw_b64 = token.split("kms:aws:", 1)[-1]
    client = boto3.client("kms", region_name=getattr(settings, "kms_region", None) or "us-east-1")
    out = client.decrypt(CiphertextBlob=base64.b64decode(raw_b64))
    return out["Plaintext"]
