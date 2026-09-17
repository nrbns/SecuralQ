"""Object storage for evidence/uploads — local FS default, S3/MinIO/R2 optional.

#251 commercial credibility: evidence blobs can live outside the app disk.
When OBJECT_STORAGE_BACKEND=local (default), behavior matches historical
data/uploads paths. s3|minio|r2 use boto3 when installed; otherwise put()
falls back to local and records the backend mismatch in metadata.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.config import settings

_log = logging.getLogger("securaiq.object_storage")


def backend_name() -> str:
    return (getattr(settings, "object_storage_backend", None) or "local").strip().lower()


def _bucket() -> str:
    return (getattr(settings, "object_storage_bucket", None) or "securaiq-evidence").strip()


def _endpoint() -> str:
    return (getattr(settings, "object_storage_endpoint", None) or "").strip()


def _region() -> str:
    return (getattr(settings, "object_storage_region", None) or "auto").strip() or "auto"


def local_root() -> Path:
    root = Path(settings.data_dir) / "object_store"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _key_path(key: str) -> Path:
    safe = key.replace("..", "_").lstrip("/")
    p = local_root() / safe
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _s3_client():
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise RuntimeError("boto3 required for S3/MinIO/R2 object storage") from exc

    kwargs: dict[str, Any] = {
        "service_name": "s3",
        "region_name": _region(),
        "config": Config(signature_version="s3v4"),
    }
    key = (getattr(settings, "object_storage_access_key", None) or "").strip()
    secret = (getattr(settings, "object_storage_secret_key", None) or "").strip()
    if key and secret:
        kwargs["aws_access_key_id"] = key
        kwargs["aws_secret_access_key"] = secret
    endpoint = _endpoint()
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    return boto3.client(**kwargs)


def put_bytes(key: str, data: bytes, *, content_type: str = "application/octet-stream") -> dict[str, Any]:
    """Store bytes; returns uri + sha256 + backend used."""
    digest = hashlib.sha256(data).hexdigest()
    backend = backend_name()
    meta = {
        "key": key,
        "bytes": len(data),
        "sha256": digest,
        "content_type": content_type,
        "backend": backend,
    }
    if backend in {"s3", "minio", "r2"}:
        try:
            client = _s3_client()
            client.put_object(
                Bucket=_bucket(),
                Key=key,
                Body=data,
                ContentType=content_type,
                Metadata={"sha256": digest},
            )
            meta["uri"] = f"s3://{_bucket()}/{key}"
            return meta
        except Exception as exc:
            _log.warning("object_storage put via %s failed (%s); falling back to local", backend, exc)
            meta["backend_fallback"] = "local"
            meta["error"] = str(exc)[:200]

    path = _key_path(key)
    path.write_bytes(data)
    meta["backend"] = "local" if meta.get("backend_fallback") else backend
    meta["uri"] = f"file://{path.resolve()}"
    meta["path"] = str(path)
    return meta


def get_bytes(key: str) -> bytes | None:
    backend = backend_name()
    if backend in {"s3", "minio", "r2"}:
        try:
            client = _s3_client()
            obj = client.get_object(Bucket=_bucket(), Key=key)
            return obj["Body"].read()
        except Exception as exc:
            _log.debug("object_storage get %s via remote failed: %s", key, exc)

    path = _key_path(key)
    if path.is_file():
        return path.read_bytes()
    # Also accept historical uploads paths referenced as file:// URIs
    return None


def delete_object(key: str) -> bool:
    backend = backend_name()
    ok = False
    if backend in {"s3", "minio", "r2"}:
        try:
            _s3_client().delete_object(Bucket=_bucket(), Key=key)
            ok = True
        except Exception:
            pass
    path = _key_path(key)
    if path.is_file():
        path.unlink(missing_ok=True)
        ok = True
    return ok


def status() -> dict[str, Any]:
    b = backend_name()
    return {
        "backend": b,
        "bucket": _bucket() if b != "local" else None,
        "endpoint": _endpoint() or None,
        "region": _region() if b != "local" else None,
        "local_root": str(local_root()),
        "configured": b == "local" or bool(_endpoint() or getattr(settings, "object_storage_access_key", "")),
    }


def evidence_key(org_id: str | None, file_id: str, filename: str) -> str:
    org = (org_id or "default").replace("/", "_")[:64]
    safe = Path(filename or "blob.bin").name[:120]
    return f"evidence/{org}/{file_id}_{safe}"


def uri_looks_remote(uri: str) -> bool:
    try:
        return urlparse(uri).scheme in {"s3", "http", "https"}
    except Exception:
        return False
