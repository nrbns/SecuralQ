"""File upload validation beyond extension + size checks.

`app/uploads.py` already enforced an extension allowlist, filename
sanitization, and a per-file size cap — but per docs/launch-readiness.md that
was only "partial" file validation. Two real gaps this closes:

  1. Extension spoofing — nothing checked that a file claiming to be
     `report.pdf` actually starts with a PDF magic byte, so a renamed
     executable would sail through and later get read back as "text" by
     `extract_text()`.
  2. No storage quota — `UPLOAD_MAX_MB` capped a single file, but a user
     could upload unlimited files with no aggregate ceiling.
"""

from __future__ import annotations

from pathlib import Path

# Magic bytes for the binary types we accept. Anything not in this map is
# treated as text and only checked for embedded executable signatures.
_MAGIC_SIGNATURES: dict[str, tuple[bytes, ...]] = {
    ".pdf": (b"%PDF-",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".webp": (b"RIFF",),  # WEBP is RIFF container; good enough signal, not a full parse
    ".bmp": (b"BM",),
    ".zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    ".docx": (b"PK\x03\x04",),
    ".xlsx": (b"PK\x03\x04",),
    ".pptx": (b"PK\x03\x04",),
    ".ipynb": (b"{",),  # JSON — loose check, real parse happens at ingest time
}

# Executable/script magic bytes that should never appear in an upload claiming
# to be a document/text/config file (renamed-executable smuggling).
_DANGEROUS_SIGNATURES: tuple[bytes, ...] = (
    b"MZ",  # Windows PE (.exe/.dll)
    b"\x7fELF",  # Linux ELF binary
    b"\xca\xfe\xba\xbe",  # Mach-O / Java class (fat binary)
    b"\xfe\xed\xfa",  # Mach-O
)


class UploadValidationError(ValueError):
    pass


def check_magic_bytes(filename: str, data: bytes) -> None:
    ext = Path(filename).suffix.lower()
    head = data[:16]

    expected = _MAGIC_SIGNATURES.get(ext)
    if expected and not any(head.startswith(sig) for sig in expected):
        raise UploadValidationError(
            f"File content doesn't match its `{ext}` extension (failed magic-byte check). "
            "This usually means the extension was changed on a different file type — rejected."
        )

    if not expected:
        # Text/config/code extension — must not actually be a binary executable.
        if any(head.startswith(sig) for sig in _DANGEROUS_SIGNATURES):
            raise UploadValidationError(
                f"File claims to be `{ext or 'no extension'}` but its content is an executable binary — rejected."
            )
        # Reject files with embedded NUL bytes early in a "text" file — a strong
        # signal it isn't actually text, regardless of what magic bytes say.
        if b"\x00" in data[:4096]:
            raise UploadValidationError(
                "File claims to be a text/code/config format but contains binary data — rejected."
            )


def check_user_quota(existing_total_bytes: int, incoming_bytes: int, quota_mb: int) -> None:
    quota_bytes = quota_mb * 1024 * 1024
    if existing_total_bytes + incoming_bytes > quota_bytes:
        used_mb = existing_total_bytes / (1024 * 1024)
        raise UploadValidationError(
            f"Upload would exceed your {quota_mb} MB storage quota "
            f"({used_mb:.1f} MB already used). Delete old files or ask an admin to raise UPLOAD_QUOTA_MB_PER_USER."
        )
