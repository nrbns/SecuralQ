"""Envelope encryption for secret values persisted to .env.

Was a real gap: `.env` held API keys, tokens, and the bootstrap admin
password in plaintext; `app/secrets.py` only masked them in API responses,
it never protected the file on disk. This encrypts those specific fields at
rest with a key that does NOT live in `.env` itself (so a leaked `.env`
backup or git-add mistake doesn't also leak the key).

Key resolution order:
  1. `ENV_SECRET_ENCRYPTION_KEY` in the real process environment (recommended
     for production — inject via your secrets manager / container orchestrator).
  2. `data/.secret.key` — auto-generated on first use with owner-only
     permissions. Fine for local/alpha use; back this file up separately from
     `data/` app-data backups (see docs/backup-dr.md).

If no key can be resolved (e.g. running read-only), values are stored as
plaintext exactly like before — this is additive, not a breaking change.
"""

from __future__ import annotations

import os
import stat

ENC_PREFIX = "enc:v1:"

_KEY_ENV_VAR = "ENV_SECRET_ENCRYPTION_KEY"
from app.paths import project_root

_KEY_FILE = project_root() / "data" / ".secret.key"

_fernet = None  # lazy singleton


def _load_or_create_key() -> bytes:
    env_key = os.environ.get(_KEY_ENV_VAR)
    if env_key:
        return env_key.encode() if isinstance(env_key, str) else env_key

    if _KEY_FILE.exists():
        return _KEY_FILE.read_bytes().strip()

    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_bytes(key)
    try:
        os.chmod(_KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600 — owner read/write only
    except OSError:
        pass  # best-effort on platforms without POSIX perms (e.g. some Windows filesystems)
    return key


def _get_fernet():
    global _fernet
    if _fernet is None:
        from cryptography.fernet import Fernet

        _fernet = Fernet(_load_or_create_key())
    return _fernet


def encrypt_value(plaintext: str) -> str:
    if not plaintext:
        return plaintext
    try:
        token = _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")
        return ENC_PREFIX + token
    except Exception:
        # Encryption unavailable (e.g. cryptography not installed) — fail open to
        # plaintext rather than breaking the app; this matches pre-existing behavior.
        return plaintext


def decrypt_value(stored: str) -> str:
    if not stored or not stored.startswith(ENC_PREFIX):
        return stored
    token = stored[len(ENC_PREFIX):]
    try:
        return _get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except Exception:
        # Wrong/missing key, or corrupted value — surface as empty rather than
        # crashing settings load. Operator will see the field as "not set" and
        # can re-enter it via Settings.
        return ""


def is_encrypted(value: str) -> bool:
    return bool(value) and value.startswith(ENC_PREFIX)
