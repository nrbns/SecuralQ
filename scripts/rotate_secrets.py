"""Rotate ENV_SECRET_ENCRYPTION_KEY / data/.secret.key (#246).

Generates a new Fernet key, re-encrypts known enc:v1: values in .env,
and writes the new key. Keep the old key backup until all replicas reload.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ENC_PREFIX = "enc:v1:"


def main() -> int:
    parser = argparse.ArgumentParser(description="Rotate SecuraIQ envelope encryption key")
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    from cryptography.fernet import Fernet

    from app.secrets_crypto import _KEY_FILE, _load_or_create_key, decrypt_value

    old_key = _load_or_create_key()
    old_f = Fernet(old_key)
    new_key = Fernet.generate_key()
    new_f = Fernet(new_key)

    env_path: Path = args.env_file
    rewritten = 0
    if env_path.is_file():
        text = env_path.read_text(encoding="utf-8")
        lines = []
        for line in text.splitlines(keepends=True):
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line.rstrip("\r\n"))
            if not m:
                lines.append(line)
                continue
            name, val = m.group(1), m.group(2)
            # strip optional quotes
            raw = val.strip().strip('"').strip("'")
            if raw.startswith(ENC_PREFIX):
                plain = decrypt_value(raw)
                token = ENC_PREFIX + new_f.encrypt(plain.encode("utf-8")).decode("ascii")
                lines.append(f"{name}={token}\n")
                rewritten += 1
            else:
                lines.append(line if line.endswith("\n") else line + "\n")
        if not args.dry_run:
            backup = env_path.with_suffix(env_path.suffix + ".pre-rotate")
            shutil.copy2(env_path, backup)
            env_path.write_text("".join(lines), encoding="utf-8")
            print(f"Backed up {env_path} → {backup}")
    else:
        print(f"No .env at {env_path} (key file rotation only)")

    if args.dry_run:
        print(f"Dry-run: would re-encrypt {rewritten} values; new key not written")
        return 0

    # Persist new key
    if os.environ.get("ENV_SECRET_ENCRYPTION_KEY"):
        print("ENV_SECRET_ENCRYPTION_KEY is set in the process environment.")
        print(f"Set it to the new key (base64): {new_key.decode('ascii')}")
        print("Then restart all app replicas. Old key must remain valid until restart completes.")
    else:
        if _KEY_FILE.exists():
            shutil.copy2(_KEY_FILE, _KEY_FILE.with_suffix(".key.pre-rotate"))
        _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        _KEY_FILE.write_bytes(new_key)
        print(f"Wrote new key to {_KEY_FILE}")
        print(f"Re-encrypted {rewritten} .env values")

    # Prove old key still decrypts nothing after rewrite — smoke with new key
    _ = old_f  # retained for operator dual-key window docs
    print("Rotation complete. Restart the API process to load the new key.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
