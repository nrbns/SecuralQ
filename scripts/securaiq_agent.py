#!/usr/bin/env python3
"""SecuraIQ native agent — real telemetry check-in, stdlib only.

Install-free by design (matches the rest of SecuraIQ's "honest, no fake
data, no unnecessary external dependencies" tooling philosophy): runs on
Python 3.8+ with zero third-party packages required. If `psutil` happens to
be installed it is used opportunistically for a fuller process list, but
its absence never causes a fake/empty result to be reported as real data —
missing sections are simply omitted, never invented.

Usage:
    python3 securaiq_agent.py --server https://securaiq.example.com --token <agent_id>.<agent_key>

The token is the one shown ONCE at enrollment time (Settings -> Agents ->
Enroll new agent, or POST /api/agents/enroll). It cannot be recovered from
the server afterwards — if lost, revoke and re-enroll.

Runs a check-in loop on --interval seconds (default 60). Each check-in is a
real, freshly-collected snapshot — not cached/replayed data.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

AGENT_VERSION = "1.1.4"
DEFAULT_INTERVAL_SEC = 60
SENTINEL_VERSION = "1.0.0"
DEFAULT_SENTINEL_INTERVAL_SEC = 10

# Config filenames looked up next to the agent binary/script (never baked secrets).
_CONFIG_FILENAMES = ("agent.env", "securaiq-agent.env", ".env")


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _agent_home() -> str:
    """Directory that holds the runnable agent + optional agent.env.

    When packaged (PyInstaller), this is the folder containing the .exe /
    binary — not the temporary extract dir — so operators can drop a config
    file next to the download and double-click to run.
    """
    if _is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _load_env_file(path: str) -> None:
    """Load KEY=VALUE lines into os.environ if the key is not already set."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except OSError:
        pass


def _autoload_config() -> str | None:
    """Load the first agent.env found next to the binary or in CWD. Returns path used."""
    candidates = [
        os.path.join(_agent_home(), name) for name in _CONFIG_FILENAMES
    ] + [os.path.join(os.getcwd(), name) for name in _CONFIG_FILENAMES]
    seen: set[str] = set()
    for path in candidates:
        ap = os.path.abspath(path)
        if ap in seen:
            continue
        seen.add(ap)
        if os.path.isfile(ap):
            _load_env_file(ap)
            return ap
    return None


# ---------------------------------------------------------------------------
# Offline telemetry buffer (embedded copy of app/agent_offline_buffer.py).
# Stdlib-only — packaged/frozen agents cannot import app.*.
# Schema: next_seq, last_acked_seq, events[{sequence,event_type,payload,enqueued_at}]
# ---------------------------------------------------------------------------

_OFFLINE_MAX_EVENTS = 5000
_OFFLINE_MAX_BYTES = 8 * 1024 * 1024
_SNAPSHOT_BUFFER_SOFT_BYTES = 100_000


def _default_offline_buffer_path(agent_id: str = "") -> Path:
    base = os.environ.get("SECURAIQ_AGENT_DATA_DIR") or os.environ.get("SECURAIQ_DATA_DIR")
    if base:
        root = Path(base)
    else:
        root = Path.home() / ".securaiq" / "agent"
    root.mkdir(parents=True, exist_ok=True)
    suffix = f"_{agent_id[:12]}" if agent_id else ""
    return root / f"offline_telemetry{suffix}.json"


class OfflineTelemetryBuffer:
    """Per-agent sequenced event queue with JSON persistence (agent-embedded)."""

    def __init__(
        self,
        agent_id: str,
        *,
        path: Path | str | None = None,
        max_events: int = _OFFLINE_MAX_EVENTS,
        max_bytes: int = _OFFLINE_MAX_BYTES,
    ) -> None:
        self.agent_id = str(agent_id or "unknown")
        self.path = Path(path) if path else _default_offline_buffer_path(self.agent_id)
        self.max_events = max(1, int(max_events))
        self.max_bytes = max(64 * 1024, int(max_bytes))
        self._lock = threading.RLock()
        self._next_seq = 1
        self._last_acked = 0
        self._events: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(raw, dict):
            return
        self._next_seq = max(1, int(raw.get("next_seq") or 1))
        self._last_acked = max(0, int(raw.get("last_acked_seq") or 0))
        events = raw.get("events") or []
        if isinstance(events, list):
            self._events = [e for e in events if isinstance(e, dict) and "sequence" in e]
        self._trim_unlocked()

    def _persist_unlocked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "agent_id": self.agent_id,
            "next_seq": self._next_seq,
            "last_acked_seq": self._last_acked,
            "events": self._events,
            "updated_at": time.time(),
        }
        text = json.dumps(payload, separators=(",", ":"))
        while len(text.encode("utf-8")) > self.max_bytes and len(self._events) > 1:
            self._events.pop(0)
            payload["events"] = self._events
            text = json.dumps(payload, separators=(",", ":"))
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(self.path)

    def _trim_unlocked(self) -> None:
        if len(self._events) > self.max_events:
            overflow = len(self._events) - self.max_events
            del self._events[:overflow]

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._events)

    def enqueue(self, event_type: str, payload: dict[str, Any] | None = None) -> int:
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1
            self._events.append(
                {
                    "sequence": seq,
                    "event_type": str(event_type or "telemetry"),
                    "payload": payload or {},
                    "enqueued_at": time.time(),
                }
            )
            self._trim_unlocked()
            self._persist_unlocked()
            return seq

    def ack(self, sequences: list[int] | int) -> int:
        if isinstance(sequences, int):
            seqs = {int(sequences)}
        else:
            seqs = {int(s) for s in sequences}
        if not seqs:
            return 0
        with self._lock:
            before = len(self._events)
            self._events = [e for e in self._events if int(e.get("sequence") or 0) not in seqs]
            removed = before - len(self._events)
            high = max(seqs)
            if high > self._last_acked:
                self._last_acked = high
            self._persist_unlocked()
            return removed

    def ack_through(self, sequence: int) -> int:
        seq = int(sequence)
        with self._lock:
            before = len(self._events)
            self._events = [e for e in self._events if int(e.get("sequence") or 0) > seq]
            removed = before - len(self._events)
            if seq > self._last_acked:
                self._last_acked = seq
            self._persist_unlocked()
            return removed

    def build_checkin_extension(
        self,
        *,
        flush_limit: int = 100,
        request_missing: bool = True,
    ) -> dict[str, Any]:
        with self._lock:
            batch = [dict(e) for e in self._events[: max(1, flush_limit)]]
            out: dict[str, Any] = {
                "sequence": self._next_seq - 1 if self._next_seq > 1 else 0,
                "buffered_events": batch,
            }
            if request_missing and self._last_acked >= 0:
                out["request_missing_from"] = self._last_acked + 1
            return out

    def apply_server_ack(self, response: dict[str, Any] | None) -> int:
        if not isinstance(response, dict):
            return 0
        removed = 0
        acked = response.get("acked_sequences") or response.get("ack_sequences")
        if isinstance(acked, list) and acked:
            removed += self.ack(acked)
        through = response.get("last_acked_seq")
        if through is not None:
            removed += self.ack_through(int(through))
        return removed


def _compact_snapshot_for_buffer(snapshot: dict) -> dict:
    """Prefer full snapshot under ~100KB; otherwise a compact host stub.

    Always keep firewall/defender/ssh (+ packages when present) so offline
    catch-up can re-apply host control telemetry (RT-05).
    """
    try:
        raw = json.dumps(snapshot, separators=(",", ":")).encode("utf-8")
        if len(raw) <= _SNAPSHOT_BUFFER_SOFT_BYTES:
            return snapshot
    except Exception:
        pass
    compact = {
        "hostname": snapshot.get("hostname"),
        "os": snapshot.get("os"),
        "os_version": snapshot.get("os_version"),
        "ip": snapshot.get("ip"),
        "agent_version": snapshot.get("agent_version") or AGENT_VERSION,
        "timestamp": time.time(),
        "truncated": True,
    }
    for key in ("firewall_status", "defender_status", "ssh_config", "packages"):
        if key in snapshot and snapshot.get(key) is not None:
            compact[key] = snapshot[key]
    return compact


def _agent_id_from_token(token: str) -> str:
    return (token or "").split(".", 1)[0]


def _b64url_decode_agent(text: str) -> bytes:
    t = (text or "").strip()
    pad = "=" * (-len(t) % 4)
    return base64.urlsafe_b64decode(t + pad)


def _canonical_command_bytes(cmd: dict, *, agent_id: str) -> bytes:
    body = {
        "command_id": str(cmd.get("id") or ""),
        "agent_id": agent_id,
        "kind": str(cmd.get("kind") or ""),
        "payload": cmd.get("payload") if isinstance(cmd.get("payload"), dict) else {},
        "nonce": str(cmd.get("nonce") or ""),
        "event_id": str(cmd.get("event_id") or ""),
    }
    if cmd.get("issued_at") is not None:
        try:
            body["issued_at"] = float(cmd.get("issued_at"))
        except (TypeError, ValueError):
            pass
    if cmd.get("expires_at") is not None:
        try:
            body["expires_at"] = float(cmd.get("expires_at"))
        except (TypeError, ValueError):
            pass
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_command_hmac(cmd: dict, *, agent_id: str, signing_key: str) -> bool:
    key = hashlib.sha256(signing_key.encode("utf-8")).digest()
    msg = _canonical_command_bytes(cmd, agent_id=agent_id)
    expected = hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, str(cmd.get("signature") or "").strip())


def _verify_command_ed25519(cmd: dict, *, agent_id: str, public_key: str) -> bool:
    """Verify Ed25519 seal when ``cryptography`` is installed. Raises ImportError if absent."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw = (public_key or "").strip()
    if not raw:
        return False
    if "BEGIN" in raw:
        key = serialization.load_pem_public_key(raw.encode("utf-8"))
    else:
        key = Ed25519PublicKey.from_public_bytes(_b64url_decode_agent(raw))
    msg = _canonical_command_bytes(cmd, agent_id=agent_id)
    try:
        key.verify(_b64url_decode_agent(str(cmd.get("signature_ed25519") or "")), msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _command_signatures_ok(cmd: dict, *, agent_id: str) -> bool:
    """Pre-execute seal checks.

    Lab-friendly by default. Mandatory verify when:
    - ``SECURAIQ_REQUIRE_COMMAND_VERIFY=1``, or
    - the server stamped ``require_verify: true`` (RT-17 /
      ``AGENT_REQUIRE_COMMAND_SIGNATURE`` on the control plane).
    """
    env_require = os.environ.get("SECURAIQ_REQUIRE_COMMAND_VERIFY", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    cmd_require = bool(cmd.get("require_verify"))
    require = env_require or cmd_require

    # Seal expiry is inside the signature when issued_at/expires_at are present.
    raw_exp = cmd.get("expires_at")
    if raw_exp is not None:
        try:
            if time.time() > float(raw_exp) + 30.0:
                print(
                    f"[securaiq-agent] command {cmd.get('id')} seal expired — refusing",
                    file=sys.stderr,
                )
                return False
        except (TypeError, ValueError):
            print(
                f"[securaiq-agent] command {cmd.get('id')} has invalid expires_at — refusing",
                file=sys.stderr,
            )
            return False

    sig_ed = str(cmd.get("signature_ed25519") or "").strip()
    # Prefer install-time pinned public key over TOFU embed when set.
    pub = str(
        os.environ.get("SECURAIQ_AGENT_ED25519_PUBLIC_KEY")
        or cmd.get("signing_public_key")
        or ""
    ).strip()
    signing_key = (os.environ.get("SECURAIQ_AGENT_SIGNING_KEY") or "").strip()
    hmac_sig = str(cmd.get("signature") or "").strip()

    if require and not hmac_sig and not sig_ed:
        print(
            f"[securaiq-agent] command {cmd.get('id')} missing signature — refusing "
            f"(require_verify={'cmd' if cmd_require else 'env'})",
            file=sys.stderr,
        )
        return False

    if sig_ed:
        if not pub:
            msg = "[securaiq-agent] command has signature_ed25519 but no signing_public_key / SECURAIQ_AGENT_ED25519_PUBLIC_KEY"
            if require:
                print(msg + " — refusing", file=sys.stderr)
                return False
            print(msg + " — skipping Ed25519 verify (lab)", file=sys.stderr)
        else:
            try:
                if not _verify_command_ed25519(cmd, agent_id=agent_id, public_key=pub):
                    print(
                        f"[securaiq-agent] Ed25519 signature verify failed for command {cmd.get('id')}",
                        file=sys.stderr,
                    )
                    return False
            except ImportError:
                msg = (
                    "[securaiq-agent] signature_ed25519 present but cryptography not installed"
                )
                if require:
                    print(msg + " — refusing to execute", file=sys.stderr)
                    return False
                print(msg + " — skipping verify (lab)", file=sys.stderr)

    if hmac_sig:
        if not signing_key:
            msg = (
                f"[securaiq-agent] command {cmd.get('id')} has HMAC signature but "
                "SECURAIQ_AGENT_SIGNING_KEY is unset"
            )
            if require:
                print(msg + " — refusing", file=sys.stderr)
                return False
            print(msg + " — skipping HMAC verify (lab)", file=sys.stderr)
        elif not _verify_command_hmac(cmd, agent_id=agent_id, signing_key=signing_key):
            print(
                f"[securaiq-agent] HMAC signature verify failed for command {cmd.get('id')}",
                file=sys.stderr,
            )
            return False
    elif signing_key and not sig_ed and require:
        print(
            f"[securaiq-agent] SECURAIQ_AGENT_SIGNING_KEY set but command {cmd.get('id')} has no signature — refusing",
            file=sys.stderr,
        )
        return False

    return True


# ---------------------------------------------------------------------------
# SecuraIQ Sentinel — the agent's real-time threat/malware detection engine.
#
# Unlike a periodic check-in field, Sentinel runs on its own fast loop
# (default every 10s, independent of the 60s telemetry check-in) and pushes
# any NEW detection to the server immediately via POST /api/agents/threat —
# that's what makes it "real time" rather than "eventually visible."
#
# It fuses four honest, install-free techniques rather than pretending to
# be a full antivirus engine:
#   1. Signature matching  — sha256 of files in watched dirs against a small
#      bundled seed list (KNOWN_BAD_HASHES). Ships with the EICAR test file
#      hash (the industry-standard, completely inert AV self-test string) so
#      the engine's signature path is provably real, not decorative. This
#      seed list is intentionally tiny — it is NOT a substitute for a live
#      threat-intel feed. Extend it with --hash-feed <file> (lines of
#      "sha256,label") for a real deployment.
#   2. Behavioral heuristics — suspicious process names, processes running
#      from temp/hidden paths, obfuscated/LOLBin command lines, suspicious
#      parent->child process spawns (e.g. an Office app spawning a shell).
#   3. Host indicators — ransomware-pattern file activity (mass renames to
#      known ransom extensions, ransom-note filenames appearing) and a
#      coarse "many concurrent outbound connections" network heuristic.
#   4. File-integrity monitoring — a real persisted baseline of every file
#      under the watched directories, diffed on each scan to catch adds,
#      modifications, and deletions (not a hardcoded empty stub).
#
# Every technique here is real and runs against real host data — but this is
# intentionally scoped and will never claim the coverage of a commercial EDR
# signature/ML engine. Detections are informational security signals, not a
# guarantee of "clean" when nothing is found.
# ---------------------------------------------------------------------------

# EICAR standard AV test string's well-known SHA-256 — a public, harmless,
# industry-standard test signature (not working malware).
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

KNOWN_BAD_HASHES: dict[str, str] = {
    EICAR_SHA256: "EICAR-Test-File (AV self-test signature, not real malware)",
}

SUSPICIOUS_PROCESS_NAMES = {
    "xmrig", "xmrig.exe", "xmr-stak", "minerd", "kinsing", "kdevtmpfsi", "kdevtmpfsi.exe",
    "mimikatz", "mimikatz.exe", "psexec.exe", "ncat", "ncat.exe", "nc.exe",
}

# Command-line fragments commonly used for obfuscated downloads / LOLBin
# living-off-the-land execution. Case-insensitive substring/regex match.
SUSPICIOUS_CMDLINE_PATTERNS = [
    re.compile(r"-enc(odedcommand)?\s+[a-z0-9+/=]{20,}", re.I),
    re.compile(r"frombase64string", re.I),
    re.compile(r"iex\s*\(", re.I),
    re.compile(r"invoke-expression", re.I),
    re.compile(r"certutil.{0,20}-urlcache", re.I),
    re.compile(r"bitsadmin.{0,20}/transfer", re.I),
    re.compile(r"mshta\s+https?://", re.I),
    re.compile(r"regsvr32.{0,20}/i:https?://", re.I),
    re.compile(r"(curl|wget)\s+https?://\S+\s*\|\s*(sh|bash)", re.I),
    re.compile(r"rundll32.{0,20}https?://", re.I),
]

SUSPICIOUS_PATH_FRAGMENTS = (
    "/tmp/", "/dev/shm/", "/var/tmp/", "/.hidden/",
    "\\temp\\", "\\appdata\\local\\temp\\", "\\programdata\\",
)

# A shell/script interpreter spawned directly by an office/reader app is a
# classic malicious-macro / phishing pattern.
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrobat.exe"}
SHELL_CHILDREN = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}

RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".cerber", ".locky", ".zzz", ".wcry", ".wncry", ".rekt", ".cryptolocker",
}
RANSOM_NOTE_NAMES = {
    "readme_to_decrypt.txt", "decrypt_instructions.txt", "how_to_decrypt.txt",
    "help_decrypt.html", "_readme.txt", "restore_files.txt",
}

_SENTINEL_STATE_LOCK = threading.Lock()


def _primary_ip() -> str:
    """Best-effort real outbound-interface IP (no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return ""
    finally:
        s.close()


def _listening_ports() -> list[int]:
    """Real listening TCP ports on this host — Linux via /proc/net/tcp*,
    everything else via a best-effort `netstat`/`ss` shellout. Returns an
    empty list (not a fake value) if neither source is available, and the
    check-in payload is honest about that rather than pretending success."""
    ports: set[int] = set()
    # Linux: parse /proc/net/tcp and tcp6 directly — no shellout needed,
    # works even in minimal containers.
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(proc_file, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local, state = parts[1], parts[3]
                if state != "0A":  # 0A = TCP_LISTEN
                    continue
                try:
                    port = int(local.split(":")[-1], 16)
                    if 0 < port < 65536:
                        ports.add(port)
                except ValueError:
                    continue
        except FileNotFoundError:
            continue
        except Exception:
            continue
    if ports:
        return sorted(ports)
    # Non-Linux (or /proc unavailable): try a real netstat/ss shellout.
    import re
    import subprocess

    for cmd in (["ss", "-tln"], ["netstat", "-an"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except Exception:
            continue
        if out.returncode != 0 and not out.stdout:
            continue
        for m in re.finditer(r"[:.](\d{2,5})\s", out.stdout):
            try:
                port = int(m.group(1))
                if 0 < port < 65536:
                    ports.add(port)
            except ValueError:
                continue
        if ports:
            break
    return sorted(ports)


def _processes(limit: int = 40) -> list[dict]:
    """Real process list. Uses psutil if present (optional dependency);
    otherwise a platform shellout (`ps` / Windows `tasklist`); returns []
    rather than fabricating entries if neither works."""
    try:
        import psutil  # type: ignore

        out = []
        for p in psutil.process_iter(["pid", "name", "username"]):
            try:
                out.append({"pid": p.info["pid"], "name": p.info["name"], "user": p.info.get("username") or ""})
            except Exception:
                continue
            if len(out) >= limit:
                break
        return out
    except ImportError:
        pass
    import subprocess

    try:
        if platform.system().lower().startswith("win"):
            out = subprocess.run(["tasklist"], capture_output=True, text=True, timeout=8)
            rows = []
            for line in (out.stdout or "").splitlines()[3:]:
                bits = line.split()
                if len(bits) >= 2 and bits[-1].isdigit() is False:
                    rows.append({"pid": None, "name": bits[0], "user": ""})
                if len(rows) >= limit:
                    break
            return rows
        out = subprocess.run(["ps", "-eo", "pid,user,comm"], capture_output=True, text=True, timeout=8)
        rows = []
        for line in (out.stdout or "").splitlines()[1:]:
            bits = line.split(None, 2)
            if len(bits) == 3:
                rows.append({"pid": int(bits[0]) if bits[0].isdigit() else None, "user": bits[1], "name": bits[2]})
            if len(rows) >= limit:
                break
        return rows
    except Exception:
        return []


def _packages(limit: int = 500) -> list[dict]:
    """Real installed-package list via the host's own package manager.
    Tries dpkg (Debian/Ubuntu), rpm (RHEL/Fedora), then gives up honestly —
    no invented package list for an unsupported OS."""
    import subprocess

    system = platform.system().lower()
    if system == "linux":
        try:
            out = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"], capture_output=True, text=True, timeout=15
            )
            if out.returncode == 0 and out.stdout:
                rows = []
                for line in out.stdout.splitlines():
                    bits = line.split("\t")
                    if len(bits) == 2:
                        rows.append({"name": bits[0], "version": bits[1]})
                    if len(rows) >= limit:
                        break
                return rows
        except Exception:
            pass
        try:
            out = subprocess.run(
                ["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"], capture_output=True, text=True, timeout=15
            )
            if out.returncode == 0 and out.stdout:
                rows = []
                for line in out.stdout.splitlines():
                    bits = line.split("\t")
                    if len(bits) == 2:
                        rows.append({"name": bits[0], "version": bits[1]})
                    if len(rows) >= limit:
                        break
                return rows
        except Exception:
            pass
    elif system == "windows":
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
                 "Select-Object DisplayName,DisplayVersion | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=20,
            )
            if out.returncode == 0 and out.stdout.strip():
                data = json.loads(out.stdout)
                items = data if isinstance(data, list) else [data]
                rows = []
                for it in items:
                    name = (it or {}).get("DisplayName")
                    if not name:
                        continue
                    rows.append({"name": name, "version": (it or {}).get("DisplayVersion") or ""})
                    if len(rows) >= limit:
                        break
                return rows
        except Exception:
            pass
    return []


# ---------------------------------------------------------------------------
# Deep telemetry collectors — services, local users, firewall, disk
# encryption, endpoint AV (Defender), startup apps, SSH hardening.
#
# Every collector here returns {"collected": bool, "reason": str, ...}. When
# a signal genuinely can't be gathered (wrong OS, tool missing, needs
# elevated privileges, command failed) that is reported honestly via
# collected=False + a real reason string -- never a fabricated/empty-looking
# "clean" result standing in for "we don't actually know."
# ---------------------------------------------------------------------------


def _run(cmd: list[str], *, timeout: float = 10.0):
    """Shared subprocess helper for the collectors below. Returns
    (ok, stdout) -- ok is False on a missing binary, non-zero exit, or
    timeout; stdout is "" in that case, never fabricated."""
    import subprocess

    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return False, ""
    except Exception:
        return False, ""
    return out.returncode == 0, (out.stdout or "")


def _services() -> dict:
    """Real running-service list. Linux: systemd. macOS: launchctl. Windows:
    the Service Control Manager via PowerShell."""
    system = platform.system().lower()
    if system == "linux":
        ok, out = _run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"], timeout=15)
        if not ok:
            return {"collected": False, "reason": "systemctl unavailable or failed (non-systemd host?)", "items": []}
        items = []
        for line in out.splitlines():
            bits = line.split()
            if bits:
                items.append({"name": bits[0], "status": "running"})
        return {"collected": True, "reason": "", "items": items}
    if system == "darwin":
        ok, out = _run(["launchctl", "list"], timeout=15)
        if not ok:
            return {"collected": False, "reason": "launchctl unavailable or failed", "items": []}
        items = []
        for line in out.splitlines()[1:]:
            bits = line.split("\t")
            if len(bits) == 3:
                items.append({"name": bits[2], "pid": bits[0]})
        return {"collected": True, "reason": "", "items": items}
    if system == "windows":
        ok, out = _run(
            ["powershell", "-NoProfile", "-Command", "Get-Service | Where-Object Status -eq 'Running' | Select-Object Name,Status | ConvertTo-Json -Compress"],
            timeout=20,
        )
        if not ok or not out.strip():
            return {"collected": False, "reason": "Get-Service unavailable or failed", "items": []}
        try:
            data = json.loads(out)
            rows = data if isinstance(data, list) else [data]
            items = [{"name": r.get("Name"), "status": "running"} for r in rows if r.get("Name")]
            return {"collected": True, "reason": "", "items": items}
        except Exception:
            return {"collected": False, "reason": "Could not parse Get-Service output", "items": []}
    return {"collected": False, "reason": f"Unsupported OS '{system}'", "items": []}


def _local_users() -> dict:
    """Real local account list -- never includes passwords/hashes, only
    usernames + whether the account is disabled, for a human-account-review
    signal (e.g. spotting an unexpected local admin)."""
    system = platform.system().lower()
    if system in ("linux", "darwin"):
        try:
            with open("/etc/passwd", "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except Exception as exc:
            return {"collected": False, "reason": f"Could not read /etc/passwd: {exc}", "items": []}
        min_uid = 500 if system == "darwin" else 1000
        items = []
        for line in lines:
            bits = line.strip().split(":")
            if len(bits) < 7:
                continue
            name, _, uid_s, _, _, _, shell = bits[:7]
            try:
                uid = int(uid_s)
            except ValueError:
                continue
            if uid < min_uid and uid != 0:
                continue
            is_login_shell = shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "")
            items.append({"name": name, "uid": uid, "login_shell": is_login_shell})
        return {"collected": True, "reason": "", "items": items}
    if system == "windows":
        ok, out = _run(
            ["powershell", "-NoProfile", "-Command", "Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json -Compress"],
            timeout=15,
        )
        if not ok or not out.strip():
            return {"collected": False, "reason": "Get-LocalUser unavailable or failed (needs the LocalAccounts module)", "items": []}
        try:
            data = json.loads(out)
            rows = data if isinstance(data, list) else [data]
            items = [{"name": r.get("Name"), "enabled": bool(r.get("Enabled"))} for r in rows if r.get("Name")]
            return {"collected": True, "reason": "", "items": items}
        except Exception:
            return {"collected": False, "reason": "Could not parse Get-LocalUser output", "items": []}
    return {"collected": False, "reason": f"Unsupported OS '{system}'", "items": []}


def _firewall_status() -> dict:
    """Real host firewall enabled/disabled state -- tries the platform's own
    firewall control tool; never guesses "enabled" from its mere presence
    on disk."""
    system = platform.system().lower()
    if system == "linux":
        ok, out = _run(["ufw", "status"], timeout=8)
        if ok and out.strip():
            enabled = out.strip().lower().startswith("status: active")
            return {"collected": True, "reason": "", "backend": "ufw", "enabled": enabled}
        ok, out = _run(["firewall-cmd", "--state"], timeout=8)
        if ok:
            return {"collected": True, "reason": "", "backend": "firewalld", "enabled": out.strip().lower() == "running"}
        return {"collected": False, "reason": "No supported firewall tool found (tried ufw, firewalld)", "enabled": None}
    if system == "darwin":
        ok, out = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], timeout=8)
        if not ok:
            return {"collected": False, "reason": "socketfilterfw unavailable or failed", "enabled": None}
        return {"collected": True, "reason": "", "backend": "pf/ALF", "enabled": "enabled" in out.lower()}
    if system == "windows":
        ok, out = _run(
            ["powershell", "-NoProfile", "-Command", "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"],
            timeout=15,
        )
        if not ok or not out.strip():
            return {"collected": False, "reason": "Get-NetFirewallProfile unavailable or failed", "enabled": None}
        try:
            data = json.loads(out)
            rows = data if isinstance(data, list) else [data]
            profiles = {r.get("Name"): bool(r.get("Enabled")) for r in rows if r.get("Name")}
            return {"collected": True, "reason": "", "backend": "Windows Firewall", "enabled": any(profiles.values()) if profiles else None, "profiles": profiles}
        except Exception:
            return {"collected": False, "reason": "Could not parse Get-NetFirewallProfile output", "enabled": None}
    return {"collected": False, "reason": f"Unsupported OS '{system}'", "enabled": None}


def _disk_encryption_status() -> dict:
    """Real full-disk-encryption state -- LUKS on Linux, FileVault on macOS,
    BitLocker on Windows. Reports "not enabled" only when the platform tool
    actually says so, not merely because the check itself failed."""
    system = platform.system().lower()
    if system == "linux":
        ok, out = _run(["lsblk", "-o", "NAME,FSTYPE", "-n"], timeout=8)
        if not ok:
            return {"collected": False, "reason": "lsblk unavailable or failed", "encrypted": None}
        encrypted = "crypto_luks" in out.lower()
        return {"collected": True, "reason": "", "backend": "LUKS", "encrypted": encrypted}
    if system == "darwin":
        ok, out = _run(["fdesetup", "status"], timeout=8)
        if not ok:
            return {"collected": False, "reason": "fdesetup unavailable or failed", "encrypted": None}
        return {"collected": True, "reason": "", "backend": "FileVault", "encrypted": "filevault is on" in out.lower()}
    if system == "windows":
        ok, out = _run(
            ["powershell", "-NoProfile", "-Command", "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus | ConvertTo-Json -Compress"],
            timeout=15,
        )
        if not ok or not out.strip():
            return {"collected": False, "reason": "Get-BitLockerVolume unavailable or failed (BitLocker module not present, or needs elevation)", "encrypted": None}
        try:
            data = json.loads(out)
            rows = data if isinstance(data, list) else [data]
            volumes = {r.get("MountPoint"): r.get("VolumeStatus") for r in rows if r.get("MountPoint")}
            any_on = any(str(v).lower() == "fullyencrypted" for v in volumes.values())
            return {"collected": True, "reason": "", "backend": "BitLocker", "encrypted": any_on, "volumes": volumes}
        except Exception:
            return {"collected": False, "reason": "Could not parse Get-BitLockerVolume output", "encrypted": None}
    return {"collected": False, "reason": f"Unsupported OS '{system}'", "encrypted": None}


def _defender_status() -> dict:
    """Windows Defender real-time protection state -- Windows only. Linux
    and macOS honestly report "not applicable" rather than an unavailable
    error, since Defender simply isn't part of those platforms."""
    system = platform.system().lower()
    if system != "windows":
        return {"collected": False, "reason": f"Not applicable on {system}", "enabled": None}
    ok, out = _run(
        ["powershell", "-NoProfile", "-Command", "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress"],
        timeout=15,
    )
    if not ok or not out.strip():
        return {"collected": False, "reason": "Get-MpComputerStatus unavailable or failed (Defender module not present, or a 3rd-party AV has taken over)", "enabled": None}
    try:
        data = json.loads(out)
        return {
            "collected": True,
            "reason": "",
            "antivirus_enabled": bool(data.get("AntivirusEnabled")),
            "realtime_protection_enabled": bool(data.get("RealTimeProtectionEnabled")),
            "signature_age_days": data.get("AntivirusSignatureAge"),
        }
    except Exception:
        return {"collected": False, "reason": "Could not parse Get-MpComputerStatus output", "enabled": None}


def _startup_apps() -> dict:
    """Real boot/login-time autostart entries -- systemd-enabled services on
    Linux, LaunchAgents/LaunchDaemons on macOS, Win32_StartupCommand on
    Windows. A common persistence-mechanism signal."""
    system = platform.system().lower()
    if system == "linux":
        ok, out = _run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"], timeout=15)
        if not ok:
            return {"collected": False, "reason": "systemctl unavailable or failed", "items": []}
        items = [{"name": line.split()[0]} for line in out.splitlines() if line.split()]
        return {"collected": True, "reason": "", "items": items}
    if system == "darwin":
        dirs = ["/Library/LaunchAgents", "/Library/LaunchDaemons", os.path.expanduser("~/Library/LaunchAgents")]
        items = []
        found_any_dir = False
        for d in dirs:
            if not os.path.isdir(d):
                continue
            found_any_dir = True
            try:
                for name in os.listdir(d):
                    if name.endswith(".plist"):
                        items.append({"name": name, "location": d})
            except Exception:
                continue
        if not found_any_dir:
            return {"collected": False, "reason": "No LaunchAgents/LaunchDaemons directories found", "items": []}
        return {"collected": True, "reason": "", "items": items}
    if system == "windows":
        ok, out = _run(
            ["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location | ConvertTo-Json -Compress"],
            timeout=20,
        )
        if not ok or not out.strip():
            return {"collected": False, "reason": "Get-CimInstance Win32_StartupCommand unavailable or failed", "items": []}
        try:
            data = json.loads(out)
            rows = data if isinstance(data, list) else [data]
            items = [{"name": r.get("Name"), "command": r.get("Command"), "location": r.get("Location")} for r in rows if r.get("Name")]
            return {"collected": True, "reason": "", "items": items}
        except Exception:
            return {"collected": False, "reason": "Could not parse Win32_StartupCommand output", "items": []}
    return {"collected": False, "reason": f"Unsupported OS '{system}'", "items": []}


def _hardware() -> dict:
    """Coarse host hardware inventory — stdlib first; never invent specs.

    Fields are best-effort and capped. Missing elevation / modules yield
    collected=False with a real reason rather than zeros that look like data.
    """
    system = platform.system().lower()
    out: dict = {
        "collected": True,
        "reason": "",
        "arch": (platform.machine() or "")[:64],
        "processor": (platform.processor() or "")[:120],
        "cpu_count": os.cpu_count(),
        "memory_mb": None,
        "disk_root_gb": None,
        "manufacturer": "",
        "model": "",
    }
    try:
        import shutil

        usage = shutil.disk_usage(os.path.abspath(os.sep))
        out["disk_root_gb"] = round(usage.total / (1024**3), 1)
    except Exception:
        pass

    if system == "linux":
        try:
            with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        out["memory_mb"] = kb // 1024
                        break
        except Exception as exc:
            if out["disk_root_gb"] is None and not out["arch"]:
                return {
                    "collected": False,
                    "reason": f"Could not read hardware signals: {exc}",
                    "arch": "",
                    "processor": "",
                    "cpu_count": None,
                    "memory_mb": None,
                    "disk_root_gb": None,
                }
        # Optional DMI product strings (may be empty in VMs / containers).
        for key, path in (
            ("manufacturer", "/sys/class/dmi/id/sys_vendor"),
            ("model", "/sys/class/dmi/id/product_name"),
        ):
            try:
                if os.path.isfile(path):
                    out[key] = open(path, "r", encoding="utf-8", errors="replace").read().strip()[:80]
            except Exception:
                pass
        return out

    if system == "windows":
        ok, raw = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance Win32_ComputerSystem | "
                    "Select-Object Manufacturer,Model,TotalPhysicalMemory,NumberOfLogicalProcessors | "
                    "ConvertTo-Json -Compress"
                ),
            ],
            timeout=15,
        )
        if ok and raw.strip():
            try:
                data = json.loads(raw)
                out["manufacturer"] = str(data.get("Manufacturer") or "")[:80]
                out["model"] = str(data.get("Model") or "")[:80]
                mem = data.get("TotalPhysicalMemory")
                if mem is not None:
                    out["memory_mb"] = int(int(mem) // (1024 * 1024))
                cpus = data.get("NumberOfLogicalProcessors")
                if cpus is not None:
                    out["cpu_count"] = int(cpus)
            except Exception:
                out["reason"] = "Parsed partial hardware; CIM JSON incomplete"
        else:
            # Stdlib fields alone still count as collected when arch/cpu known.
            if not out["arch"] and not out["cpu_count"]:
                return {
                    "collected": False,
                    "reason": "Win32_ComputerSystem unavailable and no stdlib arch/cpu",
                    "arch": "",
                    "processor": "",
                    "cpu_count": None,
                    "memory_mb": None,
                    "disk_root_gb": out.get("disk_root_gb"),
                }
        return out

    if system == "darwin":
        # Honest minimal: stdlib + disk; no sysctl dependency required.
        return out

    return {
        "collected": False,
        "reason": f"Unsupported OS '{system}'",
        "arch": out["arch"],
        "processor": out["processor"],
        "cpu_count": out["cpu_count"],
        "memory_mb": None,
        "disk_root_gb": out.get("disk_root_gb"),
    }


def _local_groups() -> dict:
    """Local groups + member names (no password material). Caps list size."""
    system = platform.system().lower()
    if system in ("linux", "darwin"):
        try:
            with open("/etc/group", "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except Exception as exc:
            return {"collected": False, "reason": f"Could not read /etc/group: {exc}", "items": []}
        items = []
        for line in lines:
            bits = line.strip().split(":")
            if len(bits) < 4:
                continue
            name, _pw, gid_s, members_s = bits[0], bits[1], bits[2], bits[3]
            try:
                gid = int(gid_s)
            except ValueError:
                continue
            members = [m for m in members_s.split(",") if m][:20]
            items.append({"name": name, "gid": gid, "members": members})
            if len(items) >= 80:
                break
        return {"collected": True, "reason": "", "items": items}

    if system == "windows":
        ok, out = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-LocalGroup | Select-Object -First 40 Name,SID | "
                    "ForEach-Object { "
                    "$m = @(); try { $m = @(Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue | "
                    "Select-Object -First 15 -ExpandProperty Name) } catch {}; "
                    "[pscustomobject]@{ name = $_.Name; members = $m } "
                    "} | ConvertTo-Json -Compress"
                ),
            ],
            timeout=25,
        )
        if not ok or not out.strip():
            return {
                "collected": False,
                "reason": "Get-LocalGroup unavailable or failed (needs LocalAccounts module / elevation)",
                "items": [],
            }
        try:
            data = json.loads(out)
            rows = data if isinstance(data, list) else [data]
            items = []
            for r in rows:
                name = r.get("name") or r.get("Name")
                if not name:
                    continue
                members = r.get("members") or r.get("Members") or []
                if not isinstance(members, list):
                    members = [members] if members else []
                items.append(
                    {
                        "name": str(name)[:80],
                        "members": [str(m)[:80] for m in members if m][:15],
                    }
                )
            return {"collected": True, "reason": "", "items": items}
        except Exception:
            return {"collected": False, "reason": "Could not parse Get-LocalGroup output", "items": []}

    return {"collected": False, "reason": f"Unsupported OS '{system}'", "items": []}


def _network() -> dict:
    """Network interfaces — name, IPv4 addresses, MAC when available."""
    system = platform.system().lower()
    if system == "linux":
        base = "/sys/class/net"
        if not os.path.isdir(base):
            return {"collected": False, "reason": "/sys/class/net not available", "interfaces": []}
        # Prefer `ip -j` when present (one call); else walk sysfs + `ip -4 -o addr`.
        ok, raw = _run(["ip", "-j", "addr"], timeout=8)
        interfaces: list[dict] = []
        if ok and raw.strip():
            try:
                data = json.loads(raw)
                for row in data if isinstance(data, list) else []:
                    name = str(row.get("ifname") or "")[:40]
                    if not name:
                        continue
                    mac = str(row.get("address") or "")[:32]
                    ipv4 = []
                    for addr in row.get("addr_info") or []:
                        if addr.get("family") == "inet" and addr.get("local"):
                            ipv4.append(str(addr["local"])[:45])
                    interfaces.append(
                        {
                            "name": name,
                            "mac": mac if mac and mac != "00:00:00:00:00:00" else "",
                            "ipv4": ipv4[:8],
                        }
                    )
                    if len(interfaces) >= 32:
                        break
                return {
                    "collected": True,
                    "reason": "",
                    "interfaces": interfaces,
                    "primary_ip": _primary_ip(),
                }
            except Exception:
                pass
        try:
            names = sorted(os.listdir(base))[:32]
        except Exception as exc:
            return {"collected": False, "reason": f"Could not list interfaces: {exc}", "interfaces": []}
        for name in names:
            iface = {"name": name, "mac": "", "ipv4": []}
            try:
                mac_path = os.path.join(base, name, "address")
                if os.path.isfile(mac_path):
                    mac = open(mac_path, "r", encoding="utf-8", errors="replace").read().strip()
                    if mac and mac != "00:00:00:00:00:00":
                        iface["mac"] = mac[:32]
            except Exception:
                pass
            ok2, out2 = _run(["ip", "-4", "-o", "addr", "show", "dev", name], timeout=5)
            if ok2 and out2.strip():
                for line in out2.splitlines():
                    bits = line.split()
                    # format: idx name family addr/mask ...
                    if len(bits) >= 4 and bits[2] == "inet":
                        iface["ipv4"].append(bits[3].split("/")[0][:45])
            interfaces.append(iface)
        return {
            "collected": True,
            "reason": "",
            "interfaces": interfaces,
            "primary_ip": _primary_ip(),
        }

    if system == "windows":
        ok, raw = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                    "Where-Object { $_.IPAddress -and $_.InterfaceAlias } | "
                    "Select-Object -First 40 InterfaceAlias,IPAddress | ConvertTo-Json -Compress"
                ),
            ],
            timeout=20,
        )
        if not ok or not raw.strip():
            return {
                "collected": False,
                "reason": "Get-NetIPAddress unavailable or failed",
                "interfaces": [],
                "primary_ip": _primary_ip(),
            }
        try:
            data = json.loads(raw)
            rows = data if isinstance(data, list) else [data]
            by_name: dict[str, dict] = {}
            for r in rows:
                name = str(r.get("InterfaceAlias") or "")[:40]
                ip = str(r.get("IPAddress") or "")[:45]
                if not name or not ip:
                    continue
                slot = by_name.setdefault(name, {"name": name, "mac": "", "ipv4": []})
                if ip not in slot["ipv4"] and len(slot["ipv4"]) < 8:
                    slot["ipv4"].append(ip)
            # Best-effort MACs
            ok_m, raw_m = _run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "Get-NetAdapter -ErrorAction SilentlyContinue | "
                        "Select-Object -First 40 Name,MacAddress | ConvertTo-Json -Compress"
                    ),
                ],
                timeout=15,
            )
            if ok_m and raw_m.strip():
                try:
                    macs = json.loads(raw_m)
                    mac_rows = macs if isinstance(macs, list) else [macs]
                    for mr in mac_rows:
                        n = str(mr.get("Name") or "")[:40]
                        mac = str(mr.get("MacAddress") or "").replace("-", ":")[:32]
                        if n in by_name and mac:
                            by_name[n]["mac"] = mac
                except Exception:
                    pass
            return {
                "collected": True,
                "reason": "",
                "interfaces": list(by_name.values())[:32],
                "primary_ip": _primary_ip(),
            }
        except Exception:
            return {
                "collected": False,
                "reason": "Could not parse Get-NetIPAddress output",
                "interfaces": [],
                "primary_ip": _primary_ip(),
            }

    if system == "darwin":
        ok, raw = _run(["ifconfig", "-a"], timeout=10)
        if not ok or not raw.strip():
            return {
                "collected": False,
                "reason": "ifconfig unavailable or failed",
                "interfaces": [],
                "primary_ip": _primary_ip(),
            }
        interfaces = []
        current: dict | None = None
        for line in raw.splitlines():
            if line and not line.startswith("\t") and not line.startswith(" "):
                name = line.split(":", 1)[0].strip()[:40]
                if current:
                    interfaces.append(current)
                current = {"name": name, "mac": "", "ipv4": []}
                if len(interfaces) >= 32:
                    break
            elif current is not None:
                s = line.strip()
                if s.startswith("ether "):
                    current["mac"] = s.split()[1][:32]
                elif s.startswith("inet "):
                    parts = s.split()
                    if len(parts) >= 2 and len(current["ipv4"]) < 8:
                        current["ipv4"].append(parts[1][:45])
        if current and len(interfaces) < 32:
            interfaces.append(current)
        return {
            "collected": True,
            "reason": "",
            "interfaces": interfaces,
            "primary_ip": _primary_ip(),
        }

    return {
        "collected": False,
        "reason": f"Unsupported OS '{system}'",
        "interfaces": [],
        "primary_ip": _primary_ip(),
    }


def _ssh_config() -> dict:
    """Real sshd_config hardening signals -- PermitRootLogin,
    PasswordAuthentication, PubkeyAuthentication, Port. Reads the config
    file directly (no daemon reload/exec involved). Honestly reports "not
    applicable" when no SSH server config exists on this host at all,
    distinct from "collected but empty"."""
    system = platform.system().lower()
    candidates = (
        ["/etc/ssh/sshd_config"]
        if system in ("linux", "darwin")
        else [r"C:\ProgramData\ssh\sshd_config"]
        if system == "windows"
        else []
    )
    path = next((p for p in candidates if os.path.isfile(p)), "")
    if not path:
        return {"collected": False, "reason": "No sshd_config found -- SSH server likely not installed on this host", "settings": {}}
    wanted = {"permitrootlogin", "passwordauthentication", "pubkeyauthentication", "port"}
    settings: dict = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                bits = line.split(None, 1)
                if len(bits) == 2 and bits[0].lower() in wanted:
                    settings[bits[0]] = bits[1]
    except Exception as exc:
        return {"collected": False, "reason": f"Could not read {path}: {exc}", "settings": {}}
    return {"collected": True, "reason": "", "path": path, "settings": settings}


def _sha256_file(path: str, max_bytes: int = 25_000_000) -> str:
    """Real sha256 of a file, skipping anything past max_bytes (avoids the
    watcher stalling on huge files) — returns "" rather than a fabricated
    value if hashing isn't possible."""
    try:
        if os.path.getsize(path) > max_bytes:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _default_watch_dirs() -> list[str]:
    home = os.path.expanduser("~")
    candidates = [
        home,
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", ""),
    ]
    seen: set[str] = set()
    out = []
    for d in candidates:
        if d and os.path.isdir(d) and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _iter_watch_files(watch_dirs: list[str], *, max_depth: int = 2, max_files: int = 4000):
    """Shallow walk of watch directories — bounded depth/count so the
    watcher stays cheap enough to run every few seconds."""
    for base in watch_dirs:
        base_depth = base.rstrip(os.sep).count(os.sep)
        count = 0
        for root, dirs, files in os.walk(base):
            depth = root.rstrip(os.sep).count(os.sep) - base_depth
            if depth >= max_depth:
                dirs[:] = []
            for name in files:
                if count >= max_files:
                    return
                path = os.path.join(root, name)
                try:
                    st = os.stat(path)
                except Exception:
                    continue
                count += 1
                yield path, name, st


def _process_snapshot_detailed(limit: int = 400) -> list[dict]:
    """Process list WITH cmdline + parent name — the extra fields Sentinel's
    behavioral checks need that the plain telemetry _processes() list
    doesn't carry. Linux: /proc directly. Windows: PowerShell CIM query.
    Falls back to an empty list (never fabricated) if unavailable."""
    system = platform.system().lower()
    out: list[dict] = []
    if system == "linux":
        try:
            pid_name: dict[str, str] = {}
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                base = f"/proc/{pid}"
                try:
                    with open(f"{base}/comm", "r", encoding="utf-8", errors="ignore") as fh:
                        name = fh.read().strip()
                    pid_name[pid] = name
                except Exception:
                    name = ""
                cmdline = ""
                try:
                    with open(f"{base}/cmdline", "rb") as fh:
                        cmdline = fh.read().replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
                except Exception:
                    pass
                exe_path = ""
                try:
                    exe_path = os.readlink(f"{base}/exe")
                except Exception:
                    pass
                ppid = ""
                try:
                    with open(f"{base}/stat", "r", encoding="utf-8", errors="ignore") as fh:
                        stat_line = fh.read()
                    after_paren = stat_line.rsplit(")", 1)[-1].split()
                    if after_paren:
                        ppid = after_paren[1] if len(after_paren) > 1 else ""
                except Exception:
                    pass
                out.append({
                    "pid": pid, "name": name, "cmdline": cmdline, "exe": exe_path, "ppid": ppid,
                })
                if len(out) >= limit:
                    break
            for row in out:
                row["ppid_name"] = pid_name.get(row.get("ppid") or "", "")
        except Exception:
            return []
        return out
    if system == "windows":
        import subprocess

        try:
            ps = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=20,
            )
            if ps.returncode == 0 and ps.stdout.strip():
                data = json.loads(ps.stdout)
                items = data if isinstance(data, list) else [data]
                pid_name = {str(it.get("ProcessId")): (it.get("Name") or "") for it in items}
                for it in items[:limit]:
                    ppid = str(it.get("ParentProcessId") or "")
                    out.append({
                        "pid": str(it.get("ProcessId") or ""),
                        "name": it.get("Name") or "",
                        "cmdline": it.get("CommandLine") or "",
                        "exe": it.get("ExecutablePath") or "",
                        "ppid": ppid,
                        "ppid_name": pid_name.get(ppid, ""),
                    })
        except Exception:
            return []
        return out
    return out


def _scan_signature(watch_dirs: list[str], known_hashes: dict[str, str]) -> list[dict]:
    detections = []
    for path, name, st in _iter_watch_files(watch_dirs):
        if st.st_size <= 0 or st.st_size > 5_000_000:
            # Signature scanning stays cheap: skip empty/large files here —
            # ransomware/path-based checks below still see every file.
            continue
        digest = _sha256_file(path)
        if digest and digest in known_hashes:
            detections.append({
                "severity": "critical", "category": "signature",
                "title": f"Known-malicious file signature matched: {known_hashes[digest]}",
                "detail": f"File: {path}", "target": path, "hash": digest,
            })
    return detections


def _scan_behavioral(procs: list[dict]) -> list[dict]:
    detections = []
    for p in procs:
        name = (p.get("name") or "").lower()
        cmdline = p.get("cmdline") or ""
        exe = (p.get("exe") or "").lower()
        ppid_name = (p.get("ppid_name") or "").lower()
        pid = p.get("pid") or "?"

        if name in SUSPICIOUS_PROCESS_NAMES or name.rstrip(".exe") in SUSPICIOUS_PROCESS_NAMES:
            detections.append({
                "severity": "high", "category": "behavioral",
                "title": f"Known-suspicious process name running: {name}",
                "detail": f"pid={pid} exe={exe or 'n/a'}", "target": f"pid:{pid}:{name}",
            })

        for pat in SUSPICIOUS_CMDLINE_PATTERNS:
            if cmdline and pat.search(cmdline):
                detections.append({
                    "severity": "high", "category": "behavioral",
                    "title": "Obfuscated / living-off-the-land command line detected",
                    "detail": f"pid={pid} name={name} cmdline={cmdline[:300]}",
                    "target": f"pid:{pid}:{name}",
                })
                break

        if exe and any(frag in exe for frag in SUSPICIOUS_PATH_FRAGMENTS):
            detections.append({
                "severity": "medium", "category": "behavioral",
                "title": f"Process executing from a temp/hidden path: {name}",
                "detail": f"pid={pid} exe={exe}", "target": f"pid:{pid}:{name}",
            })

        if ppid_name in OFFICE_PARENTS and name in SHELL_CHILDREN:
            detections.append({
                "severity": "critical", "category": "behavioral",
                "title": f"Office/reader app spawned a shell: {ppid_name} -> {name}",
                "detail": f"pid={pid} cmdline={cmdline[:300]}", "target": f"pid:{pid}:{name}",
            })
    return detections


def _scan_ransomware(watch_dirs: list[str], *, recent_sec: int = 900) -> list[dict]:
    now_ts = time.time()
    ransom_ext_hits = 0
    note_hits: list[str] = []
    for path, name, st in _iter_watch_files(watch_dirs):
        lname = name.lower()
        if (now_ts - st.st_mtime) > recent_sec:
            continue
        if any(lname.endswith(ext) for ext in RANSOM_EXTENSIONS):
            ransom_ext_hits += 1
        if lname in RANSOM_NOTE_NAMES:
            note_hits.append(path)
    detections = []
    if note_hits:
        detections.append({
            "severity": "critical", "category": "ransomware",
            "title": "Ransom-note filename appeared in a watched directory",
            "detail": f"{len(note_hits)} note(s), e.g. {note_hits[0]}", "target": note_hits[0],
        })
    if ransom_ext_hits >= 5:
        detections.append({
            "severity": "critical", "category": "ransomware",
            "title": f"Mass file rename to known ransomware extensions ({ransom_ext_hits} files)",
            "detail": f"{ransom_ext_hits} recently-modified files carry a known ransomware extension",
            "target": "watch_dirs",
        })
    return detections


def _scan_network(threshold: int = 25) -> list[dict]:
    """Coarse, honest heuristic only: counts distinct ESTABLISHED remote
    IPs. This is NOT beacon/C2 detection — it's a cheap signal that many
    concurrent outbound connections may warrant a look, clearly labeled as
    such so it isn't mistaken for real network threat intel."""
    remotes: set[str] = set()
    try:
        for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(proc_file, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()[1:]
            except FileNotFoundError:
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                remote, state = parts[2], parts[3]
                if state != "01":  # ESTABLISHED
                    continue
                ip_hex = remote.split(":")[0]
                remotes.add(ip_hex)
    except Exception:
        return []
    if len(remotes) >= threshold:
        return [{
            "severity": "low", "category": "network",
            "title": f"High number of concurrent outbound connections ({len(remotes)} distinct remote hosts)",
            "detail": "Coarse heuristic only — review for beaconing/exfil, not a confirmed threat.",
            "target": "network",
        }]
    return []


# ---------------------------------------------------------------------------
# File-integrity monitoring (FIM) — real baseline + diff, not a stub.
#
# First scan on a fresh agent establishes a baseline silently (like Wazuh's
# FIM: an initial inventory pass isn't itself a flood of "new file" alerts).
# Every scan after that reports genuine added/modified/deleted events against
# that baseline. The baseline persists to disk next to the agent script so a
# process restart doesn't misreport the whole watched tree as "new".
# ---------------------------------------------------------------------------

_FIM_LOCK = threading.Lock()
_FIM_BASELINE: dict[str, dict] = {}
_FIM_BASELINE_LOADED = False
_FIM_LAST_SUMMARY: dict = {
    "tracked_files": 0, "baseline_established": False,
    "added": 0, "modified": 0, "deleted": 0, "last_scan_ts": None,
}
_FIM_LAST_EVENTS: list[dict] = []
_FIM_MAX_HASH_BYTES = 5_000_000


def _fim_state_path() -> str:
    try:
        base = _agent_home()
        if os.access(base, os.W_OK):
            return os.path.join(base, ".securaiq_fim_baseline.json")
    except Exception:
        pass
    import tempfile

    return os.path.join(tempfile.gettempdir(), "securaiq_fim_baseline.json")


def _fim_load_baseline() -> dict:
    global _FIM_BASELINE, _FIM_BASELINE_LOADED
    if _FIM_BASELINE_LOADED:
        return _FIM_BASELINE
    try:
        with open(_fim_state_path(), "r", encoding="utf-8") as fh:
            _FIM_BASELINE = json.load(fh)
    except Exception:
        _FIM_BASELINE = {}
    _FIM_BASELINE_LOADED = True
    return _FIM_BASELINE


def _fim_save_baseline() -> None:
    path = _fim_state_path()
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(_FIM_BASELINE, fh)
        os.replace(tmp, path)
    except Exception:
        pass  # best-effort persistence — a restart just re-baselines, no crash


def _scan_file_integrity(watch_dirs: list[str], *, max_files: int = 2000) -> list[dict]:
    """Real add/modify/delete diff against a persisted baseline. Returns
    Sentinel detections for modified/deleted files (added files are recorded
    for visibility but aren't inherently a threat, so they don't spawn a
    finding/incident on their own)."""
    global _FIM_LAST_SUMMARY, _FIM_LAST_EVENTS
    detections: list[dict] = []
    events: list[dict] = []
    with _FIM_LOCK:
        baseline = _fim_load_baseline()
        first_run = not baseline
        seen_paths: set[str] = set()
        added = modified = deleted = 0
        for path, _name, st in _iter_watch_files(watch_dirs, max_files=max_files):
            seen_paths.add(path)
            hashable = st.st_size <= _FIM_MAX_HASH_BYTES
            digest = _sha256_file(path) if hashable else ""
            prior = baseline.get(path)
            if prior is None:
                baseline[path] = {"hash": digest, "size": st.st_size, "mtime": st.st_mtime}
                if not first_run:
                    added += 1
                    events.append({"path": path, "status": "added", "hash": digest})
                continue
            if hashable and prior.get("hash"):
                changed = digest != prior.get("hash")
            else:
                # Large file we don't hash — coarse fallback via size/mtime.
                changed = st.st_size != prior.get("size") or abs(st.st_mtime - float(prior.get("mtime") or 0)) > 1
            if changed:
                baseline[path] = {"hash": digest, "size": st.st_size, "mtime": st.st_mtime}
                modified += 1
                events.append({"path": path, "status": "modified", "hash": digest})
                detections.append({
                    "severity": "medium", "category": "file_integrity",
                    "title": f"Monitored file modified: {os.path.basename(path)}",
                    "detail": f"Path: {path}", "target": path, "hash": digest,
                })
            else:
                baseline[path]["mtime"] = st.st_mtime
        # Deletions: baseline paths still under a watch dir but no longer seen.
        for path in list(baseline.keys()):
            if path in seen_paths:
                continue
            if not any(path.startswith(d.rstrip(os.sep) + os.sep) for d in watch_dirs):
                continue
            if os.path.exists(path):
                continue  # exists but wasn't re-visited this tick (size/count caps)
            del baseline[path]
            deleted += 1
            events.append({"path": path, "status": "deleted"})
            detections.append({
                "severity": "medium", "category": "file_integrity",
                "title": f"Monitored file deleted: {os.path.basename(path)}",
                "detail": f"Path: {path}", "target": path,
            })
        _fim_save_baseline()
        _FIM_LAST_SUMMARY = {
            "tracked_files": len(baseline), "baseline_established": True,
            "added": added, "modified": modified, "deleted": deleted,
            "last_scan_ts": time.time(),
        }
        _FIM_LAST_EVENTS = events[-50:]
    return detections


def fim_recent_events() -> list[dict]:
    """Real, current FIM event log for the telemetry check-in payload —
    replaces the old hardcoded empty list. Empty until Sentinel has run at
    least once (honest: no FIM data yet, not a fabricated result)."""
    with _FIM_LOCK:
        return list(_FIM_LAST_EVENTS)


def sentinel_scan(watch_dirs: list[str], known_hashes: dict[str, str]) -> list[dict]:
    """One full Sentinel pass: signature + behavioral + ransomware + network +
    file-integrity. Returns a flat list of detection dicts, each already
    shaped for POST /api/agents/threat."""
    detections: list[dict] = []
    try:
        detections += _scan_signature(watch_dirs, known_hashes)
    except Exception:
        pass
    try:
        detections += _scan_behavioral(_process_snapshot_detailed())
    except Exception:
        pass
    try:
        detections += _scan_ransomware(watch_dirs)
    except Exception:
        pass
    try:
        detections += _scan_network()
    except Exception:
        pass
    try:
        detections += _scan_file_integrity(watch_dirs)
    except Exception:
        pass
    return detections


def load_hash_feed(path: str) -> dict[str, str]:
    """Optional extra known-bad-hash list: lines of 'sha256,label'. Lets a
    real deployment extend the tiny bundled seed list without editing this
    script."""
    out: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",", 1)
                digest = parts[0].strip().lower()
                label = parts[1].strip() if len(parts) > 1 else "custom-feed"
                if len(digest) == 64:
                    out[digest] = label
    except Exception:
        pass
    return out


def send_threat_report(server: str, token: str, detections: list[dict], *, insecure: bool = False, timeout: float = 15.0) -> dict:
    url = server.rstrip("/") + "/api/agents/threat"
    data = json.dumps({"detections": detections}).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": f"SecuraIQ-Agent/{AGENT_VERSION}",
        },
    )
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def sentinel_loop(server: str, token: str, *, interval: int, watch_dirs: list[str], known_hashes: dict[str, str], insecure: bool = False, stop_event: "threading.Event | None" = None):
    """Background watcher thread: scans on its own fast cadence, independent
    of the telemetry check-in loop, and pushes new detections the moment
    they're found."""
    print(f"[sentinel] watching {len(watch_dirs)} dir(s) every {interval}s — {SENTINEL_VERSION}")
    while not (stop_event and stop_event.is_set()):
        try:
            detections = sentinel_scan(watch_dirs, known_hashes)
            if detections:
                with _SENTINEL_STATE_LOCK:
                    result = send_threat_report(server, token, detections, insecure=insecure)
                created = result.get("created", 0)
                skipped = result.get("skipped", 0)
                if created:
                    print(f"[sentinel] {created} new detection(s) reported, {skipped} still-active (re-alert suppressed)")
        except urllib.error.HTTPError as exc:
            print(f"[sentinel] report FAILED: HTTP {exc.code}", file=sys.stderr)
        except Exception as exc:
            print(f"[sentinel] scan error: {exc}", file=sys.stderr)
        time.sleep(max(3, interval))


def _collect_safe(fn, default):
    """Run a collector, but never let one collector's crash take down the
    whole check-in -- falls back to an honest "not collected" default
    rather than dropping the field or fabricating a value."""
    try:
        return fn()
    except Exception as exc:
        d = dict(default)
        d["reason"] = f"Collector raised: {exc}"
        return d


def collect_snapshot() -> dict:
    uname = platform.uname()
    try:
        uptime_sec = time.time() - float(open("/proc/uptime").read().split()[0]) if os.path.exists("/proc/uptime") else None
    except Exception:
        uptime_sec = None
    return {
        "hostname": socket.gethostname(),
        "ip": _primary_ip(),
        "os": uname.system,
        "os_version": f"{uname.release} {uname.version}".strip()[:120],
        "agent_version": AGENT_VERSION,
        "listening_ports": _listening_ports(),
        "processes": _processes(),
        "packages": _packages(),
        "file_integrity": fim_recent_events(),  # real baseline-diff events from Sentinel's FIM pass
        "uptime_sec": uptime_sec,
        # Deep telemetry (task #140) -- each collector honestly reports
        # collected=False + a real reason on failure/unsupported OS, never a
        # fabricated "clean" result. See collector docstrings above.
        "services": _collect_safe(_services, {"collected": False, "items": []}),
        "local_users": _collect_safe(_local_users, {"collected": False, "items": []}),
        "local_groups": _collect_safe(_local_groups, {"collected": False, "items": []}),
        "hardware": _collect_safe(_hardware, {"collected": False}),
        "network": _collect_safe(_network, {"collected": False, "interfaces": []}),
        "firewall_status": _collect_safe(_firewall_status, {"collected": False, "enabled": None}),
        "disk_encryption_status": _collect_safe(_disk_encryption_status, {"collected": False, "encrypted": None}),
        "defender_status": _collect_safe(_defender_status, {"collected": False, "enabled": None}),
        "startup_apps": _collect_safe(_startup_apps, {"collected": False, "items": []}),
        "ssh_config": _collect_safe(_ssh_config, {"collected": False, "settings": {}}),
    }


# ---------------------------------------------------------------------------
# Patch command execution — the agent side of the patch + verify loop.
#
# The server never sends an arbitrary shell string: a command is always one
# of known kinds -- {"kind": "patch_package", ...}, {"kind": "agent_upgrade",
# ...}, {"kind": "enable_firewall", "payload": {}}, or
# {"kind": "enable_defender", "payload": {}} -- and only
# the four package managers below are ever invoked for patch_package, each
# with the package name passed as a single subprocess argument (never
# interpolated into a shell string), so a compromised/malicious server
# response still can't achieve arbitrary command execution here.
# ---------------------------------------------------------------------------

_PACKAGE_MANAGER_UPGRADE_CMD = {
    # (installed-version lookup, upgrade command) — both real subprocess
    # argv lists, no shell=True anywhere in this file.
    "apt": {
        "version": lambda pkg: ["dpkg-query", "-W", "-f=${Version}", pkg],
        "upgrade": lambda pkg: ["apt-get", "install", "--only-upgrade", "-y", pkg],
        "needs_root": True,
    },
    "winget": {
        "version": None,  # winget's list output isn't reliably single-line parseable; see below
        "upgrade": lambda pkg: [
            "winget", "upgrade", "--id", pkg, "-e", "--silent",
            "--accept-package-agreements", "--accept-source-agreements",
        ],
        "needs_root": False,
    },
    "brew": {
        "version": lambda pkg: ["brew", "list", "--versions", pkg],
        "upgrade": lambda pkg: ["brew", "upgrade", pkg],
        "needs_root": False,
    },
    "pip": {
        "version": lambda pkg: [sys.executable, "-m", "pip", "show", pkg],
        "upgrade": lambda pkg: [sys.executable, "-m", "pip", "install", "--upgrade", pkg],
        "needs_root": False,
    },
}

_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,199}$")


def _pkg_version(manager: str, package: str) -> str:
    """Best-effort installed-version lookup for the 'before' snapshot in the
    result report. Returns "" (not a guess) when the manager doesn't expose
    a simply-parseable version, or the package isn't found."""
    import subprocess

    spec = _PACKAGE_MANAGER_UPGRADE_CMD.get(manager) or {}
    getter = spec.get("version")
    if not getter:
        return ""
    try:
        out = subprocess.run(getter(package), capture_output=True, text=True, timeout=15)
    except Exception:
        return ""
    if out.returncode != 0:
        return ""
    text = (out.stdout or "").strip()
    if manager == "pip":
        for line in text.splitlines():
            if line.lower().startswith("version:"):
                return line.split(":", 1)[1].strip()
        return ""
    return text.splitlines()[0].strip() if text else ""


def execute_patch_package(payload: dict) -> dict:
    """Run one package-manager upgrade. Always returns a result dict — never
    raises — so the check-in loop can report failure honestly back to the
    server instead of crashing the whole agent process."""
    import subprocess

    manager = str(payload.get("manager") or "").strip().lower()
    package = str(payload.get("package") or "").strip()
    spec = _PACKAGE_MANAGER_UPGRADE_CMD.get(manager)
    if not spec:
        return {"ok": False, "error": f"Unsupported package manager '{manager}'. Supported: {sorted(_PACKAGE_MANAGER_UPGRADE_CMD)}"}
    if not package or not _PACKAGE_NAME_RE.match(package):
        return {"ok": False, "error": "Invalid or missing package name"}
    import shutil

    binary = spec["upgrade"](package)[0]
    if shutil.which(binary) is None:
        return {"ok": False, "error": f"'{binary}' not found on this host — is {manager} installed?"}
    if spec.get("needs_root") and hasattr(os, "geteuid") and os.geteuid() != 0:
        return {"ok": False, "error": f"{manager} upgrades need root/sudo — agent is not running as root"}
    old_version = _pkg_version(manager, package)
    try:
        out = subprocess.run(spec["upgrade"](package), capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Upgrade command timed out after 600s", "old_version": old_version}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "old_version": old_version}
    new_version = _pkg_version(manager, package)
    ok = out.returncode == 0
    return {
        "ok": ok,
        "manager": manager,
        "package": package,
        "old_version": old_version,
        "new_version": new_version,
        "exit_code": out.returncode,
        "output": ((out.stdout or "") + "\n" + (out.stderr or ""))[-4000:],
        **({} if ok else {"error": f"exit code {out.returncode}"}),
    }


# ---------------------------------------------------------------------------
# Self-upgrade command execution.
#
# Never a blind "run whatever the server sends now" fetch: the command's
# payload carries expected_sha256, computed by the server from its OWN
# scripts/securaiq_agent.py at the moment a human requested the upgrade. At
# execution time this downloads the server's current install-script and
# only proceeds if its sha256 still matches that pre-approved value -- if
# the server's file changed since approval (a compromised server, or a
# newer release landing mid-flight), the mismatch is reported as an error
# and nothing on disk is touched. This is the one narrowly-scoped
# self-modification this agent is allowed: fetch and checksum-verify one
# server-declared file, replace this script with it, and exit for the
# service supervisor to restart with the new code. It never executes
# arbitrary code the server sends -- same "no shell strings from the
# server" discipline as execute_patch_package above.
# ---------------------------------------------------------------------------


def execute_agent_upgrade(payload: dict, *, server: str, insecure: bool = False) -> dict:
    """Download and verify the server's agent script, then atomically
    replace this file with it. Always returns a result dict -- never
    raises."""
    expected = str(payload.get("expected_sha256") or "").strip().lower()
    if not expected:
        return {
            "ok": False,
            "error": "No expected_sha256 in command payload -- refusing to self-upgrade without a "
            "server-declared checksum to verify against",
        }
    url = server.rstrip("/") + "/api/agents/install-script"
    req = urllib.request.Request(url, headers={"User-Agent": f"SecuraIQ-Agent/{AGENT_VERSION}"})
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            new_content = resp.read()
    except Exception as exc:
        return {"ok": False, "error": f"Could not download install script: {exc}"}
    actual = hashlib.sha256(new_content).hexdigest()
    if actual != expected:
        return {
            "ok": False,
            "error": "Checksum mismatch -- the server's install-script content no longer matches what "
            "was approved. Refusing to self-upgrade.",
            "expected_sha256": expected,
            "actual_sha256": actual,
        }
    if _is_frozen():
        return {
            "ok": False,
            "error": "Packaged binary agents cannot self-upgrade in place. "
            "Download a new SecuraIQ-Agent package from your server / release and reinstall.",
            "expected_sha256": expected,
            "actual_sha256": actual,
        }
    this_file = os.path.abspath(__file__)
    tmp_path = this_file + ".new"
    try:
        with open(tmp_path, "wb") as fh:
            fh.write(new_content)
        os.replace(tmp_path, this_file)
    except Exception as exc:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        return {"ok": False, "error": f"Could not write new agent script: {exc}"}
    return {
        "ok": True,
        "sha256": actual,
        "note": "Script replaced -- process will exit so the service supervisor restarts it with the new code",
    }


def execute_enable_firewall(payload: dict | None = None) -> dict:
    """Enable host firewall on lab/owned systems via fixed argv only.

    Never interpolates untrusted strings into a shell. Windows: Set-NetFirewallProfile
    with a fixed PowerShell -Command string. Linux: ufw enable, else report
    firewall-cmd state honestly if enable is unavailable.
    """
    _ = payload  # reserved for future safe flags; ignore untrusted content
    system = platform.system().lower()
    if system == "windows":
        # Fixed argv — no payload interpolation into the PowerShell string.
        ps = (
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; "
            "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
        )
        ok, out = _run(
            ["powershell", "-NoProfile", "-Command", ps],
            timeout=30,
        )
        if not ok:
            return {
                "ok": False,
                "error": "Set-NetFirewallProfile failed or unavailable (elevation may be required)",
                "backend": "Windows Firewall",
                "output": (out or "")[-2000:],
            }
        return {
            "ok": True,
            "backend": "Windows Firewall",
            "note": "Enabled Domain,Public,Private profiles",
            "output": (out or "")[-2000:],
        }
    if system == "linux":
        ok, out = _run(["ufw", "--force", "enable"], timeout=30)
        if ok:
            return {
                "ok": True,
                "backend": "ufw",
                "note": "ufw --force enable succeeded",
                "output": (out or "")[-2000:],
            }
        # Honest fallback: report firewalld state; do not invent enable success.
        state_ok, state_out = _run(["firewall-cmd", "--state"], timeout=8)
        if state_ok:
            return {
                "ok": False,
                "error": (
                    "ufw enable failed; firewalld is present "
                    f"(state={state_out.strip()!r}) but auto-enable via firewall-cmd "
                    "is not performed by this agent — enable manually or install ufw"
                ),
                "backend": "firewalld",
                "firewall_state": state_out.strip(),
            }
        return {
            "ok": False,
            "error": (
                "Could not enable firewall: ufw enable failed and firewall-cmd "
                "unavailable — enable manually on this host"
            ),
            "backend": None,
            "output": (out or "")[-1000:],
        }
    if system == "darwin":
        return {
            "ok": False,
            "error": "enable_firewall is not automated on macOS — enable Application Firewall manually",
            "backend": "pf/ALF",
        }
    return {"ok": False, "error": f"Unsupported OS '{system}' for enable_firewall"}


def execute_enable_defender(payload: dict | None = None) -> dict:
    """Enable Windows Defender realtime protection via fixed argv only.

    Never interpolates untrusted strings into a shell. Windows: Set-MpPreference
    -DisableRealtimeMonitoring $false. Non-Windows: honest not supported.
    """
    _ = payload  # reserved for future safe flags; ignore untrusted content
    system = platform.system().lower()
    if system != "windows":
        return {
            "ok": False,
            "error": (
                f"enable_defender is not supported on {system} — "
                "Microsoft Defender realtime preference is Windows-only"
            ),
            "backend": None,
        }
    # Fixed argv — no payload interpolation into the PowerShell string.
    ps = (
        "Set-MpPreference -DisableRealtimeMonitoring $false; "
        "Get-MpComputerStatus | Select-Object AntivirusEnabled,"
        "RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json -Compress"
    )
    ok, out = _run(
        ["powershell", "-NoProfile", "-Command", ps],
        timeout=30,
    )
    if not ok:
        return {
            "ok": False,
            "error": (
                "Set-MpPreference failed or unavailable "
                "(elevation may be required, Defender module missing, "
                "or a third-party AV has taken over)"
            ),
            "backend": "Microsoft Defender",
            "output": (out or "")[-2000:],
        }
    return {
        "ok": True,
        "backend": "Microsoft Defender",
        "note": "Set-MpPreference -DisableRealtimeMonitoring $false applied",
        "output": (out or "")[-2000:],
    }


def send_command_result(server: str, token: str, command_id: str, status: str, result: dict, *, insecure: bool = False, timeout: float = 15.0) -> dict:
    url = server.rstrip("/") + f"/api/agents/commands/{command_id}/result"
    data = json.dumps({"status": status, "result": result}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": f"SecuraIQ-Agent/{AGENT_VERSION}",
    }
    headers.update(_replay_headers(token, data))
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers=headers,
    )
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run_commands(server: str, token: str, commands: list, *, insecure: bool = False) -> None:
    upgraded = False
    agent_id = _agent_id_from_token(token)
    for cmd in commands or []:
        kind = cmd.get("kind")
        cid = cmd.get("id")
        if not cid:
            continue
        cmd_aid = str(cmd.get("agent_id") or "") or agent_id
        if not _command_signatures_ok(cmd, agent_id=cmd_aid):
            print(f"[securaiq-agent] refusing command {cid}: signature verification failed", file=sys.stderr)
            try:
                send_command_result(
                    server, token, cid, "error",
                    {"error": "signature verification failed", "ok": False},
                    insecure=insecure,
                )
            except Exception:
                pass
            continue
        try:
            send_command_ack(server, token, cid, insecure=insecure)
        except Exception:
            pass
        if kind == "patch_package":
            print(f"[securaiq-agent] running command {cid}: patch_package {cmd.get('payload')}")
            result = execute_patch_package(cmd.get("payload") or {})
            summary = f"{result.get('old_version', '?')} -> {result.get('new_version', '?')}"
        elif kind == "agent_upgrade":
            print(f"[securaiq-agent] running command {cid}: agent_upgrade")
            result = execute_agent_upgrade(cmd.get("payload") or {}, server=server, insecure=insecure)
            upgraded = upgraded or bool(result.get("ok"))
            summary = result.get("note") or result.get("error") or "?"
        elif kind == "enable_firewall":
            print(f"[securaiq-agent] running command {cid}: enable_firewall")
            result = execute_enable_firewall(cmd.get("payload") or {})
            summary = result.get("note") or result.get("error") or "?"
        elif kind == "enable_defender":
            print(f"[securaiq-agent] running command {cid}: enable_defender")
            result = execute_enable_defender(cmd.get("payload") or {})
            summary = result.get("note") or result.get("error") or "?"
        else:
            send_command_result(server, token, cid, "error", {"error": f"Unknown command kind '{kind}'"}, insecure=insecure)
            continue
        status = "done" if result.get("ok") else "error"
        try:
            send_command_result(server, token, cid, status, result, insecure=insecure)
            print(f"[securaiq-agent] command {cid} {status}: {summary}")
        except Exception as exc:
            print(f"[securaiq-agent] could not report result for command {cid}: {exc}", file=sys.stderr)
    if upgraded:
        print("[securaiq-agent] self-upgrade applied -- exiting so the service supervisor restarts with the new code")
        sys.exit(0)


def _replay_headers(token: str, body: bytes) -> dict:
    """Timestamp + nonce + request HMAC so the server can reject replayed check-ins.

    ``X-SecuraIQ-Sig`` = HMAC-SHA256(agent_key, ``ts.nonce.sha256(body)``) —
    matches ``app.agent_auth.sign_payload``.
    """
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    headers = {
        "X-SecuraIQ-Ts": ts,
        "X-SecuraIQ-Nonce": nonce,
    }
    parts = (token or "").split(".", 1)
    agent_key = parts[1] if len(parts) == 2 else ""
    if agent_key:
        digest = hashlib.sha256(body or b"").hexdigest()
        msg = f"{ts}.{nonce}.{digest}".encode("utf-8")
        headers["X-SecuraIQ-Sig"] = hmac.new(
            agent_key.encode("utf-8"), msg, hashlib.sha256
        ).hexdigest()
    return headers


def send_checkin(server: str, token: str, payload: dict, *, insecure: bool = False, timeout: float = 15.0) -> dict:
    url = server.rstrip("/") + "/api/agents/checkin"
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": f"SecuraIQ-Agent/{AGENT_VERSION}",
    }
    headers.update(_replay_headers(token, data))
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers=headers,
    )
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def gateway_wait(
    server: str,
    token: str,
    *,
    timeout_sec: float = 25.0,
    insecure: bool = False,
) -> dict:
    """Long-poll the Agent Gateway for near-instant command delivery."""
    url = server.rstrip("/") + "/api/agents/gateway/wait"
    data = json.dumps({"timeout_sec": timeout_sec, "limit": 5}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": f"SecuraIQ-Agent/{AGENT_VERSION}",
    }
    headers.update(_replay_headers(token, data))
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers=headers,
    )
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    # Long-poll can sit until timeout_sec; add a small buffer.
    with urllib.request.urlopen(req, timeout=max(35.0, timeout_sec + 10.0), context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_command_ack(server: str, token: str, command_id: str, *, insecure: bool = False) -> dict:
    url = server.rstrip("/") + f"/api/agents/commands/{command_id}/ack"
    data = b"{}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": f"SecuraIQ-Agent/{AGENT_VERSION}",
    }
    headers.update(_replay_headers(token, data))
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers=headers,
    )
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=15.0, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _ws_url(server: str) -> str:
    base = server.rstrip("/")
    if base.startswith("https://"):
        return "wss://" + base[8:] + "/api/agents/ws"
    if base.startswith("http://"):
        return "ws://" + base[7:] + "/api/agents/ws"
    return "ws://" + base + "/api/agents/ws"


def _ws_connect(server: str, token: str, *, insecure: bool = False, timeout: float = 15.0):
    """Minimal RFC6455 client (stdlib only). Returns a connected socket or None."""
    url = _ws_url(server)
    tls = url.startswith("wss://")
    rest = url.split("://", 1)[1]
    hostport, _, path = rest.partition("/")
    path = "/" + path
    if ":" in hostport:
        host, port_s = hostport.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = hostport, (443 if tls else 80)
    sock = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {hostport}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Authorization: Bearer {token}\r\n"
        f"User-Agent: SecuraIQ-Agent/{AGENT_VERSION}\r\n"
        "\r\n"
    )
    sock.sendall(req.encode("ascii"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            sock.close()
            return None
        buf += chunk
    header, _, rest = buf.partition(b"\r\n\r\n")
    if b"101" not in header.split(b"\r\n", 1)[0]:
        sock.close()
        return None
    return sock, rest


def _ws_mask(payload: bytes) -> bytes:
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return mask + masked


def _ws_send_text(sock, text: str) -> None:
    payload = text.encode("utf-8")
    header = bytearray([0x81])
    n = len(payload)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.extend(struct.pack("!BH", 0x80 | 126, n))
    else:
        header.extend(struct.pack("!BQ", 0x80 | 127, n))
    sock.sendall(bytes(header) + _ws_mask(payload))


def _ws_recv_text(sock, leftover: bytearray, timeout: float) -> str | None:
    sock.settimeout(timeout)
    while True:
        while len(leftover) < 2:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            leftover.extend(chunk)
        b1, b2 = leftover[0], leftover[1]
        opcode = b1 & 0x0F
        masked = b2 & 0x80
        n = b2 & 0x7F
        idx = 2
        if n == 126:
            while len(leftover) < 4:
                leftover.extend(sock.recv(4096) or b"")
            n = struct.unpack("!H", leftover[2:4])[0]
            idx = 4
        elif n == 127:
            while len(leftover) < 10:
                leftover.extend(sock.recv(4096) or b"")
            n = struct.unpack("!Q", leftover[2:10])[0]
            idx = 10
        if masked:
            while len(leftover) < idx + 4:
                leftover.extend(sock.recv(4096) or b"")
            mask = leftover[idx : idx + 4]
            idx += 4
        else:
            mask = None
        while len(leftover) < idx + n:
            leftover.extend(sock.recv(4096) or b"")
        data = bytes(leftover[idx : idx + n])
        del leftover[: idx + n]
        if mask:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        if opcode == 0x8:
            return None
        if opcode == 0x9:  # ping
            # pong
            hdr = bytearray([0x8A, 0x80 | len(data)])
            sock.sendall(bytes(hdr) + _ws_mask(data))
            continue
        if opcode == 0x1:
            return data.decode("utf-8", errors="replace")


def websocket_session(
    server: str,
    token: str,
    *,
    insecure: bool = False,
    stop_event: threading.Event | None = None,
    offline_buf: OfflineTelemetryBuffer | None = None,
) -> bool:
    """Persistent gateway session. Returns False if connect failed (caller should fall back)."""
    try:
        conn = _ws_connect(server, token, insecure=insecure)
    except Exception as exc:
        print(f"[securaiq-agent] websocket connect failed: {exc}", file=sys.stderr)
        return False
    if not conn:
        print("[securaiq-agent] websocket handshake rejected — using HTTP fallback", file=sys.stderr)
        return False
    sock, rest = conn
    leftover = bytearray(rest)
    try:
        hello = {"type": "hello", "token": token, "ts": str(int(time.time())), "nonce": secrets.token_hex(8)}
        _ws_send_text(sock, json.dumps(hello))
        raw = _ws_recv_text(sock, leftover, 15.0)
        if not raw:
            return False
        welcome = json.loads(raw)
        if welcome.get("type") != "welcome":
            print(f"[securaiq-agent] websocket hello failed: {welcome}", file=sys.stderr)
            return False
        hb = int(welcome.get("heartbeat_sec") or 30)
        print("[securaiq-agent] websocket connected — commands will be pushed")
        snapshot = collect_snapshot()
        checkin_payload = dict(snapshot)
        if offline_buf is not None:
            checkin_payload.update(offline_buf.build_checkin_extension())
        _ws_send_text(sock, json.dumps({"type": "checkin", "payload": checkin_payload}))
        last_hb = time.time()
        while not (stop_event and stop_event.is_set()):
            wait = max(5.0, hb - (time.time() - last_hb))
            try:
                raw = _ws_recv_text(sock, leftover, wait)
            except socket.timeout:
                _ws_send_text(sock, json.dumps({"type": "heartbeat", "ts": time.time()}))
                last_hb = time.time()
                continue
            if raw is None:
                return True  # disconnected after a successful session — reconnect
            msg = json.loads(raw)
            kind = msg.get("type")
            if kind == "commands":
                cmds = msg.get("commands") or []
                for c in cmds:
                    cid = c.get("id")
                    if cid:
                        _ws_send_text(sock, json.dumps({"type": "ack", "command_id": cid}))
                if cmds:
                    run_commands(server, token, cmds, insecure=insecure)
            elif kind == "pong":
                last_hb = time.time()
            elif kind == "checkin_ok":
                if offline_buf is not None:
                    drained = offline_buf.apply_server_ack(msg)
                    if drained:
                        print(
                            f"[securaiq-agent] offline buffer drained {drained} event(s); "
                            f"pending={offline_buf.pending_count}"
                        )
                print(f"[securaiq-agent] ws check-in ok asset_id={msg.get('asset_id', '')}")
        return True
    except Exception as exc:
        print(f"[securaiq-agent] websocket session ended: {exc}", file=sys.stderr)
        return True
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main() -> int:
    # Load agent.env before argparse defaults so SECURAIQ_* from the file apply.
    config_path = _autoload_config()

    ap = argparse.ArgumentParser(description="SecuraIQ native agent — real telemetry check-in")
    ap.add_argument(
        "--version", action="version", version=f"SecuraIQ-Agent {AGENT_VERSION}",
    )
    ap.add_argument(
        "--server", default=os.environ.get("SECURAIQ_SERVER", ""),
        help="SecuraIQ server base URL, e.g. https://securaiq.example.com (or set SECURAIQ_SERVER)",
    )
    ap.add_argument(
        "--token", default=os.environ.get("SECURAIQ_TOKEN", ""),
        help="Agent token from enrollment: <agent_id>.<agent_key> (or set SECURAIQ_TOKEN)",
    )
    ap.add_argument(
        "--token-file", default="",
        help="Path to a file containing just the token — for running as a service without the "
             "token showing up in `ps`/Task Manager. Recommended permissions: readable by the "
             "service account only (chmod 600 on Linux/macOS).",
    )
    ap.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_SEC, help="Seconds between check-ins (default 60)")
    ap.add_argument(
        "--gateway",
        action="store_true",
        default=True,
        help="Long-poll Agent Gateway between check-ins for faster command delivery (default on)",
    )
    ap.add_argument(
        "--no-gateway",
        action="store_true",
        help="Disable gateway long-poll; rely on check-in interval only",
    )
    ap.add_argument(
        "--no-websocket",
        action="store_true",
        help="Skip WebSocket Agent Gateway; use long-poll + HTTP check-in",
    )
    ap.add_argument("--once", action="store_true", help="Check in once and exit (for cron/Task Scheduler use)")
    ap.add_argument(
        "--insecure",
        action="store_true",
        default=os.environ.get("SECURAIQ_INSECURE", "").strip().lower() in ("1", "true", "yes"),
        help="Skip TLS verification (self-signed server certs only; or SECURAIQ_INSECURE=1)",
    )
    ap.add_argument("--no-sentinel", action="store_true", help="Disable the real-time Sentinel threat watcher")
    ap.add_argument(
        "--sentinel-interval", type=int, default=DEFAULT_SENTINEL_INTERVAL_SEC,
        help=f"Seconds between Sentinel scans (default {DEFAULT_SENTINEL_INTERVAL_SEC}) — independent of --interval",
    )
    ap.add_argument("--watch-dir", action="append", default=[], help="Extra directory for Sentinel to watch (repeatable)")
    ap.add_argument("--hash-feed", default="", help="Optional file of extra known-bad 'sha256,label' lines for signature matching")
    ap.add_argument(
        "--no-offline-buffer",
        action="store_true",
        help="Disable local offline telemetry buffer (no enqueue/flush on check-in failure)",
    )
    args = ap.parse_args()

    if args.token_file:
        try:
            with open(args.token_file, "r", encoding="utf-8") as fh:
                file_token = fh.read().strip()
            if file_token:
                args.token = file_token
        except Exception as exc:
            print(f"[securaiq-agent] could not read --token-file {args.token_file}: {exc}", file=sys.stderr)
            return 2
    if not args.server or not args.token:
        print(
            "[securaiq-agent] --server and --token are required (directly, via --token-file, "
            "via SECURAIQ_SERVER/SECURAIQ_TOKEN env vars, or agent.env next to the binary)",
            file=sys.stderr,
        )
        home = _agent_home()
        print(
            f"[securaiq-agent] Copy agent.env.example to {os.path.join(home, 'agent.env')} "
            "and set SECURAIQ_SERVER + SECURAIQ_TOKEN from Security Operations → Agents → Enroll.",
            file=sys.stderr,
        )
        return 2

    if config_path:
        print(f"[securaiq-agent] loaded config from {config_path}")

    watch_dirs = _default_watch_dirs() + [d for d in args.watch_dir if os.path.isdir(d)]
    known_hashes = dict(KNOWN_BAD_HASHES)
    if args.hash_feed:
        known_hashes.update(load_hash_feed(args.hash_feed))

    agent_id = _agent_id_from_token(args.token)
    offline_buf: OfflineTelemetryBuffer | None = None
    if not args.no_offline_buffer:
        offline_buf = OfflineTelemetryBuffer(agent_id)
        if offline_buf.pending_count:
            print(f"[securaiq-agent] offline buffer pending={offline_buf.pending_count} path={offline_buf.path}")

    def _tick() -> bool:
        snapshot = collect_snapshot()
        payload = dict(snapshot)
        if offline_buf is not None:
            payload.update(offline_buf.build_checkin_extension())
        try:
            result = send_checkin(args.server, args.token, payload, insecure=args.insecure)
            ok = bool(result.get("ok"))
            print(
                f"[securaiq-agent] check-in {'ok' if ok else 'FAILED'} · "
                f"host={snapshot['hostname']} ports={len(snapshot['listening_ports'])} "
                f"packages={len(snapshot['packages'])} asset_id={result.get('asset_id', '')}"
            )
            if offline_buf is not None and ok:
                drained = offline_buf.apply_server_ack(result)
                if drained:
                    print(
                        f"[securaiq-agent] offline buffer drained {drained} event(s); "
                        f"pending={offline_buf.pending_count}"
                    )
            commands = result.get("commands") or []
            if commands:
                run_commands(args.server, args.token, commands, insecure=args.insecure)
            return ok
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            print(f"[securaiq-agent] check-in FAILED: HTTP {exc.code} {body}", file=sys.stderr)
            if offline_buf is not None:
                seq = offline_buf.enqueue("telemetry", _compact_snapshot_for_buffer(snapshot))
                print(
                    f"[securaiq-agent] buffered telemetry seq={seq} pending={offline_buf.pending_count}",
                    file=sys.stderr,
                )
            return False
        except Exception as exc:
            print(f"[securaiq-agent] check-in FAILED: {exc}", file=sys.stderr)
            if offline_buf is not None:
                seq = offline_buf.enqueue("telemetry", _compact_snapshot_for_buffer(snapshot))
                print(
                    f"[securaiq-agent] buffered telemetry seq={seq} pending={offline_buf.pending_count}",
                    file=sys.stderr,
                )
            return False

    if args.once:
        ok = _tick()
        if not args.no_sentinel:
            try:
                detections = sentinel_scan(watch_dirs, known_hashes)
                if detections:
                    result = send_threat_report(args.server, args.token, detections, insecure=args.insecure)
                    print(f"[sentinel] one-shot scan: {result.get('created', 0)} new detection(s) reported")
                else:
                    print("[sentinel] one-shot scan: no detections")
            except Exception as exc:
                print(f"[sentinel] one-shot scan FAILED: {exc}", file=sys.stderr)
        return 0 if ok else 1

    print(f"[securaiq-agent] starting — server={args.server} interval={args.interval}s")
    if not args.no_sentinel:
        t = threading.Thread(
            target=sentinel_loop,
            kwargs=dict(
                server=args.server, token=args.token, interval=args.sentinel_interval,
                watch_dirs=watch_dirs, known_hashes=known_hashes, insecure=args.insecure,
            ),
            daemon=True,
        )
        t.start()
    backoff = 2.0
    while True:
        if not args.no_websocket:
            connected = websocket_session(
                args.server, args.token, insecure=args.insecure, offline_buf=offline_buf
            )
            if connected:
                backoff = 2.0
                time.sleep(min(5.0, backoff))
                continue
            print("[securaiq-agent] websocket unavailable — HTTP check-in + long-poll fallback")
        _tick()
        use_gateway = bool(args.gateway) and not bool(args.no_gateway)
        remaining = max(10, args.interval)
        if use_gateway:
            deadline = time.time() + remaining
            while time.time() < deadline:
                slice_sec = min(25.0, max(1.0, deadline - time.time()))
                try:
                    gw = gateway_wait(
                        args.server, args.token, timeout_sec=slice_sec, insecure=args.insecure
                    )
                    commands = gw.get("commands") or []
                    if commands:
                        print(f"[securaiq-agent] gateway delivered {len(commands)} command(s)")
                        run_commands(args.server, args.token, commands, insecure=args.insecure)
                except Exception as exc:
                    print(f"[securaiq-agent] gateway wait failed: {exc}", file=sys.stderr)
                    time.sleep(min(5.0, slice_sec))
        else:
            time.sleep(remaining)
        backoff = min(30.0, backoff * 1.5)


if __name__ == "__main__":
    raise SystemExit(main())
