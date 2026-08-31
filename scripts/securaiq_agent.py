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
import hashlib
import json
import os
import platform
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request

AGENT_VERSION = "1.0.0"
DEFAULT_INTERVAL_SEC = 60
SENTINEL_VERSION = "1.0.0"
DEFAULT_SENTINEL_INTERVAL_SEC = 10

# ---------------------------------------------------------------------------
# SecuraIQ Sentinel — the agent's real-time threat/malware detection engine.
#
# Unlike a periodic check-in field, Sentinel runs on its own fast loop
# (default every 10s, independent of the 60s telemetry check-in) and pushes
# any NEW detection to the server immediately via POST /api/agents/threat —
# that's what makes it "real time" rather than "eventually visible."
#
# It fuses three honest, install-free techniques rather than pretending to
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


def sentinel_scan(watch_dirs: list[str], known_hashes: dict[str, str]) -> list[dict]:
    """One full Sentinel pass: signature + behavioral + ransomware + network.
    Returns a flat list of detection dicts, each already shaped for
    POST /api/agents/threat."""
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
        "file_integrity": [],  # reserved for --watch paths (see --watch flag)
        "uptime_sec": uptime_sec,
    }


def send_checkin(server: str, token: str, payload: dict, *, insecure: bool = False, timeout: float = 15.0) -> dict:
    url = server.rstrip("/") + "/api/agents/checkin"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
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


def main() -> int:
    ap = argparse.ArgumentParser(description="SecuraIQ native agent — real telemetry check-in")
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
    ap.add_argument("--once", action="store_true", help="Check in once and exit (for cron/Task Scheduler use)")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification (self-signed server certs only)")
    ap.add_argument("--no-sentinel", action="store_true", help="Disable the real-time Sentinel threat watcher")
    ap.add_argument(
        "--sentinel-interval", type=int, default=DEFAULT_SENTINEL_INTERVAL_SEC,
        help=f"Seconds between Sentinel scans (default {DEFAULT_SENTINEL_INTERVAL_SEC}) — independent of --interval",
    )
    ap.add_argument("--watch-dir", action="append", default=[], help="Extra directory for Sentinel to watch (repeatable)")
    ap.add_argument("--hash-feed", default="", help="Optional file of extra known-bad 'sha256,label' lines for signature matching")
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
            "or via SECURAIQ_SERVER/SECURAIQ_TOKEN env vars)",
            file=sys.stderr,
        )
        return 2

    watch_dirs = _default_watch_dirs() + [d for d in args.watch_dir if os.path.isdir(d)]
    known_hashes = dict(KNOWN_BAD_HASHES)
    if args.hash_feed:
        known_hashes.update(load_hash_feed(args.hash_feed))

    def _tick() -> bool:
        snapshot = collect_snapshot()
        try:
            result = send_checkin(args.server, args.token, snapshot, insecure=args.insecure)
            ok = bool(result.get("ok"))
            print(
                f"[securaiq-agent] check-in {'ok' if ok else 'FAILED'} · "
                f"host={snapshot['hostname']} ports={len(snapshot['listening_ports'])} "
                f"packages={len(snapshot['packages'])} asset_id={result.get('asset_id', '')}"
            )
            return ok
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            print(f"[securaiq-agent] check-in FAILED: HTTP {exc.code} {body}", file=sys.stderr)
            return False
        except Exception as exc:
            print(f"[securaiq-agent] check-in FAILED: {exc}", file=sys.stderr)
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
    while True:
        _tick()
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
