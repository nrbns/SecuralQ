#!/usr/bin/env python3
"""Build SecuraIQ native-agent packages (Windows / Linux / macOS).

Produces versioned artifacts under dist/agent-packages/:

  SecuraIQ-Agent-<ver>-windows-x64.exe     (standalone binary; this host)
  SecuraIQ-Agent-<ver>-windows-x64.zip     (exe + install.ps1 + docs)
  SecuraIQ-Agent-<ver>-linux-x64.tar.gz    (binary if native/CI, else script layout)
  SecuraIQ-Agent-<ver>-macos-<arch>.tar.gz (portable layout; DMG needs macOS)
  SecuraIQ-Agent-<ver>-macos-<arch>.dmg    (only when run on macOS / CI)

Usage (repo root):
  python scripts/build_agent_packages.py
  python scripts/build_agent_packages.py --platform windows
  python scripts/build_agent_packages.py --platform all --skip-pyinstaller

PyInstaller does not cross-compile. On Windows this script builds a real
Windows exe and portable tar.gz layouts for Linux/macOS (script + installers).
Native Linux/macOS binaries and the .dmg are produced on matching runners
(see .github/workflows/agent-packages.yml).
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGING = ROOT / "scripts" / "packaging"
AGENT_SCRIPT = ROOT / "scripts" / "securaiq_agent.py"
SPEC = ROOT / "packaging" / "securaiq_agent.spec"
OUT = ROOT / "dist" / "agent-packages"
PYI_DIST = ROOT / "dist"
PYI_BUILD = ROOT / "build" / "securaiq_agent"


def _agent_version() -> str:
    text = AGENT_SCRIPT.read_text(encoding="utf-8")
    m = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else "0.0.0"


def _rust_agent_version() -> str:
    cargo = (ROOT / "securaiq-agent" / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', cargo)
    return m.group(1) if m else "0.0.0"


def _host_arch() -> str:
    m = platform.machine().lower()
    if m in ("amd64", "x86_64"):
        return "x64"
    if m in ("arm64", "aarch64"):
        return "arm64"
    return m or "unknown"


def _host_os() -> str:
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "macos"
    if s == "linux":
        return "linux"
    return s


def _python() -> Path:
    venv = ROOT / ".venv" / ("Scripts" if os.name == "nt" else "bin") / (
        "python.exe" if os.name == "nt" else "python"
    )
    if venv.is_file():
        return venv
    return Path(sys.executable)


def _run(cmd: list[str], *, cwd: Path | None = None) -> None:
    print("+", " ".join(cmd))
    subprocess.check_call(cmd, cwd=str(cwd or ROOT))


def ensure_pyinstaller(py: Path) -> None:
    _run([str(py), "-m", "pip", "install", "-q", "pyinstaller>=6.3"])


def build_native_binary(py: Path) -> Path:
    """PyInstaller onefile → dist/SecuraIQ-Agent(.exe). Returns path."""
    ensure_pyinstaller(py)
    _run([str(py), "-m", "PyInstaller", "--noconfirm", "--clean", str(SPEC)])
    name = "SecuraIQ-Agent.exe" if os.name == "nt" else "SecuraIQ-Agent"
    path = PYI_DIST / name
    if not path.is_file():
        raise SystemExit(f"PyInstaller finished but {path} was not created")
    return path


def build_rust_binary() -> Path:
    """``cargo build --release`` → copy to dist/SecuraIQ-Agent(.exe)."""
    crate = ROOT / "securaiq-agent"
    if not (crate / "Cargo.toml").is_file():
        raise SystemExit(f"Rust crate missing: {crate}")
    env = os.environ.copy()
    # Keep artifacts under the crate (Windows sandbox/CI often redirect target/).
    target_dir = crate / "target"
    env["CARGO_TARGET_DIR"] = str(target_dir)
    print("+", "cargo build --release")
    subprocess.check_call(["cargo", "build", "--release"], cwd=str(crate), env=env)
    bin_name = "securaiq-agent.exe" if os.name == "nt" else "securaiq-agent"
    built = target_dir / "release" / bin_name
    if not built.is_file():
        raise SystemExit(f"cargo finished but {built} was not created")
    PYI_DIST.mkdir(parents=True, exist_ok=True)
    dest_name = "SecuraIQ-Agent.exe" if os.name == "nt" else "SecuraIQ-Agent"
    dest = PYI_DIST / dest_name
    shutil.copy2(built, dest)
    # Also drop beside packaging installers for local install.ps1 / install.sh.
    pkg_copy = PACKAGING / dest_name
    shutil.copy2(built, pkg_copy)
    print(f"Rust agent → {dest} (+ {pkg_copy})")
    return dest


def _copy_common(dest: Path, *, include_macos_installer: bool = False) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(PACKAGING / "QUICKSTART.md", dest / "QUICKSTART.md")
    shutil.copy2(PACKAGING / "agent.env.example", dest / "agent.env.example")
    shutil.copy2(AGENT_SCRIPT, dest / "securaiq_agent.py")


def _write_version_file(dest: Path, version: str, target_os: str, arch: str) -> None:
    (dest / "VERSION.txt").write_text(
        f"SecuraIQ-Agent {version}\n"
        f"target={target_os}-{arch}\n"
        f"built_on={_host_os()}-{_host_arch()}\n"
        f"realtime=websocket+/api/agents/ws + gateway wait + HTTP checkin\n",
        encoding="utf-8",
    )


def package_windows(version: str, binary: Path | None) -> list[Path]:
    arch = _host_arch() if _host_os() == "windows" else "x64"
    folder_name = f"SecuraIQ-Agent-{version}-windows-{arch}"
    stage = OUT / "_stage" / folder_name
    if stage.exists():
        shutil.rmtree(stage)
    _copy_common(stage)
    shutil.copy2(PACKAGING / "install.ps1", stage / "install.ps1")
    _write_version_file(stage, version, "windows", arch)

    artifacts: list[Path] = []
    if binary and binary.is_file():
        exe_name = "SecuraIQ-Agent.exe"
        shutil.copy2(binary, stage / exe_name)
        # Standalone versioned exe (open-and-use with agent.env beside it)
        standalone = OUT / f"SecuraIQ-Agent-{version}-windows-{arch}.exe"
        shutil.copy2(binary, standalone)
        artifacts.append(standalone)

    zip_path = OUT / f"{folder_name}.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in stage.rglob("*"):
            if p.is_file():
                zf.write(p, arcname=str(Path(folder_name) / p.relative_to(stage)))
    artifacts.append(zip_path)
    print(f"Windows package: {zip_path}")
    return artifacts


def _make_tar_gz(stage: Path, archive: Path, root_name: str) -> Path:
    if archive.exists():
        archive.unlink()
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(stage, arcname=root_name)
    return archive


def package_linux(version: str, binary: Path | None, *, native: bool) -> list[Path]:
    arch = _host_arch() if native else "x64"
    folder_name = f"SecuraIQ-Agent-{version}-linux-{arch}"
    stage = OUT / "_stage" / folder_name
    if stage.exists():
        shutil.rmtree(stage)
    _copy_common(stage)
    shutil.copy2(PACKAGING / "install.sh", stage / "install.sh")
    # Preserve executable bit in tar via mode when extracting; set now for local use
    try:
        os.chmod(stage / "install.sh", 0o755)
        os.chmod(stage / "securaiq_agent.py", 0o755)
    except OSError:
        pass
    _write_version_file(stage, version, "linux", arch)

    note = stage / "BUILD_NOTES.txt"
    if binary and native and binary.is_file():
        dest_bin = stage / "SecuraIQ-Agent"
        shutil.copy2(binary, dest_bin)
        try:
            os.chmod(dest_bin, 0o755)
        except OSError:
            pass
        note.write_text(
            "This archive includes a native SecuraIQ-Agent binary built on Linux.\n"
            "Run sudo ./install.sh --server URL --token TOKEN\n",
            encoding="utf-8",
        )
    else:
        note.write_text(
            "Portable layout built on a non-Linux host (or --skip-pyinstaller).\n"
            "Includes securaiq_agent.py (Python 3.8+, stdlib only) + install.sh.\n"
            "For a native Linux binary, build on ubuntu-latest / Linux:\n"
            "  python scripts/build_agent_packages.py --platform linux\n"
            "Or use GitHub Actions workflow agent-packages.yml.\n",
            encoding="utf-8",
        )

    archive = OUT / f"{folder_name}.tar.gz"
    _make_tar_gz(stage, archive, folder_name)
    print(f"Linux package: {archive}")
    return [archive]


def package_macos_tarball(version: str, binary: Path | None, *, native: bool) -> list[Path]:
    arch = _host_arch() if native else "arm64"
    # On Intel Mac native builds, use x64; interim from Windows defaults to arm64
    # (Apple Silicon common) but documents both in BUILD_NOTES.
    if native:
        arch = _host_arch()
    folder_name = f"SecuraIQ-Agent-{version}-macos-{arch}"
    stage = OUT / "_stage" / folder_name
    if stage.exists():
        shutil.rmtree(stage)
    _copy_common(stage)
    shutil.copy2(PACKAGING / "install_macos.sh", stage / "install.sh")
    try:
        os.chmod(stage / "install.sh", 0o755)
        os.chmod(stage / "securaiq_agent.py", 0o755)
    except OSError:
        pass
    _write_version_file(stage, version, "macos", arch)

    note = stage / "BUILD_NOTES.txt"
    if binary and native and binary.is_file():
        dest_bin = stage / "SecuraIQ-Agent"
        shutil.copy2(binary, dest_bin)
        try:
            os.chmod(dest_bin, 0o755)
        except OSError:
            pass
        note.write_text(
            "Native macOS binary included. For .dmg run:\n"
            "  bash scripts/packaging/build_macos_dmg.sh\n"
            "Gatekeeper: unsigned builds may need Open Anyway / xattr -dr quarantine.\n",
            encoding="utf-8",
        )
    else:
        note.write_text(
            "Interim portable package (script + launchd installer).\n"
            "A real .dmg requires macOS (local or GitHub Actions macos-*).\n"
            "  bash scripts/packaging/build_macos_dmg.sh\n"
            "Python 3.8+ can run securaiq_agent.py until a native binary is available.\n",
            encoding="utf-8",
        )

    archive = OUT / f"{folder_name}.tar.gz"
    _make_tar_gz(stage, archive, folder_name)
    print(f"macOS tar.gz: {archive}")
    return [archive]


def try_macos_dmg(version: str) -> list[Path]:
    if _host_os() != "macos":
        print("Skipping .dmg (not running on macOS). Use scripts/packaging/build_macos_dmg.sh on a Mac/CI.")
        return []
    script = PACKAGING / "build_macos_dmg.sh"
    _run(["bash", str(script), "--version", version, "--arch", _host_arch(), "--out-dir", str(OUT)])
    dmg = OUT / f"SecuraIQ-Agent-{version}-macos-{_host_arch()}.dmg"
    return [dmg] if dmg.is_file() else []


def smoke_test_binary(binary: Path) -> None:
    print(f"Smoke-testing {binary} …")
    for args in (["--help"], ["--version"]):
        r = subprocess.run(
            [str(binary), *args],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(binary.parent),
        )
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode != 0 and args != ["--help"]:
            print(out)
            raise SystemExit(f"Smoke test failed: {binary} {' '.join(args)} → {r.returncode}")
        if args == ["--version"]:
            # PyInstaller: SecuraIQ-Agent; Rust clap: securaiq-agent <ver>
            if "SecuraIQ" not in out and "securaiq-agent" not in out.lower() and r.returncode != 0:
                print(out)
                raise SystemExit("Smoke test: --version did not identify SecuraIQ agent")
        print(f"  {' '.join(args)}: ok (exit {r.returncode})")


def main() -> int:
    global OUT
    ap = argparse.ArgumentParser(description="Build SecuraIQ Agent packages")
    ap.add_argument(
        "--platform",
        choices=("all", "windows", "linux", "macos", "host"),
        default="all",
        help="Which packages to produce (default: all feasible)",
    )
    ap.add_argument(
        "--skip-pyinstaller",
        action="store_true",
        help="Skip native binary; still produce portable script packages",
    )
    ap.add_argument(
        "--rust",
        action="store_true",
        help="Build the Rust securaiq-agent release binary instead of PyInstaller",
    )
    ap.add_argument(
        "--out-dir",
        default=str(ROOT / "dist" / "agent-packages"),
        help="Artifact output directory (default: dist/agent-packages)",
    )
    ap.add_argument("--no-smoke", action="store_true", help="Skip --help/--version smoke test")
    args = ap.parse_args()

    OUT = Path(args.out_dir)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "_stage").mkdir(parents=True, exist_ok=True)

    version = _rust_agent_version() if args.rust else _agent_version()
    host = _host_os()
    engine = "rust" if args.rust else "pyinstaller"
    print(f"SecuraIQ Agent packaging — version {version} ({engine}) — host {host}-{_host_arch()}")

    want = args.platform
    if want == "host":
        want = host

    need_native = (args.rust or not args.skip_pyinstaller) and (
        want in ("all", host) or (want == "host")
    )
    binary: Path | None = None
    if need_native:
        if args.rust:
            binary = build_rust_binary()
        else:
            py = _python()
            print(f"Using Python: {py}")
            binary = build_native_binary(py)
        if not args.no_smoke:
            smoke_test_binary(binary)

    artifacts: list[Path] = []

    if want in ("all", "windows"):
        artifacts.extend(package_windows(version, binary if host == "windows" else None))

    if want in ("all", "linux"):
        artifacts.extend(
            package_linux(version, binary if host == "linux" else None, native=(host == "linux"))
        )

    if want in ("all", "macos"):
        artifacts.extend(
            package_macos_tarball(
                version, binary if host == "macos" else None, native=(host == "macos")
            )
        )
        if host == "macos" and not args.skip_pyinstaller and not args.rust:
            artifacts.extend(try_macos_dmg(version))

    manifest = OUT / "MANIFEST.txt"
    lines = [f"SecuraIQ-Agent {version}", f"engine={engine}", f"host={host}-{_host_arch()}", ""]
    for p in artifacts:
        if p.is_file():
            lines.append(f"{p.name}\t{p.stat().st_size}\t{p}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("")
    print("Artifacts:")
    for p in artifacts:
        if p.is_file():
            print(f"  {p}  ({p.stat().st_size:,} bytes)")
    print(f"Manifest: {manifest}")
    if host != "macos":
        print("Note: .dmg requires macOS — see scripts/packaging/build_macos_dmg.sh and CI.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
