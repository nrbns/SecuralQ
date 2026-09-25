"""Low-storage cloud Docker package — AI in-container, leftover scripts gone."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def test_cloud_docker_package_files():
    assert (_ROOT / ".dockerignore").is_file()
    ignore = (_ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert ".venv" in ignore
    assert "securaiq-agent/target" in ignore
    assert (_ROOT / "Dockerfile.slim").is_file()
    slim = (_ROOT / "Dockerfile.slim").read_text(encoding="utf-8")
    assert "INSTALL_ZAP" not in slim
    assert "ollama" in slim.lower()
    assert (_ROOT / "docker-compose.cloud.yml").is_file()
    cloud = (_ROOT / "docker-compose.cloud.yml").read_text(encoding="utf-8")
    assert "ollama/ollama" in cloud
    assert "MODEL_BACKEND: \"ollama\"" in cloud
    assert "Dockerfile.slim" in cloud
    assert (_ROOT / "docs" / "ops" / "CLOUD-DOCKER.md").is_file()


def test_compose_has_docker_ai():
    main = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "ollama/ollama" in main
    assert "ollama-data:" in main
    cloud = (_ROOT / "docker-compose.cloud.yml").read_text(encoding="utf-8")
    assert "services:" in cloud
    assert "OLLAMA_BASE_URL: \"http://ollama:11434\"" in cloud


def test_unwanted_one_off_scripts_removed():
    leftovers = [
        "data/_fix_billing.py",
        "data/_p0_remaining.py",
        "data/_cc_ops_home.py",
        "data/_p0_evidence.py",
        "data/_fix_dg_upserts.py",
        "data/_move_plane.py",
        "data/_ux_polish.py",
        "data/_fix_mojibake.py",
        "data/_fix_mojibake2.py",
        "data/_ui_audit/audit_ui.py",
        "data/_capacity_extended.json",
        "data/_capacity_ladder.json",
        "data/_pdf_smoke.pdf",
        "data/_pdf_live_smoke.pdf",
        "data/_vuln_export_smoke.pdf",
        "data/exports/exec-local.pptx",
        "SecuraIQ_Scan_Report.html",
        "dump.rdb",
    ]
    for rel in leftovers:
        assert not (_ROOT / rel).exists(), rel
