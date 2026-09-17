"""Product shell: system health + commercial roadmap docs."""

from pathlib import Path

from tests._http_test_utils import configure_isolated_settings


def test_system_health_payload(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.system_health_api import build_system_health

    out = build_system_health()
    assert out["ok"] is True
    assert "checks" in out
    assert "api" in out["checks"]
    assert "database" in out["checks"]
    assert "DISCOVER" in out["loop"]


def test_product_ui_shell_markers():
    root = Path(__file__).resolve().parents[1]
    html = (root / "static" / "index.html").read_text(encoding="utf-8")
    assert "What needs attention" in html
    assert "Live security timeline" in html
    assert 'data-workspace="system_health"' in html
    assert "Continuous Security Control Plane" in html
    assert (root / "docs" / "PRODUCT-ROADMAP.md").is_file()
