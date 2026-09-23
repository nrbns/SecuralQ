"""Every in-repo checklist is engineering-complete (ops leftovers honest)."""

from __future__ import annotations

from pathlib import Path

from tests._http_test_utils import configure_isolated_settings


def test_all_checklists_board(tmp_path, monkeypatch):
    configure_isolated_settings(monkeypatch, tmp_path)
    from app.checklist_board import all_checklists_board
    from app.db import init_schema
    from app.tenancy import ensure_tenant_schema

    init_schema()
    ensure_tenant_schema()
    board = all_checklists_board()
    assert board["ok"] is True
    assert board["all_complete"] is True
    ids = {c["id"] for c in board["checklists"]}
    assert ids == {"master", "world_class", "priority", "closed_beta"}
    for c in board["checklists"]:
        assert c["complete"] is True, c
        assert c["engineering_complete"] is True
        assert (Path(__file__).resolve().parents[1] / c["doc"]).is_file()


def test_checklist_docs_exist():
    root = Path(__file__).resolve().parents[1]
    for rel in (
        "docs/MASTER-CHECKLIST.md",
        "docs/WORLD-CLASS-CHECKLIST.md",
        "docs/priority-checklist.md",
        "docs/closed-beta-checklist.md",
    ):
        assert (root / rel).is_file()
