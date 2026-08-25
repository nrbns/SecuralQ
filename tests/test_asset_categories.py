"""Asset inventory category normalization and inference."""

from app.asset_categories import (
    category_for_asset_row,
    category_label,
    infer_asset_category,
    inventory_breakdown,
    is_better_category,
    normalize_asset_category,
)


def test_normalize_aliases():
    assert normalize_asset_category("workstation") == "computer"
    assert normalize_asset_category("laptop") == "computer"
    assert normalize_asset_category("host") == "endpoint"
    assert normalize_asset_category("router") == "network"


def test_infer_windows_computer():
    assert infer_asset_category(ports=[135, 445, 3389]) == "computer"


def test_infer_linux_server():
    assert infer_asset_category(ports=[22, 443], http_server="nginx/1.24") == "server"


def test_infer_mobile_hostname():
    assert infer_asset_category(hostname="Johns-iPhone") == "mobile"


def test_infer_printer_ports():
    assert infer_asset_category(ports=[9100]) == "printer"


def test_is_better_category():
    assert is_better_category("computer", "endpoint")
    assert not is_better_category("endpoint", "computer")


def test_category_for_asset_row_from_notes():
    row = category_for_asset_row(
        {
            "name": "192.168.1.10",
            "asset_type": "host",
            "notes": '{"ip":"192.168.1.10","hostname":"win-pc","os":"Windows","services":[{"port":445}]}',
        }
    )
    assert row == "computer"


def test_inventory_breakdown():
    assets = [
        {"asset_type": "server", "name": "srv1"},
        {"asset_type": "computer", "name": "pc1"},
    ]
    bd = inventory_breakdown(assets)
    assert bd.get("server") == 1
    assert bd.get("computer") == 1


def test_category_label():
    assert category_label("mobile") == "Mobile"
