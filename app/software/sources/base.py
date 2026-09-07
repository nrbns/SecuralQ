"""Inventory source adapters — each produces InstallationRecord rows."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.software.models import InstallationRecord


class InventorySource(ABC):
    key: str = "manual"
    label: str = "Manual"

    @abstractmethod
    def collect(self, user_id: str) -> list[InstallationRecord]:
        ...

    def health(self, user_id: str) -> dict[str, Any]:
        return {"key": self.key, "label": self.label, "configured": True, "healthy": True}


SOURCE_REGISTRY: dict[str, type[InventorySource]] = {}


def register_source(cls: type[InventorySource]) -> type[InventorySource]:
    SOURCE_REGISTRY[cls.key] = cls
    return cls


def all_sources() -> list[InventorySource]:
    from app.software.sources import (  # noqa: F401
        asset_legacy,
        openaudit,
        scan,
        securaiq_agent,
        wazuh,
        windows_control_panel,
    )

    return [SOURCE_REGISTRY[k]() for k in sorted(SOURCE_REGISTRY.keys())]
