from __future__ import annotations

from .runtime import get_simulator


def get_vulnerabilities(asset_id: str) -> list[dict]:
    return get_simulator().get_vulnerabilities(asset_id)
