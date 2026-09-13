from __future__ import annotations

from .runtime import get_simulator


def get_asset(destination_ip: str) -> dict:
    return get_simulator().get_asset(destination_ip)
