from __future__ import annotations

from .runtime import get_simulator


def get_firewall_state() -> dict:
    return get_simulator().get_firewall_state()


def firewall_block_ip(ip: str) -> dict:
    return get_simulator().firewall_block_ip(ip)


def quarantine_host(asset_id: str) -> dict:
    return get_simulator().quarantine_host(asset_id)
