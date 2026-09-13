from __future__ import annotations

from .runtime import get_simulator


def get_network_evidence(host: str, source_ip: str | None = None, time_window: str | None = None) -> list[dict]:
    return get_simulator().get_network_evidence(host=host, source_ip=source_ip, time_window=time_window)
