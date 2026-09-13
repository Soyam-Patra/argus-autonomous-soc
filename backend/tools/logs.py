from __future__ import annotations

from .runtime import get_simulator


def search_server_logs(host: str, source_ip: str | None = None, time_range: str | None = None, query: str | None = None) -> list[dict]:
    return get_simulator().search_server_logs(host=host, source_ip=source_ip, time_range=time_range, query=query)
