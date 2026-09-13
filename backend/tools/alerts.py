from __future__ import annotations

from .runtime import get_simulator


def get_alert(alert_id: str) -> dict:
    return get_simulator().get_alert(alert_id)
