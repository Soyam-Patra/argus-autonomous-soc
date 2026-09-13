from __future__ import annotations

from .runtime import get_simulator


def verify_environment() -> dict:
    return get_simulator().verify_environment()
