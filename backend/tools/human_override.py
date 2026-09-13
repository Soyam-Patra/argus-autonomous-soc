from __future__ import annotations

_ALLOWED = {"APPROVE", "DENY"}


def human_override(decision: str, action: str, reason: str | None = None) -> dict:
    normalized = decision.upper()
    if normalized not in _ALLOWED:
        raise ValueError(f"decision must be one of {_ALLOWED}")
    return {
        "decision": normalized,
        "action": action,
        "reason": reason,
        "simulated": True,
        "status": "recorded",
    }
