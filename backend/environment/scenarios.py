from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import json
from typing import Any


DATA_DIR = Path(__file__).resolve().parents[2] / "data"


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    name: str
    incident_id: str
    alert_id: str
    expected_outcome: str
    description: str
    mutable_environment: dict[str, Any]


def _load_json(name: str) -> Any:
    with (DATA_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_scenarios() -> dict[str, Scenario]:
    raw = _load_json("scenarios.json")
    return {
        item["scenario_id"]: Scenario(
            scenario_id=item["scenario_id"],
            name=item["name"],
            incident_id=item["incident_id"],
            alert_id=item["alert_id"],
            expected_outcome=item["expected_outcome"],
            description=item["description"],
            mutable_environment=deepcopy(item["mutable_environment"]),
        )
        for item in raw
    }


def load_seed_data() -> dict[str, Any]:
    return {
        "alerts": _load_json("alerts.json"),
        "assets": _load_json("assets.json"),
        "vulnerabilities": _load_json("vulnerabilities.json"),
        "network_events": _load_json("network_events.json"),
        "server_logs": _load_json("server_logs.json"),
    }
