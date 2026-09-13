from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from .scenarios import Scenario, load_scenarios, load_seed_data


class SimulatorError(ValueError):
    """Raised when a simulated tool receives invalid input."""


class ArgusSimulator:
    """Stateful deterministic environment for bounded ARGUS tool calls."""

    def __init__(self, scenario_id: str = "scenario-003") -> None:
        self.seed = load_seed_data()
        self.scenarios = load_scenarios()
        self.tool_log: list[dict[str, Any]] = []
        self.reset(scenario_id)

    def reset(self, scenario_id: str | None = None) -> dict[str, Any]:
        if scenario_id is not None:
            if scenario_id not in self.scenarios:
                raise SimulatorError(f"Unknown scenario: {scenario_id}")
            self.scenario_id = scenario_id
        scenario = self.scenarios[self.scenario_id]
        self.scenario: Scenario = scenario
        self.environment = deepcopy(scenario.mutable_environment)
        self.firewall = {
            "blocked_ips": [],
            "quarantined_assets": [],
            "recent_actions": [],
        }
        self.tool_log = []
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "incident_id": self.scenario.incident_id,
            "alert_id": self.scenario.alert_id,
            "environment": deepcopy(self.environment),
            "firewall": deepcopy(self.firewall),
            "tool_calls": deepcopy(self.tool_log),
        }

    def _record(self, tool: str, arguments: dict[str, Any], result: Any) -> Any:
        self.tool_log.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tool": tool,
                "arguments": deepcopy(arguments),
                "result": deepcopy(result),
            }
        )
        return result

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        alert = next((item for item in self.seed["alerts"] if item["alert_id"] == alert_id), None)
        if not alert:
            raise SimulatorError(f"Unknown alert: {alert_id}")
        return self._record("get_alert", {"alert_id": alert_id}, deepcopy(alert))

    def get_network_evidence(self, host: str, source_ip: str | None = None, time_window: str | None = None) -> list[dict[str, Any]]:
        results = []
        active_sources = set(self.environment.get("active_malicious_sources", []))
        for event in self.seed["network_events"]:
            if event["dest_ip"] != host:
                continue
            if source_ip and event["src_ip"] != source_ip:
                continue
            event_copy = deepcopy(event)
            if event_copy["src_ip"] in active_sources:
                event_copy["currently_active"] = True
            results.append(event_copy)
        return self._record(
            "get_network_evidence",
            {"host": host, "source_ip": source_ip, "time_window": time_window},
            results,
        )

    def get_asset(self, destination_ip: str) -> dict[str, Any]:
        asset = next((item for item in self.seed["assets"] if item["ip"] == destination_ip or item["asset_id"] == destination_ip), None)
        if not asset:
            raise SimulatorError(f"Unknown asset: {destination_ip}")
        return self._record("get_asset", {"destination_ip": destination_ip}, deepcopy(asset))

    def get_vulnerabilities(self, asset_id: str) -> list[dict[str, Any]]:
        results = [deepcopy(item) for item in self.seed["vulnerabilities"] if item["asset_id"] == asset_id]
        return self._record("get_vulnerabilities", {"asset_id": asset_id}, results)

    def search_server_logs(
        self,
        host: str,
        source_ip: str | None = None,
        time_range: str | None = None,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        query_text = query.lower() if query else None
        results = []
        for item in self.seed["server_logs"]:
            if item["host"] != host:
                continue
            if source_ip and item.get("src_ip") != source_ip:
                continue
            haystack = json_dumps_lower(item)
            if query_text and query_text not in haystack:
                continue
            results.append(deepcopy(item))
        return self._record(
            "search_server_logs",
            {"host": host, "source_ip": source_ip, "time_range": time_range, "query": query},
            results,
        )

    def get_firewall_state(self) -> dict[str, Any]:
        return self._record("get_firewall_state", {}, deepcopy(self.firewall))

    def firewall_block_ip(self, ip: str) -> dict[str, Any]:
        if not ip or not isinstance(ip, str):
            raise SimulatorError("A valid IP string is required")
        if ip not in self.firewall["blocked_ips"]:
            self.firewall["blocked_ips"].append(ip)
        action = {"action": "block_ip", "ip": ip, "simulated": True, "status": "applied"}
        self.firewall["recent_actions"].append(action)

        rotation = self.environment.get("source_rotation")
        if rotation and rotation.get("trigger") == "block_ip" and ip == rotation.get("from") and not rotation.get("used"):
            self.environment["active_malicious_sources"] = [rotation["to"]]
            self.environment["malicious_traffic_active"] = True
            rotation["used"] = True
            action["side_effect"] = "attacker_source_rotated"
            action["new_source"] = rotation["to"]
        elif ip in self.environment.get("active_malicious_sources", []):
            self.environment["active_malicious_sources"] = [
                source for source in self.environment["active_malicious_sources"] if source != ip
            ]
            self.environment["malicious_traffic_active"] = bool(self.environment["active_malicious_sources"])
        return self._record("firewall_block_ip", {"ip": ip}, action)

    def quarantine_host(self, asset_id: str) -> dict[str, Any]:
        if not asset_id or not isinstance(asset_id, str):
            raise SimulatorError("A valid asset ID is required")
        if asset_id not in self.firewall["quarantined_assets"]:
            self.firewall["quarantined_assets"].append(asset_id)
        self.environment["host_isolated"] = True
        self.environment["malicious_traffic_active"] = False
        self.environment["active_malicious_sources"] = []
        action = {"action": "quarantine_host", "asset_id": asset_id, "simulated": True, "status": "applied"}
        self.firewall["recent_actions"].append(action)
        return self._record("quarantine_host", {"asset_id": asset_id}, action)

    def verify_environment(self) -> dict[str, Any]:
        active_sources = self.environment.get("active_malicious_sources", [])
        blocked = set(self.firewall["blocked_ips"])
        unblocked_active = [source for source in active_sources if source not in blocked]
        malicious_traffic = bool(self.environment.get("malicious_traffic_active") and unblocked_active)
        rotation = self.environment.get("source_rotation") or {}
        result = {
            "malicious_traffic": malicious_traffic,
            "exploit_attempts": len(unblocked_active) if malicious_traffic else 0,
            "new_connections": len(unblocked_active) if malicious_traffic else 0,
            "alternate_source_detected": bool(rotation.get("used")),
            "active_sources": deepcopy(unblocked_active),
            "blocked_ips": deepcopy(self.firewall["blocked_ips"]),
            "host_isolated": bool(self.environment.get("host_isolated", False)),
            "verification_status": "failed" if malicious_traffic else "passed",
        }
        return self._record("verify_environment", {}, result)


def json_dumps_lower(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True).lower()

