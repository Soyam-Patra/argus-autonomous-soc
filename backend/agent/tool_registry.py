from __future__ import annotations

from collections.abc import Callable
from typing import Any

from backend.tools import alerts, assets, firewall, logs, network, verification, vulnerabilities

from .schemas import ToolName, ToolSpec


TOOL_SPECS: dict[ToolName, ToolSpec] = {
    ToolName.GET_ALERT: ToolSpec(
        name=ToolName.GET_ALERT,
        description="Retrieve the original NIDS alert by ID.",
        required_arguments=["alert_id"],
    ),
    ToolName.GET_NETWORK_EVIDENCE: ToolSpec(
        name=ToolName.GET_NETWORK_EVIDENCE,
        description="Retrieve network metadata for host/source relationships.",
        required_arguments=["host"],
    ),
    ToolName.GET_ASSET: ToolSpec(
        name=ToolName.GET_ASSET,
        description="Retrieve destination asset inventory and exposure context.",
        required_arguments=["destination_ip"],
    ),
    ToolName.GET_VULNERABILITIES: ToolSpec(
        name=ToolName.GET_VULNERABILITIES,
        description="Retrieve synthetic vulnerability context for an asset.",
        required_arguments=["asset_id"],
    ),
    ToolName.SEARCH_SERVER_LOGS: ToolSpec(
        name=ToolName.SEARCH_SERVER_LOGS,
        description="Search bounded synthetic server logs for impact evidence.",
        required_arguments=["host"],
    ),
    ToolName.GET_FIREWALL_STATE: ToolSpec(
        name=ToolName.GET_FIREWALL_STATE,
        description="Read simulated firewall state.",
    ),
    ToolName.FIREWALL_BLOCK_IP: ToolSpec(
        name=ToolName.FIREWALL_BLOCK_IP,
        description="Apply a simulated source IP block.",
        state_changing=True,
        required_arguments=["ip"],
    ),
    ToolName.QUARANTINE_HOST: ToolSpec(
        name=ToolName.QUARANTINE_HOST,
        description="Apply simulated host quarantine.",
        state_changing=True,
        required_arguments=["asset_id"],
    ),
    ToolName.VERIFY_ENVIRONMENT: ToolSpec(
        name=ToolName.VERIFY_ENVIRONMENT,
        description="Verify post-response synthetic environment state.",
    ),
}

_TOOL_FUNCTIONS: dict[ToolName, Callable[..., Any]] = {
    ToolName.GET_ALERT: alerts.get_alert,
    ToolName.GET_NETWORK_EVIDENCE: network.get_network_evidence,
    ToolName.GET_ASSET: assets.get_asset,
    ToolName.GET_VULNERABILITIES: vulnerabilities.get_vulnerabilities,
    ToolName.SEARCH_SERVER_LOGS: logs.search_server_logs,
    ToolName.GET_FIREWALL_STATE: firewall.get_firewall_state,
    ToolName.FIREWALL_BLOCK_IP: firewall.firewall_block_ip,
    ToolName.QUARANTINE_HOST: firewall.quarantine_host,
    ToolName.VERIFY_ENVIRONMENT: verification.verify_environment,
}

_EVIDENCE_KIND_BY_TOOL: dict[ToolName, str] = {
    ToolName.GET_ALERT: "alert",
    ToolName.GET_NETWORK_EVIDENCE: "network",
    ToolName.GET_ASSET: "asset",
    ToolName.GET_VULNERABILITIES: "vulnerabilities",
    ToolName.SEARCH_SERVER_LOGS: "server_logs",
    ToolName.GET_FIREWALL_STATE: "firewall",
    ToolName.FIREWALL_BLOCK_IP: "response",
    ToolName.QUARANTINE_HOST: "response",
    ToolName.VERIFY_ENVIRONMENT: "verification",
}


def available_tools() -> list[ToolSpec]:
    return list(TOOL_SPECS.values())


def execute_tool(tool: ToolName | str, arguments: dict[str, Any]) -> tuple[str, Any]:
    tool_name = ToolName(tool)
    spec = TOOL_SPECS[tool_name]
    missing = [name for name in spec.required_arguments if name not in arguments or arguments[name] in (None, "")]
    if missing:
        raise ValueError(f"Missing required arguments for {tool_name.value}: {', '.join(missing)}")
    result = _TOOL_FUNCTIONS[tool_name](**arguments)
    return _EVIDENCE_KIND_BY_TOOL[tool_name], result
