from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class HypothesisOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNKNOWN = "UNKNOWN"


class DecisionType(str, Enum):
    GATHER_EVIDENCE = "GATHER_EVIDENCE"
    ASSESS = "ASSESS"
    RESPOND = "RESPOND"
    VERIFY = "VERIFY"
    CLOSE = "CLOSE"


class ToolName(str, Enum):
    GET_ALERT = "get_alert"
    GET_NETWORK_EVIDENCE = "get_network_evidence"
    GET_ASSET = "get_asset"
    GET_VULNERABILITIES = "get_vulnerabilities"
    SEARCH_SERVER_LOGS = "search_server_logs"
    GET_FIREWALL_STATE = "get_firewall_state"
    FIREWALL_BLOCK_IP = "firewall_block_ip"
    QUARANTINE_HOST = "quarantine_host"
    VERIFY_ENVIRONMENT = "verify_environment"


class Hypothesis(BaseModel):
    outcome: HypothesisOutcome = HypothesisOutcome.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: str = "Investigation has not gathered enough evidence yet."


class AgentDecision(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    decision: DecisionType
    tool: ToolName | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    assessment: HypothesisOutcome | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rationale: str
    evidence_used: list[str] = Field(default_factory=list)


class ToolSpec(BaseModel):
    name: ToolName
    description: str
    state_changing: bool = False
    required_arguments: list[str] = Field(default_factory=list)


EvidenceKind = Literal[
    "alert",
    "network",
    "asset",
    "vulnerabilities",
    "server_logs",
    "firewall",
    "response",
    "verification",
]
