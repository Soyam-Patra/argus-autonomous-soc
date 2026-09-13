from __future__ import annotations

from .schemas import AgentDecision, ContainmentStatus, DecisionType, ToolName
from .state import InvestigationState


class PolicyGuardError(ValueError):
    pass


class PolicyGuard:
    """Deterministic guard for state-changing simulated actions."""

    def validate(self, decision: AgentDecision, state: InvestigationState) -> None:
        if DecisionType(decision.decision) != DecisionType.RESPOND:
            return
        if decision.tool not in {ToolName.FIREWALL_BLOCK_IP, ToolName.QUARANTINE_HOST, "firewall_block_ip", "quarantine_host"}:
            raise PolicyGuardError(f"Unsupported response tool: {decision.tool}")
        if state.hypothesis.confidence < 0.7:
            raise PolicyGuardError("Response denied: confidence is below policy threshold.")
        if state.hypothesis.outcome.value != "SUCCESS":
            raise PolicyGuardError("Response denied: compromise is not confirmed.")
        if decision.tool in {ToolName.FIREWALL_BLOCK_IP, "firewall_block_ip"}:
            target = str(decision.arguments.get("ip", ""))
            if self._denied(state, "block_ip", target):
                raise PolicyGuardError("Response denied: human override denied this source block.")
        if decision.tool in {ToolName.QUARANTINE_HOST, "quarantine_host"}:
            target = str(decision.arguments.get("asset_id", ""))
            if self._denied(state, "quarantine_host", target):
                raise PolicyGuardError("Response denied: human override denied this quarantine.")
            if not state.actions_taken:
                raise PolicyGuardError("Response denied: quarantine is reserved for later containment escalation.")
            if state.containment_status != ContainmentStatus.FAILED or not state.active_threat:
                raise PolicyGuardError("Response denied: quarantine requires failed containment with active threat.")

    def _denied(self, state: InvestigationState, action: str, target: str) -> bool:
        return any(
            item.get("decision") == "DENY" and item.get("action") == action and item.get("target") == target
            for item in state.denied_actions
        )

