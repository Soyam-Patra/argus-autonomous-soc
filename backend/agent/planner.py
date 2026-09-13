from __future__ import annotations

import json
import os
from typing import Protocol

from .schemas import AgentDecision, ContainmentStatus, DecisionType, HypothesisOutcome, ToolName, ToolSpec
from .state import InvestigationState


class AgentPlanner(Protocol):
    def decide(self, state: InvestigationState, available_tools: list[ToolSpec], environment_state: dict) -> AgentDecision:
        ...


class LLMStructuredPlanner:
    """Optional planner hook for a structured-output LLM provider.

    Milestone 2 keeps this boundary explicit and safe. The planner receives only
    structured investigation state and an allowlisted tool catalog. It is disabled
    unless ARGUS_ENABLE_LLM=1 and a future provider implementation is configured.
    """

    def __init__(self) -> None:
        self.enabled = os.getenv("ARGUS_ENABLE_LLM") == "1"

    def decide(self, state: InvestigationState, available_tools: list[ToolSpec], environment_state: dict) -> AgentDecision:
        if not self.enabled:
            raise RuntimeError("LLM planner is disabled; using deterministic fallback planner.")
        raise RuntimeError("LLM planner provider is not configured in Milestone 2.")

    def _build_prompt_payload(self, state: InvestigationState, available_tools: list[ToolSpec], environment_state: dict) -> str:
        payload = {
            "state": state.model_dump(mode="json"),
            "available_tools": [tool.model_dump(mode="json") for tool in available_tools],
            "environment_state": environment_state,
            "decision_schema": AgentDecision.model_json_schema(),
        }
        return json.dumps(payload, sort_keys=True)


class DeterministicFallbackPlanner:
    """Evidence-driven fallback planner separated from the LLM planner boundary."""

    def decide(self, state: InvestigationState, available_tools: list[ToolSpec], environment_state: dict) -> AgentDecision:
        tool_names = {tool.name for tool in available_tools}
        alert = state.evidence.alert
        asset = state.evidence.asset

        if not alert:
            return AgentDecision(
                decision=DecisionType.GATHER_EVIDENCE,
                tool=ToolName.GET_ALERT,
                arguments={"alert_id": state.alert_id},
                rationale="Alert details are required before any conclusion or response is justified.",
                confidence=0.1,
            )

        if not asset and ToolName.GET_ASSET in tool_names:
            return AgentDecision(
                decision=DecisionType.GATHER_EVIDENCE,
                tool=ToolName.GET_ASSET,
                arguments={"destination_ip": alert["dest_ip"]},
                rationale="The destination asset context is unknown, so exposure and ownership must be checked next.",
                confidence=0.28,
                evidence_used=["alert"],
            )

        if not state.evidence.network and ToolName.GET_NETWORK_EVIDENCE in tool_names:
            return AgentDecision(
                decision=DecisionType.GATHER_EVIDENCE,
                tool=ToolName.GET_NETWORK_EVIDENCE,
                arguments={"host": alert["dest_ip"], "source_ip": alert["src_ip"]},
                rationale="Network evidence is needed to determine whether the alert corresponds to observed traffic.",
                confidence=0.35,
                evidence_used=["alert", "asset"] if asset else ["alert"],
            )

        if asset and not state.evidence.vulnerabilities and ToolName.GET_VULNERABILITIES in tool_names:
            return AgentDecision(
                decision=DecisionType.GATHER_EVIDENCE,
                tool=ToolName.GET_VULNERABILITIES,
                arguments={"asset_id": asset["asset_id"]},
                rationale="The observed traffic is suspicious, but target vulnerability must be established before assessment.",
                confidence=0.45,
                evidence_used=["alert", "network"],
            )

        if asset and not state.evidence.server_logs and ToolName.SEARCH_SERVER_LOGS in tool_names:
            return AgentDecision(
                decision=DecisionType.GATHER_EVIDENCE,
                tool=ToolName.SEARCH_SERVER_LOGS,
                arguments={"host": asset["hostname"], "source_ip": alert["src_ip"]},
                rationale="Exploitability alone is insufficient; server-side impact evidence is needed.",
                confidence=0.58,
                evidence_used=["alert", "asset", "vulnerabilities", "network"],
            )

        state.recalculate_hypothesis()
        if state.hypothesis.outcome == HypothesisOutcome.SUCCESS:
            if state.has_unverified_response() and ToolName.VERIFY_ENVIRONMENT in tool_names:
                return AgentDecision(
                    decision=DecisionType.VERIFY,
                    tool=ToolName.VERIFY_ENVIRONMENT,
                    arguments={},
                    rationale="A simulated response was applied, so the environment must be checked before declaring containment.",
                    confidence=state.hypothesis.confidence,
                    evidence_used=["response"],
                )

            latest_verification = state.latest_verification()
            if state.containment_status == ContainmentStatus.FAILED and latest_verification:
                active_sources = latest_verification.get("active_sources", [])
                uninspected_sources = [
                    source for source in active_sources if not state.has_network_evidence_for_source(source)
                ]
                if uninspected_sources and ToolName.GET_NETWORK_EVIDENCE in tool_names:
                    return AgentDecision(
                        decision=DecisionType.GATHER_EVIDENCE,
                        tool=ToolName.GET_NETWORK_EVIDENCE,
                        arguments={"host": alert["dest_ip"], "source_ip": uninspected_sources[0]},
                        rationale="Verification found continued malicious traffic from a source not yet inspected in the investigation evidence.",
                        confidence=state.hypothesis.confidence,
                        evidence_used=["verification", "environment"],
                    )

                if (
                    state.active_threat
                    and asset
                    and self._action_taken(state, "block_ip")
                    and not self._action_taken(state, "quarantine_host")
                    and not self._response_denied(state, "quarantine_host", asset["asset_id"])
                    and ToolName.QUARANTINE_HOST in tool_names
                ):
                    return AgentDecision(
                        decision=DecisionType.RESPOND,
                        tool=ToolName.QUARANTINE_HOST,
                        arguments={"asset_id": asset["asset_id"]},
                        rationale="Current verification and network evidence show the source-IP block did not contain active malicious traffic, so a different bounded response is required.",
                        confidence=state.hypothesis.confidence,
                        evidence_used=["verification", "network", "response"],
                    )

            if (
                not state.actions_taken
                and not self._response_denied(state, "block_ip", alert["src_ip"])
                and ToolName.FIREWALL_BLOCK_IP in tool_names
            ):
                return AgentDecision(
                    decision=DecisionType.RESPOND,
                    tool=ToolName.FIREWALL_BLOCK_IP,
                    arguments={"ip": alert["src_ip"]},
                    rationale="Compromise is supported by execution evidence, so a bounded simulated source block is justified.",
                    confidence=state.hypothesis.confidence,
                    evidence_used=["vulnerabilities", "network", "server_logs"],
                )

        if state.hypothesis.outcome in {HypothesisOutcome.SUCCESS, HypothesisOutcome.FAILED, HypothesisOutcome.INCONCLUSIVE}:
            return AgentDecision(
                decision=DecisionType.CLOSE,
                assessment=state.hypothesis.outcome,
                confidence=state.hypothesis.confidence,
                rationale=state.hypothesis.rationale,
                evidence_used=self._available_evidence_labels(state),
            )

        return AgentDecision(
            decision=DecisionType.ASSESS,
            assessment=HypothesisOutcome.INCONCLUSIVE,
            confidence=state.hypothesis.confidence,
            rationale="No additional useful Milestone 2 evidence source remains, so the investigation is inconclusive.",
            evidence_used=self._available_evidence_labels(state),
        )

    def _available_evidence_labels(self, state: InvestigationState) -> list[str]:
        labels = []
        if state.evidence.alert:
            labels.append("alert")
        if state.evidence.asset:
            labels.append("asset")
        if state.evidence.network:
            labels.append("network")
        if state.evidence.vulnerabilities:
            labels.append("vulnerabilities")
        if state.evidence.server_logs:
            labels.append("server_logs")
        if state.evidence.response:
            labels.append("response")
        if state.evidence.verification:
            labels.append("verification")
        return labels

    def _action_taken(self, state: InvestigationState, action: str) -> bool:
        return any(item.get("action") == action for item in state.actions_taken)

    def _response_denied(self, state: InvestigationState, action: str, target: str) -> bool:
        return any(
            item.get("decision") == "DENY" and item.get("action") == action and item.get("target") == target
            for item in state.denied_actions
        )


class CompositePlanner:
    def __init__(self, primary: AgentPlanner | None = None, fallback: AgentPlanner | None = None) -> None:
        self.primary = primary or LLMStructuredPlanner()
        self.fallback = fallback or DeterministicFallbackPlanner()

    def decide(self, state: InvestigationState, available_tools: list[ToolSpec], environment_state: dict) -> AgentDecision:
        try:
            return self.primary.decide(state, available_tools, environment_state)
        except Exception:
            return self.fallback.decide(state, available_tools, environment_state)
