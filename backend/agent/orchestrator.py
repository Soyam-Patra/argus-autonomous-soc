from __future__ import annotations

from backend.tools.runtime import get_simulator, reset_simulator

from .planner import CompositePlanner
from .policy_guard import PolicyGuard
from .schemas import AgentDecision, DecisionType
from .state import InvestigationState
from .tool_registry import available_tools, execute_tool


class InvestigationOrchestrator:
    def __init__(self, planner: CompositePlanner | None = None, policy_guard: PolicyGuard | None = None) -> None:
        self.planner = planner or CompositePlanner()
        self.policy_guard = policy_guard or PolicyGuard()

    def run(self, scenario_id: str = "scenario-003", max_steps: int = 12) -> InvestigationState:
        simulator = reset_simulator(scenario_id)
        state = InvestigationState(incident_id=simulator.scenario.incident_id, alert_id=simulator.scenario.alert_id)
        state.add_event("START", "ALERT RECEIVED")

        for _ in range(max_steps):
            decision = self.planner.decide(state, available_tools(), simulator.snapshot())
            self._record_decision(state, decision)

            decision_type = DecisionType(decision.decision)
            if decision_type in {DecisionType.GATHER_EVIDENCE, DecisionType.RESPOND, DecisionType.VERIFY}:
                if decision_type == DecisionType.RESPOND:
                    self.policy_guard.validate(decision, state)
                    if decision.tool == "quarantine_host":
                        state.add_event(
                            "ADAPTIVE_RESPONSE_SELECTED",
                            "Adaptive response selected: quarantine affected host",
                            decision=decision.decision,
                            tool=str(decision.tool),
                            rationale=decision.rationale,
                            confidence=decision.confidence,
                        )
                if decision.tool is None:
                    raise ValueError("Tool decision did not include a tool name.")
                evidence_kind, result = execute_tool(decision.tool, decision.arguments)
                state.add_evidence(evidence_kind, result)
                if decision_type == DecisionType.RESPOND:
                    state.add_event(
                        "RESPONSE_ATTEMPTED",
                        f"Response attempted: {result.get('action')} {result.get('status')}",
                        decision=decision.decision,
                        tool=str(decision.tool),
                        rationale=decision.rationale,
                        confidence=decision.confidence,
                    )
                state.add_event(
                    "TOOL_RESULT",
                    f"{decision.tool} returned {self._summarize_result(result)}",
                    tool=str(decision.tool),
                )
                if decision_type == DecisionType.GATHER_EVIDENCE and state.containment_status.value == "FAILED":
                    state.add_event(
                        "NEW_EVIDENCE_FOUND",
                        f"New evidence found after containment failure: {self._summarize_result(result)}",
                        tool=str(decision.tool),
                        rationale=decision.rationale,
                        confidence=decision.confidence,
                    )
                if decision_type == DecisionType.VERIFY:
                    if result.get("verification_status") == "failed":
                        state.add_event(
                            "VERIFICATION_FAILED",
                            "Verification failed: malicious traffic is still active.",
                            tool=str(decision.tool),
                            confidence=decision.confidence,
                        )
                        state.add_event(
                            "CONTAINMENT_FAILURE_DETECTED",
                            "Containment failure detected: active threat remains after the response.",
                            tool=str(decision.tool),
                            confidence=decision.confidence,
                        )
                        state.add_event(
                            "HYPOTHESIS_REVISED",
                            "Attack outcome remains SUCCESS while containment status is FAILED.",
                            confidence=state.attack_confidence,
                        )
                    else:
                        state.add_event(
                            "RESPONSE_VERIFIED",
                            "Response verified: containment succeeded.",
                            tool=str(decision.tool),
                            confidence=decision.confidence,
                        )
                continue

            if decision_type == DecisionType.ASSESS:
                state.recalculate_hypothesis()
                state.add_event(
                    "ASSESSMENT",
                    f"Assessment: {state.hypothesis.outcome.value}",
                    decision=decision.decision,
                    rationale=decision.rationale,
                    confidence=state.hypothesis.confidence,
                )
                continue

            if decision_type == DecisionType.CLOSE:
                state.build_final_assessment()
                state.add_event(
                    "CLOSE",
                    f"Final assessment: {state.hypothesis.outcome.value}",
                    decision=decision.decision,
                    rationale=decision.rationale,
                    confidence=state.hypothesis.confidence,
                )
                break
        else:
            state.add_event("STOP", "Maximum step count reached before closure.")
        return state

    def _record_decision(self, state: InvestigationState, decision: AgentDecision) -> None:
        state.add_event(
            "DECISION",
            self._decision_message(decision),
            decision=decision.decision,
            tool=str(decision.tool) if decision.tool else None,
            rationale=decision.rationale,
            confidence=decision.confidence,
        )

    def _decision_message(self, decision: AgentDecision) -> str:
        if decision.tool:
            return f"Decision: {decision.decision} via {decision.tool}"
        if decision.assessment:
            return f"Assessment decision: {decision.assessment}"
        return f"Decision: {decision.decision}"

    def _summarize_result(self, result: object) -> str:
        if isinstance(result, list):
            return f"{len(result)} record(s)"
        if isinstance(result, dict):
            if "verification_status" in result:
                return f"verification {result['verification_status']}"
            if "action" in result:
                return f"action {result['action']} {result.get('status', '')}".strip()
            if "alert_id" in result:
                return result["alert_id"]
            if "hostname" in result:
                return result["hostname"]
        return "result"


def run_terminal_demo(scenario_id: str = "scenario-003") -> InvestigationState:
    orchestrator = InvestigationOrchestrator()
    return orchestrator.run(scenario_id=scenario_id)


