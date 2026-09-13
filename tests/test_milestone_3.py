from __future__ import annotations

import unittest

from backend.agent.orchestrator import InvestigationOrchestrator
from backend.agent.planner import DeterministicFallbackPlanner
from backend.agent.policy_guard import PolicyGuard, PolicyGuardError
from backend.agent.schemas import ContainmentStatus, DecisionType, ResponseStatus, ToolName
from backend.agent.state import InvestigationState
from backend.agent.tool_registry import available_tools
from backend.environment.simulator import ArgusSimulator
from backend.tools.runtime import reset_simulator


class MilestoneThreeAdaptationTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_simulator("scenario-003")
        self.planner = DeterministicFallbackPlanner()
        self.tools = available_tools()

    def test_successful_attack_can_still_have_failed_containment(self) -> None:
        state = self._confirmed_success_state()
        state.add_evidence("response", {"action": "block_ip", "ip": "185.22.91.14", "status": "applied"})
        state.add_evidence(
            "verification",
            {
                "verification_status": "failed",
                "malicious_traffic": True,
                "active_sources": ["185.22.91.17"],
            },
        )

        self.assertEqual(state.attack_outcome.value, "SUCCESS")
        self.assertGreaterEqual(state.attack_confidence, 0.7)
        self.assertEqual(state.response_status, ResponseStatus.APPLIED)
        self.assertEqual(state.containment_status, ContainmentStatus.FAILED)
        self.assertTrue(state.active_threat)

    def test_block_action_can_fail_and_rotation_is_observable(self) -> None:
        simulator = ArgusSimulator("scenario-003")
        block_result = simulator.firewall_block_ip("185.22.91.14")
        verification = simulator.verify_environment()

        self.assertEqual(block_result["side_effect"], "attacker_source_rotated")
        self.assertEqual(verification["verification_status"], "failed")
        self.assertTrue(verification["alternate_source_detected"])
        self.assertEqual(verification["active_sources"], ["185.22.91.17"])

    def test_planner_inspects_new_source_before_adaptive_response(self) -> None:
        state = self._failed_containment_state()

        decision = self.planner.decide(state, self.tools, {})

        self.assertEqual(decision.decision, DecisionType.GATHER_EVIDENCE)
        self.assertEqual(decision.tool, ToolName.GET_NETWORK_EVIDENCE)
        self.assertEqual(decision.arguments["source_ip"], "185.22.91.17")

    def test_agent_chooses_alternative_response_based_on_current_evidence(self) -> None:
        state = self._failed_containment_state()
        state.add_evidence(
            "network",
            [
                {
                    "event_id": "net-1002",
                    "src_ip": "185.22.91.17",
                    "dest_ip": "10.0.1.25",
                    "classification": "continued_exploit_after_rotation",
                }
            ],
        )

        decision = self.planner.decide(state, self.tools, {})

        self.assertEqual(decision.decision, DecisionType.RESPOND)
        self.assertEqual(decision.tool, ToolName.QUARANTINE_HOST)
        self.assertEqual(decision.arguments, {"asset_id": "asset-payments-api"})
        self.assertIn("different bounded response", decision.rationale)

    def test_quarantine_changes_state_and_final_verification_succeeds(self) -> None:
        simulator = ArgusSimulator("scenario-003")
        simulator.firewall_block_ip("185.22.91.14")
        failed = simulator.verify_environment()
        quarantine = simulator.quarantine_host("asset-payments-api")
        passed = simulator.verify_environment()

        self.assertEqual(failed["verification_status"], "failed")
        self.assertEqual(quarantine["status"], "applied")
        self.assertEqual(passed["verification_status"], "passed")
        self.assertTrue(passed["host_isolated"])
        self.assertFalse(passed["malicious_traffic"])

    def test_orchestrator_runs_full_adaptive_loop_to_containment_success(self) -> None:
        state = InvestigationOrchestrator().run("scenario-003", max_steps=16)
        event_types = [event.event_type for event in state.events]

        self.assertTrue(state.complete)
        self.assertEqual(state.final_assessment["attack_outcome"], "SUCCESS")
        self.assertEqual(state.final_assessment["response_status"], "APPLIED")
        self.assertEqual(state.final_assessment["containment_status"], "SUCCESS")
        self.assertFalse(state.final_assessment["active_threat"])
        self.assertIn("VERIFICATION_FAILED", event_types)
        self.assertIn("CONTAINMENT_FAILURE_DETECTED", event_types)
        self.assertIn("NEW_EVIDENCE_FOUND", event_types)
        self.assertIn("HYPOTHESIS_REVISED", event_types)
        self.assertIn("ADAPTIVE_RESPONSE_SELECTED", event_types)
        self.assertIn("RESPONSE_VERIFIED", event_types)
        self.assertTrue(any(action.get("action") == "block_ip" for action in state.actions_taken))
        self.assertTrue(any(action.get("action") == "quarantine_host" for action in state.actions_taken))

    def test_human_deny_prevents_corresponding_response_action(self) -> None:
        state = self._failed_containment_state()
        state.add_evidence(
            "network",
            [
                {
                    "src_ip": "185.22.91.17",
                    "dest_ip": "10.0.1.25",
                    "classification": "continued_exploit_after_rotation",
                }
            ],
        )
        state.record_human_override(
            action="quarantine_host",
            target="asset-payments-api",
            decision="DENY",
            reason="Analyst requested manual containment.",
        )

        decision = self.planner.decide(state, self.tools, {})

        self.assertNotEqual(decision.tool, ToolName.QUARANTINE_HOST)
        with self.assertRaises(PolicyGuardError):
            PolicyGuard().validate(
                decision.model_copy(
                    update={
                        "decision": DecisionType.RESPOND,
                        "tool": ToolName.QUARANTINE_HOST,
                        "arguments": {"asset_id": "asset-payments-api"},
                    }
                ),
                state,
            )

    def _confirmed_success_state(self) -> InvestigationState:
        state = InvestigationState(incident_id="INC-1042", alert_id="ALERT-1042")
        state.add_evidence(
            "alert",
            {
                "alert_id": "ALERT-1042",
                "incident_id": "INC-1042",
                "src_ip": "185.22.91.14",
                "dest_ip": "10.0.1.25",
            },
        )
        state.add_evidence(
            "asset",
            {"asset_id": "asset-payments-api", "hostname": "payments-api", "ip": "10.0.1.25"},
        )
        state.add_evidence(
            "network",
            [
                {
                    "event_id": "net-1001",
                    "src_ip": "185.22.91.14",
                    "dest_ip": "10.0.1.25",
                    "classification": "exploit_attempt",
                }
            ],
        )
        state.add_evidence(
            "vulnerabilities",
            [{"asset_id": "asset-payments-api", "patched": False, "exploit_available": True}],
        )
        state.add_evidence(
            "server_logs",
            [
                {"event_type": "process_creation", "outcome": "malicious"},
                {"event_type": "outbound_connection", "outcome": "malicious"},
            ],
        )
        return state

    def _failed_containment_state(self) -> InvestigationState:
        state = self._confirmed_success_state()
        state.add_evidence("response", {"action": "block_ip", "ip": "185.22.91.14", "status": "applied"})
        state.add_evidence(
            "verification",
            {
                "verification_status": "failed",
                "malicious_traffic": True,
                "active_sources": ["185.22.91.17"],
                "alternate_source_detected": True,
            },
        )
        return state


if __name__ == "__main__":
    unittest.main()
