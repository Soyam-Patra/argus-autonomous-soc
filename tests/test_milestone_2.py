from __future__ import annotations

import unittest

from backend.agent.orchestrator import InvestigationOrchestrator
from backend.agent.planner import DeterministicFallbackPlanner
from backend.agent.schemas import DecisionType, ToolName
from backend.agent.state import InvestigationState
from backend.agent.tool_registry import available_tools
from backend.tools.runtime import reset_simulator


class MilestoneTwoAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_simulator("scenario-003")
        self.planner = DeterministicFallbackPlanner()
        self.tools = available_tools()
        self.environment = {}

    def test_empty_state_chooses_alert_lookup(self) -> None:
        state = InvestigationState(incident_id="INC-1042", alert_id="ALERT-1042")

        decision = self.planner.decide(state, self.tools, self.environment)

        self.assertEqual(decision.decision, DecisionType.GATHER_EVIDENCE)
        self.assertEqual(decision.tool, ToolName.GET_ALERT)
        self.assertEqual(decision.arguments, {"alert_id": "ALERT-1042"})

    def test_alert_only_state_chooses_asset_lookup(self) -> None:
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

        decision = self.planner.decide(state, self.tools, self.environment)

        self.assertEqual(decision.tool, ToolName.GET_ASSET)
        self.assertEqual(decision.arguments, {"destination_ip": "10.0.1.25"})

    def test_network_missing_state_chooses_network_before_vulnerability(self) -> None:
        state = self._state_with_alert_and_asset()

        decision = self.planner.decide(state, self.tools, self.environment)

        self.assertEqual(decision.tool, ToolName.GET_NETWORK_EVIDENCE)
        self.assertEqual(decision.arguments["host"], "10.0.1.25")

    def test_vulnerability_present_but_impact_unknown_chooses_server_logs(self) -> None:
        state = self._state_with_alert_and_asset()
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
            [
                {
                    "asset_id": "asset-payments-api",
                    "patched": False,
                    "exploit_available": True,
                }
            ],
        )

        decision = self.planner.decide(state, self.tools, self.environment)

        self.assertEqual(decision.tool, ToolName.SEARCH_SERVER_LOGS)
        self.assertIn("impact evidence", decision.rationale)

    def test_false_positive_evidence_closes_failed_without_response(self) -> None:
        state = InvestigationState(incident_id="INC-2041", alert_id="ALERT-2041")
        state.add_evidence(
            "alert",
            {
                "alert_id": "ALERT-2041",
                "incident_id": "INC-2041",
                "src_ip": "203.0.113.55",
                "dest_ip": "10.0.2.40",
            },
        )
        state.add_evidence("asset", {"asset_id": "asset-portal", "hostname": "employee-portal", "ip": "10.0.2.40"})
        state.add_evidence("network", [{"classification": "blocked_probe"}])
        state.add_evidence("vulnerabilities", [{"asset_id": "asset-portal", "patched": True, "exploit_available": False}])
        state.add_evidence(
            "server_logs",
            [
                {"event_type": "waf_event", "outcome": "blocked"},
                {"event_type": "auth_event", "outcome": "benign"},
            ],
        )

        decision = self.planner.decide(state, self.tools, self.environment)

        self.assertEqual(decision.decision, DecisionType.CLOSE)
        self.assertEqual(decision.assessment, "FAILED")
        self.assertIsNone(decision.tool)

    def test_orchestrator_runs_terminal_investigation_to_close(self) -> None:
        state = InvestigationOrchestrator().run("scenario-001")

        self.assertTrue(state.complete)
        self.assertEqual(state.final_assessment["verdict"], "SUCCESS")
        self.assertTrue(any(event.event_type == "DECISION" for event in state.events))
        self.assertTrue(any(event.tool == "firewall_block_ip" for event in state.events))
        self.assertTrue(any(event.tool == "verify_environment" for event in state.events))

    def _state_with_alert_and_asset(self) -> InvestigationState:
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
        state.add_evidence("asset", {"asset_id": "asset-payments-api", "hostname": "payments-api", "ip": "10.0.1.25"})
        return state


if __name__ == "__main__":
    unittest.main()
