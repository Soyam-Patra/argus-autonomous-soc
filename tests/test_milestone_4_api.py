from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from backend.api.app import app
from backend.api import routes


class MilestoneFourApiTests(unittest.TestCase):
    def setUp(self) -> None:
        routes._investigations.clear()
        self.client = TestClient(app)

    def test_health_succeeds(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "service": "argus"})

    def test_scenarios_returns_available_scenarios(self) -> None:
        response = self.client.get("/scenarios")

        self.assertEqual(response.status_code, 200)
        scenario_ids = {item["scenario_id"] for item in response.json()}
        self.assertIn("scenario-003", scenario_ids)

    def test_post_investigations_starts_primary_scenario(self) -> None:
        response = self.client.post("/investigations", json={"scenario_id": "scenario-003"})

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["incident_id"], "INC-1042")
        self.assertEqual(body["scenario_id"], "scenario-003")
        self.assertEqual(body["summary"]["attack_outcome"], "SUCCESS")
        self.assertEqual(body["summary"]["containment_status"], "SUCCESS")

    def test_get_investigation_returns_structured_state(self) -> None:
        create_response = self.client.post("/investigations", json={"scenario_id": "scenario-003"})
        incident_id = create_response.json()["incident_id"]

        response = self.client.get(f"/investigations/{incident_id}")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["incident_id"], "INC-1042")
        self.assertEqual(body["alert_id"], "ALERT-1042")
        self.assertIn("evidence", body)
        self.assertIn("events", body)
        self.assertEqual(body["attack_outcome"], "SUCCESS")
        self.assertEqual(body["response_status"], "APPLIED")
        self.assertEqual(body["containment_status"], "SUCCESS")
        self.assertFalse(body["active_threat"])

    def test_events_endpoint_returns_adaptive_trace(self) -> None:
        create_response = self.client.post("/investigations", json={"scenario_id": "scenario-003"})
        incident_id = create_response.json()["incident_id"]

        response = self.client.get(f"/investigations/{incident_id}/events")

        self.assertEqual(response.status_code, 200)
        event_types = [event["event_type"] for event in response.json()]
        self.assertIn("RESPONSE_ATTEMPTED", event_types)
        self.assertIn("VERIFICATION_FAILED", event_types)
        self.assertIn("CONTAINMENT_FAILURE_DETECTED", event_types)
        self.assertIn("NEW_EVIDENCE_FOUND", event_types)
        self.assertIn("HYPOTHESIS_REVISED", event_types)
        self.assertIn("ADAPTIVE_RESPONSE_SELECTED", event_types)
        self.assertIn("RESPONSE_VERIFIED", event_types)

    def test_evidence_endpoint_returns_collected_evidence(self) -> None:
        create_response = self.client.post("/investigations", json={"scenario_id": "scenario-003"})
        incident_id = create_response.json()["incident_id"]

        response = self.client.get(f"/investigations/{incident_id}/evidence")

        self.assertEqual(response.status_code, 200)
        evidence = response.json()
        self.assertEqual(evidence["alert"]["alert_id"], "ALERT-1042")
        self.assertEqual(evidence["asset"]["hostname"], "payments-api")
        self.assertGreaterEqual(len(evidence["network"]), 2)
        self.assertGreaterEqual(len(evidence["server_logs"]), 3)

    def test_unknown_investigation_returns_404(self) -> None:
        response = self.client.get("/investigations/INC-MISSING")

        self.assertEqual(response.status_code, 404)
        self.assertIn("Unknown investigation", response.json()["detail"])

    def test_unknown_scenario_returns_404(self) -> None:
        response = self.client.post("/investigations", json={"scenario_id": "scenario-missing"})

        self.assertEqual(response.status_code, 404)
        self.assertIn("Unknown scenario", response.json()["detail"])

    def test_invalid_human_override_returns_422(self) -> None:
        create_response = self.client.post("/investigations", json={"scenario_id": "scenario-003", "max_steps": 7})
        incident_id = create_response.json()["incident_id"]

        response = self.client.post(
            f"/investigations/{incident_id}/override",
            json={"action": "quarantine_host", "target": "asset-payments-api", "decision": "MAYBE"},
        )

        self.assertEqual(response.status_code, 422)

    def test_human_deny_override_prevents_denied_response_action(self) -> None:
        create_response = self.client.post("/investigations", json={"scenario_id": "scenario-003", "max_steps": 7})
        incident_id = create_response.json()["incident_id"]

        override_response = self.client.post(
            f"/investigations/{incident_id}/override",
            json={
                "action": "quarantine_host",
                "target": "asset-payments-api",
                "decision": "DENY",
                "reason": "Analyst requested manual containment.",
            },
        )
        continue_response = self.client.post(f"/investigations/{incident_id}/continue", json={"max_steps": 4})

        self.assertEqual(override_response.status_code, 200)
        self.assertEqual(continue_response.status_code, 200)
        body = continue_response.json()
        actions = [action["action"] for action in body["actions_taken"]]
        self.assertIn("block_ip", actions)
        self.assertNotIn("quarantine_host", actions)
        self.assertEqual(body["response_status"], "DENIED")


if __name__ == "__main__":
    unittest.main()
