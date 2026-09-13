from __future__ import annotations

import unittest

from backend.environment.simulator import ArgusSimulator, SimulatorError
from backend.tools import alerts, assets, firewall, logs, network, runtime, verification, vulnerabilities


class MilestoneOneSimulatorTests(unittest.TestCase):
    def test_primary_adaptation_scenario_changes_state_and_verifies(self) -> None:
        simulator = ArgusSimulator("scenario-003")

        alert = simulator.get_alert("ALERT-1042")
        asset = simulator.get_asset(alert["dest_ip"])
        vulns = simulator.get_vulnerabilities(asset["asset_id"])
        network_events = simulator.get_network_evidence(alert["dest_ip"], alert["src_ip"])
        server_logs = simulator.search_server_logs(asset["hostname"], alert["src_ip"])

        self.assertEqual(asset["hostname"], "payments-api")
        self.assertTrue(any(vuln["exploit_available"] for vuln in vulns))
        self.assertTrue(any(event["classification"] == "exploit_attempt" for event in network_events))
        self.assertTrue(any(item["event_type"] == "process_creation" for item in server_logs))

        block_result = simulator.firewall_block_ip(alert["src_ip"])
        self.assertEqual(block_result["status"], "applied")
        self.assertEqual(block_result["side_effect"], "attacker_source_rotated")

        failed_verification = simulator.verify_environment()
        self.assertEqual(failed_verification["verification_status"], "failed")
        self.assertTrue(failed_verification["malicious_traffic"])
        self.assertEqual(failed_verification["active_sources"], ["185.22.91.17"])

        quarantine_result = simulator.quarantine_host(asset["asset_id"])
        self.assertEqual(quarantine_result["status"], "applied")

        passed_verification = simulator.verify_environment()
        self.assertEqual(passed_verification["verification_status"], "passed")
        self.assertFalse(passed_verification["malicious_traffic"])
        self.assertTrue(passed_verification["host_isolated"])

    def test_block_ip_contains_non_rotating_confirmed_scenario(self) -> None:
        simulator = ArgusSimulator("scenario-001")
        alert = simulator.get_alert("ALERT-1042")

        simulator.firewall_block_ip(alert["src_ip"])
        result = simulator.verify_environment()

        self.assertEqual(result["verification_status"], "passed")
        self.assertFalse(result["malicious_traffic"])
        self.assertIn("185.22.91.14", result["blocked_ips"])

    def test_false_positive_scenario_has_blocked_logs_and_no_active_malicious_traffic(self) -> None:
        simulator = ArgusSimulator("scenario-002")
        alert = simulator.get_alert("ALERT-2041")
        asset = simulator.get_asset(alert["dest_ip"])
        server_logs = simulator.search_server_logs(asset["hostname"], alert["src_ip"])
        verification_result = simulator.verify_environment()

        self.assertTrue(any(item["event_type"] == "waf_event" and item["outcome"] == "blocked" for item in server_logs))
        self.assertFalse(any(item["event_type"] == "process_creation" for item in server_logs))
        self.assertEqual(verification_result["verification_status"], "passed")

    def test_tool_wrappers_use_shared_runtime_simulator(self) -> None:
        runtime.reset_simulator("scenario-003")

        alert = alerts.get_alert("ALERT-1042")
        asset = assets.get_asset(alert["dest_ip"])
        vuln_results = vulnerabilities.get_vulnerabilities(asset["asset_id"])
        net_results = network.get_network_evidence(alert["dest_ip"], alert["src_ip"])
        log_results = logs.search_server_logs(asset["hostname"], alert["src_ip"])
        before_firewall = firewall.get_firewall_state()
        block_result = firewall.firewall_block_ip(alert["src_ip"])
        failed_verification = verification.verify_environment()
        quarantine_result = firewall.quarantine_host(asset["asset_id"])
        passed_verification = verification.verify_environment()

        self.assertEqual(before_firewall["blocked_ips"], [])
        self.assertTrue(vuln_results)
        self.assertTrue(net_results)
        self.assertTrue(log_results)
        self.assertEqual(block_result["side_effect"], "attacker_source_rotated")
        self.assertEqual(failed_verification["verification_status"], "failed")
        self.assertEqual(quarantine_result["action"], "quarantine_host")
        self.assertEqual(passed_verification["verification_status"], "passed")

    def test_unknown_scenario_and_alert_raise_clear_errors(self) -> None:
        with self.assertRaises(SimulatorError):
            ArgusSimulator("missing")

        simulator = ArgusSimulator("scenario-001")
        with self.assertRaises(SimulatorError):
            simulator.get_alert("missing")


if __name__ == "__main__":
    unittest.main()
