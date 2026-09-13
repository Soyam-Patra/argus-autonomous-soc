from __future__ import annotations

import argparse

from .orchestrator import run_terminal_demo


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ARGUS terminal investigation loop.")
    parser.add_argument("--scenario", default="scenario-003", help="Scenario ID to run, such as scenario-001 or scenario-002.")
    args = parser.parse_args()

    state = run_terminal_demo(args.scenario)
    print(f"ARGUS Milestone 3 adaptive terminal investigation")
    print(f"Scenario: {args.scenario}")
    print(f"Incident: {state.incident_id}")
    for event in state.events:
        if event.event_type == "DECISION":
            print(f"Agent: {event.rationale}")
            print(event.message)
        elif event.event_type == "TOOL_RESULT":
            print(event.message)
        elif event.event_type in {
            "START",
            "ASSESSMENT",
            "RESPONSE_ATTEMPTED",
            "VERIFICATION_FAILED",
            "CONTAINMENT_FAILURE_DETECTED",
            "NEW_EVIDENCE_FOUND",
            "HYPOTHESIS_REVISED",
            "ADAPTIVE_RESPONSE_SELECTED",
            "RESPONSE_VERIFIED",
            "CLOSE",
            "STOP",
        }:
            print(event.message)
    if state.final_assessment:
        print(f"Verdict: {state.final_assessment['verdict']}")
        print(f"Confidence: {state.final_assessment['confidence']:.0%}")
        print(f"Evidence score: {state.final_assessment['evidence_score']}")
        print(f"Attack outcome: {state.final_assessment['attack_outcome']}")
        print(f"Response status: {state.final_assessment['response_status']}")
        print(f"Containment status: {state.final_assessment['containment_status']}")
        print(f"Active threat: {state.final_assessment['active_threat']}")


if __name__ == "__main__":
    main()
