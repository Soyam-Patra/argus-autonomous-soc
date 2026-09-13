from __future__ import annotations

import argparse

from .orchestrator import run_terminal_demo


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ARGUS Milestone 2 terminal investigation loop.")
    parser.add_argument("--scenario", default="scenario-003", help="Scenario ID to run, such as scenario-001 or scenario-002.")
    args = parser.parse_args()

    state = run_terminal_demo(args.scenario)
    print(f"ARGUS Milestone 2 terminal investigation")
    print(f"Scenario: {args.scenario}")
    print(f"Incident: {state.incident_id}")
    for event in state.events:
        if event.event_type == "DECISION":
            print(f"Agent: {event.rationale}")
            print(event.message)
        elif event.event_type == "TOOL_RESULT":
            print(event.message)
        elif event.event_type in {"START", "ASSESSMENT", "CLOSE", "STOP"}:
            print(event.message)
    if state.final_assessment:
        print(f"Verdict: {state.final_assessment['verdict']}")
        print(f"Confidence: {state.final_assessment['confidence']:.0%}")
        print(f"Evidence score: {state.final_assessment['evidence_score']}")


if __name__ == "__main__":
    main()
