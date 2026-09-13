from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status

from backend.agent.orchestrator import InvestigationOrchestrator
from backend.environment.scenarios import load_scenarios
from backend.environment.simulator import SimulatorError

from .schemas import HumanOverrideRequest, InvestigationContinueRequest, InvestigationCreateRequest


router = APIRouter()

_orchestrator = InvestigationOrchestrator()
_investigations: dict[str, dict[str, Any]] = {}


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "argus"}


@router.get("/scenarios")
def scenarios() -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": scenario.scenario_id,
            "name": scenario.name,
            "incident_id": scenario.incident_id,
            "alert_id": scenario.alert_id,
            "expected_outcome": scenario.expected_outcome,
            "description": scenario.description,
        }
        for scenario in load_scenarios().values()
    ]


@router.post("/investigations", status_code=status.HTTP_201_CREATED)
def create_investigation(request: InvestigationCreateRequest) -> dict[str, Any]:
    try:
        state = _orchestrator.run(request.scenario_id, max_steps=request.max_steps or 20)
    except SimulatorError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    _investigations[state.incident_id] = {"scenario_id": request.scenario_id, "state": state}
    return {
        "incident_id": state.incident_id,
        "scenario_id": request.scenario_id,
        "status": _status_for_state(state),
        "summary": _summary(state, request.scenario_id),
        "state": _state_payload(state, request.scenario_id),
    }


@router.post("/investigations/{incident_id}/continue")
def continue_investigation(incident_id: str, request: InvestigationContinueRequest) -> dict[str, Any]:
    record = _get_record(incident_id)
    state = _orchestrator.continue_run(record["state"], max_steps=request.max_steps)
    record["state"] = state
    return _state_payload(state, record["scenario_id"])


@router.get("/investigations/{incident_id}")
def get_investigation(incident_id: str) -> dict[str, Any]:
    record = _get_record(incident_id)
    return _state_payload(record["state"], record["scenario_id"])


@router.get("/investigations/{incident_id}/events")
def get_investigation_events(incident_id: str) -> list[dict[str, Any]]:
    record = _get_record(incident_id)
    return [event.model_dump(mode="json") for event in record["state"].events]


@router.get("/investigations/{incident_id}/evidence")
def get_investigation_evidence(incident_id: str) -> dict[str, Any]:
    record = _get_record(incident_id)
    return record["state"].evidence.model_dump(mode="json")


@router.post("/investigations/{incident_id}/override")
def record_override(incident_id: str, request: HumanOverrideRequest) -> dict[str, Any]:
    if request.decision.upper() not in {"APPROVE", "DENY"}:
        raise HTTPException(
            status_code=422,
            detail="decision must be APPROVE or DENY",
        )
    record = _get_record(incident_id)
    state = record["state"]
    state.record_human_override(
        action=request.action,
        target=request.target,
        decision=request.decision,
        reason=request.reason,
    )
    state.add_event(
        "HUMAN_OVERRIDE",
        f"Human override recorded: {request.decision.upper()} {request.action} {request.target}",
        rationale=request.reason,
    )
    return {
        "incident_id": incident_id,
        "scenario_id": record["scenario_id"],
        "status": "recorded",
        "override": state.denied_actions[-1],
    }


def _get_record(incident_id: str) -> dict[str, Any]:
    if incident_id not in _investigations:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown investigation: {incident_id}")
    return _investigations[incident_id]


def _state_payload(state: Any, scenario_id: str) -> dict[str, Any]:
    latest_decision = next((event for event in reversed(state.events) if event.event_type == "DECISION"), None)
    return {
        "incident_id": state.incident_id,
        "scenario_id": scenario_id,
        "alert_id": state.alert_id,
        "status": _status_for_state(state),
        "attack_outcome": state.attack_outcome.value,
        "attack_confidence": state.attack_confidence,
        "response_status": state.response_status.value,
        "containment_status": state.containment_status.value,
        "active_threat": state.active_threat,
        "final_assessment": state.final_assessment,
        "evidence": state.evidence.model_dump(mode="json"),
        "actions_taken": state.actions_taken,
        "events": [event.model_dump(mode="json") for event in state.events],
        "current_step": len([event for event in state.events if event.event_type == "DECISION"]),
        "current_decision": latest_decision.model_dump(mode="json") if latest_decision else None,
    }


def _summary(state: Any, scenario_id: str) -> dict[str, Any]:
    return {
        "incident_id": state.incident_id,
        "scenario_id": scenario_id,
        "status": _status_for_state(state),
        "attack_outcome": state.attack_outcome.value,
        "attack_confidence": state.attack_confidence,
        "response_status": state.response_status.value,
        "containment_status": state.containment_status.value,
        "active_threat": state.active_threat,
        "final_assessment": state.final_assessment,
    }


def _status_for_state(state: Any) -> str:
    if state.complete:
        return "CLOSED"
    if state.active_threat:
        return "ACTIVE"
    return "INVESTIGATING"
