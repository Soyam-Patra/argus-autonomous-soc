from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class InvestigationCreateRequest(BaseModel):
    scenario_id: str = Field(default="scenario-003")
    max_steps: int | None = Field(default=None, ge=1, le=50)


class InvestigationContinueRequest(BaseModel):
    max_steps: int = Field(default=12, ge=1, le=50)


class HumanOverrideRequest(BaseModel):
    action: str
    target: str
    decision: str
    reason: str | None = None


class InvestigationSummary(BaseModel):
    incident_id: str
    scenario_id: str
    status: str
    attack_outcome: str
    attack_confidence: float
    response_status: str
    containment_status: str
    active_threat: bool
    final_assessment: dict[str, Any] | None = None

