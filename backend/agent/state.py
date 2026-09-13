from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from .schemas import EvidenceKind, Hypothesis, HypothesisOutcome


class InvestigationEvent(BaseModel):
    timestamp: str
    event_type: str
    message: str
    decision: str | None = None
    tool: str | None = None
    rationale: str | None = None
    confidence: float | None = None


class EvidenceStore(BaseModel):
    alert: dict[str, Any] | None = None
    network: list[dict[str, Any]] = Field(default_factory=list)
    asset: dict[str, Any] | None = None
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    server_logs: list[dict[str, Any]] = Field(default_factory=list)
    firewall: list[dict[str, Any]] = Field(default_factory=list)
    response: list[dict[str, Any]] = Field(default_factory=list)
    verification: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationState(BaseModel):
    incident_id: str
    alert_id: str
    run_id: str = Field(default_factory=lambda: f"RUN-{uuid4().hex[:8].upper()}")
    hypothesis: Hypothesis = Field(default_factory=Hypothesis)
    uncertainties: list[str] = Field(default_factory=lambda: ["Alert details have not been retrieved."])
    evidence: EvidenceStore = Field(default_factory=EvidenceStore)
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    events: list[InvestigationEvent] = Field(default_factory=list)
    final_assessment: dict[str, Any] | None = None
    complete: bool = False

    def add_event(
        self,
        event_type: str,
        message: str,
        decision: str | None = None,
        tool: str | None = None,
        rationale: str | None = None,
        confidence: float | None = None,
    ) -> None:
        self.events.append(
            InvestigationEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=event_type,
                message=message,
                decision=decision,
                tool=tool,
                rationale=rationale,
                confidence=confidence,
            )
        )

    def add_evidence(self, kind: EvidenceKind, result: Any) -> None:
        if kind == "alert":
            self.evidence.alert = result
            self.incident_id = result.get("incident_id", self.incident_id)
            self._replace_uncertainty("Alert details have not been retrieved.", "Is the destination asset important and exposed?")
            self._add_uncertainty("Is there network evidence matching the alert?")
        elif kind == "asset":
            self.evidence.asset = result
            self._remove_uncertainty("Is the destination asset important and exposed?")
            self._add_uncertainty("Is the destination vulnerable to the observed attack?")
        elif kind == "vulnerabilities":
            self.evidence.vulnerabilities = result
            self._remove_uncertainty("Is the destination vulnerable to the observed attack?")
            self._add_uncertainty("Did server-side execution or impact occur?")
        elif kind == "network":
            self.evidence.network.extend(result)
            self._remove_uncertainty("Is there network evidence matching the alert?")
            self._add_uncertainty("Did server-side execution or impact occur?")
        elif kind == "server_logs":
            self.evidence.server_logs.extend(result)
            self._remove_uncertainty("Did server-side execution or impact occur?")
        elif kind == "firewall":
            self.evidence.firewall.append(result)
        elif kind == "response":
            self.evidence.response.append(result)
            self.actions_taken.append(result)
            self._add_uncertainty("Did the response actually stop malicious activity?")
        elif kind == "verification":
            self.evidence.verification.append(result)
            self._remove_uncertainty("Did the response actually stop malicious activity?")
        self.recalculate_hypothesis()

    def recalculate_hypothesis(self) -> None:
        score = self.evidence_score()
        if score >= 70:
            outcome = HypothesisOutcome.SUCCESS
            rationale = "Exploit evidence includes vulnerability relevance plus execution or outbound activity."
        elif self._has_blocking_or_no_execution_evidence() and score < 30:
            outcome = HypothesisOutcome.FAILED
            rationale = "Available evidence points to blocking or no confirmed execution."
        elif score >= 30:
            outcome = HypothesisOutcome.INCONCLUSIVE
            rationale = "Suspicious evidence exists, but successful compromise is not proven yet."
        else:
            outcome = HypothesisOutcome.UNKNOWN
            rationale = "Evidence is still insufficient to determine attack outcome."
        self.hypothesis = Hypothesis(outcome=outcome, confidence=min(max(score / 100.0, 0.0), 1.0), rationale=rationale)

    def evidence_score(self) -> int:
        score = 0
        if self.evidence.network:
            if any("exploit" in item.get("classification", "") for item in self.evidence.network):
                score += 15
        if self.evidence.vulnerabilities:
            if any(not item.get("patched", True) for item in self.evidence.vulnerabilities):
                score += 20
            if any(item.get("exploit_available") for item in self.evidence.vulnerabilities):
                score += 10
        logs = self.evidence.server_logs
        if any(item.get("event_type") == "waf_event" and item.get("outcome") == "blocked" for item in logs):
            score -= 30
        if any(item.get("event_type") == "process_creation" for item in logs):
            score += 30
        if any(item.get("event_type") == "command_execution" for item in logs):
            score += 30
        if any(item.get("event_type") == "outbound_connection" for item in logs):
            score += 25
        if logs and not any(item.get("event_type") in {"process_creation", "command_execution", "outbound_connection"} for item in logs):
            score -= 15
        return score

    def build_final_assessment(self) -> dict[str, Any]:
        self.recalculate_hypothesis()
        assessment = {
            "incident_id": self.incident_id,
            "alert_id": self.alert_id,
            "verdict": self.hypothesis.outcome.value,
            "confidence": self.hypothesis.confidence,
            "rationale": self.hypothesis.rationale,
            "evidence_score": self.evidence_score(),
            "actions_taken": self.actions_taken,
        }
        self.final_assessment = assessment
        self.complete = True
        return assessment

    def _has_blocking_or_no_execution_evidence(self) -> bool:
        logs = self.evidence.server_logs
        return bool(logs) and not any(
            item.get("event_type") in {"process_creation", "command_execution", "outbound_connection"}
            for item in logs
        )

    def _add_uncertainty(self, text: str) -> None:
        if text not in self.uncertainties:
            self.uncertainties.append(text)

    def _remove_uncertainty(self, text: str) -> None:
        self.uncertainties = [item for item in self.uncertainties if item != text]

    def _replace_uncertainty(self, old: str, new: str) -> None:
        self._remove_uncertainty(old)
        self._add_uncertainty(new)
