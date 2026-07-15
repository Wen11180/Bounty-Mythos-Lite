"""Redacted, advisory-only feedback for the black-box field pilot."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


FIELD_PILOT_SCHEMA_VERSION = "black_box_field_pilot_v1"
SAFE_ALIAS_PATTERN = r"^[a-z][a-z0-9_-]{0,99}$"
FIELD_PILOT_SAFETY_NOTES = [
    "redacted_aggregate_only",
    "advisory_ranking_only",
    "no_execution_permission",
    "no_scope_change",
    "no_review_bypass",
    "no_report_submission",
]
FIELD_PILOT_METADATA_KEYS = {
    "schema_version",
    "engagement_alias",
    "candidate_alias",
    "candidate_rank",
    "label",
    "researcher_minutes",
    "externally_valid_report",
    "safety_incident",
    "operator_confirmed",
}

FieldPilotLabel = Literal[
    "valid",
    "duplicate",
    "invalid",
    "out_of_scope",
    "needs_evidence",
]
LearningOutcome = Literal["accepted", "duplicate", "informative", "na", "rejected"]
FieldPilotStatusValue = Literal["collecting_evidence", "field_pilot", "outcome_proven"]

LEARNING_OUTCOME_BY_LABEL: dict[str, LearningOutcome] = {
    "valid": "accepted",
    "duplicate": "duplicate",
    "invalid": "rejected",
    "out_of_scope": "na",
    "needs_evidence": "informative",
}


class FieldPilotFeedbackError(ValueError):
    pass


class FieldPilotFeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    program_id: str = Field(min_length=1, max_length=100, pattern=SAFE_ALIAS_PATTERN)
    engagement_alias: str = Field(min_length=1, max_length=100, pattern=SAFE_ALIAS_PATTERN)
    candidate_alias: str = Field(min_length=1, max_length=100, pattern=SAFE_ALIAS_PATTERN)
    playbook_id: str = Field(min_length=1, max_length=100, pattern=SAFE_ALIAS_PATTERN)
    candidate_rank: int = Field(ge=1, le=100)
    label: FieldPilotLabel
    researcher_minutes: int = Field(ge=1, le=10_080)
    bounty_amount: int | None = Field(default=None, ge=0, le=1_000_000_000)
    externally_valid_report: bool = False
    safety_incident: bool = False
    operator_confirmed: Literal[True]

    @model_validator(mode="after")
    def require_consistent_external_outcome(self) -> FieldPilotFeedbackRequest:
        if self.externally_valid_report and self.label != "valid":
            raise ValueError("external_report_requires_valid_label")
        if self.bounty_amount is not None and not self.externally_valid_report:
            raise ValueError("bounty_requires_externally_valid_report")
        return self

    def metadata(self) -> dict[str, Any]:
        return {
            "schema_version": FIELD_PILOT_SCHEMA_VERSION,
            "engagement_alias": self.engagement_alias,
            "candidate_alias": self.candidate_alias,
            "candidate_rank": self.candidate_rank,
            "label": self.label,
            "researcher_minutes": self.researcher_minutes,
            "externally_valid_report": self.externally_valid_report,
            "safety_incident": self.safety_incident,
            "operator_confirmed": self.operator_confirmed,
        }


class FieldPilotFeedbackEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    learning_signal_id: str = Field(min_length=1, max_length=100, pattern=SAFE_ALIAS_PATTERN)
    program_id: str = Field(min_length=1, max_length=100, pattern=SAFE_ALIAS_PATTERN)
    engagement_alias: str = Field(min_length=1, max_length=100, pattern=SAFE_ALIAS_PATTERN)
    candidate_alias: str = Field(min_length=1, max_length=100, pattern=SAFE_ALIAS_PATTERN)
    playbook_id: str = Field(min_length=1, max_length=100, pattern=SAFE_ALIAS_PATTERN)
    candidate_rank: int = Field(ge=1, le=100)
    label: FieldPilotLabel
    researcher_minutes: int = Field(ge=1, le=10_080)
    bounty_amount: int | None = Field(default=None, ge=0, le=1_000_000_000)
    externally_valid_report: bool = False
    safety_incident: bool = False
    operator_confirmed: Literal[True]
    created_at: str | None = None

    @model_validator(mode="after")
    def require_consistent_external_outcome(self) -> FieldPilotFeedbackEntry:
        if self.externally_valid_report and self.label != "valid":
            raise ValueError("external_report_requires_valid_label")
        if self.bounty_amount is not None and not self.externally_valid_report:
            raise ValueError("bounty_requires_externally_valid_report")
        return self


class FieldPilotFeedbackResponse(FieldPilotFeedbackEntry):
    learning_outcome: LearningOutcome
    execution_allowed: Literal[False] = False
    lease_grant_allowed: Literal[False] = False
    scope_change_allowed: Literal[False] = False
    review_bypass_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    safety_notes: list[str] = Field(
        default_factory=lambda: list(FIELD_PILOT_SAFETY_NOTES)
    )


class FieldPilotMetrics(BaseModel):
    independent_engagement_count: int = Field(ge=0)
    program_count: int = Field(ge=0)
    manually_reviewed_candidate_count: int = Field(ge=0)
    top_10_reviewed_count: int = Field(ge=0)
    top_10_valid_count: int = Field(ge=0)
    top_10_submit_worthy_precision: float = Field(ge=0, le=1)
    safety_incident_count: int = Field(ge=0)
    externally_valid_report_count: int = Field(ge=0)
    externally_valid_program_count: int = Field(ge=0)
    bounty_outcome_count: int = Field(ge=0)
    researcher_minutes: int = Field(ge=0)
    bounty_total: int = Field(ge=0)
    bounty_per_researcher_hour: float = Field(ge=0)


class FieldPilotRequirements(BaseModel):
    field_pilot: bool
    outcome_proven: bool


class FieldPilotStatus(BaseModel):
    status: FieldPilotStatusValue
    metrics: FieldPilotMetrics
    requirements: FieldPilotRequirements
    execution_allowed: Literal[False] = False
    lease_grant_allowed: Literal[False] = False
    scope_change_allowed: Literal[False] = False
    review_bypass_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    safety_notes: list[str] = Field(
        default_factory=lambda: list(FIELD_PILOT_SAFETY_NOTES)
    )


def record_field_pilot_feedback(
    *,
    repository: Any,
    request: FieldPilotFeedbackRequest,
) -> FieldPilotFeedbackResponse:
    metadata = request.metadata()
    for record in repository.list_learning_signals(request.program_id):
        existing_metadata = getattr(record, "field_pilot_feedback", None)
        if not isinstance(existing_metadata, dict):
            continue
        if (
            existing_metadata.get("schema_version") != FIELD_PILOT_SCHEMA_VERSION
            or existing_metadata.get("engagement_alias") != request.engagement_alias
            or existing_metadata.get("candidate_alias") != request.candidate_alias
        ):
            continue
        entry = _entry_from_record(record)
        if entry is not None and _entry_matches_request(entry, request):
            return _feedback_response(entry)
        raise FieldPilotFeedbackError("field_pilot_feedback_already_recorded")

    learning_outcome = LEARNING_OUTCOME_BY_LABEL[request.label]
    record = repository.save_learning_signal(
        program_id=request.program_id,
        playbook_id=request.playbook_id,
        outcome=learning_outcome,
        surface_key=request.candidate_alias,
        notes=_feedback_notes(request.label),
        bounty_amount=request.bounty_amount,
        severity_delta=None,
        evidence_quality=None,
        triager_feedback=None,
        target_relationships=[],
        field_pilot_feedback=metadata,
    )
    entry = _entry_from_record(record)
    if entry is None:
        raise FieldPilotFeedbackError("field_pilot_feedback_write_failed")
    if not _entry_matches_request(entry, request):
        raise FieldPilotFeedbackError("field_pilot_feedback_already_recorded")
    return _feedback_response(entry)


def field_pilot_entries(records: Iterable[Any]) -> list[FieldPilotFeedbackEntry]:
    entries_by_candidate: dict[tuple[str, str, str], FieldPilotFeedbackEntry] = {}
    for record in records:
        entry = _entry_from_record(record)
        if entry is None:
            continue
        key = (entry.program_id, entry.engagement_alias, entry.candidate_alias)
        entries_by_candidate.setdefault(key, entry)
    return list(entries_by_candidate.values())


def evaluate_field_pilot_status(
    entries: Iterable[FieldPilotFeedbackEntry],
) -> FieldPilotStatus:
    reviewed = list(entries)
    top_10 = [entry for entry in reviewed if entry.candidate_rank <= 10]
    top_10_valid_count = sum(entry.label == "valid" for entry in top_10)
    precision = round(top_10_valid_count / len(top_10), 4) if top_10 else 0.0
    safety_incident_count = sum(entry.safety_incident for entry in reviewed)
    externally_valid_report_count = sum(
        entry.externally_valid_report for entry in reviewed
    )
    externally_valid_program_count = len(
        {
            entry.program_id
            for entry in reviewed
            if entry.externally_valid_report
        }
    )
    bounty_outcome_count = sum(
        entry.externally_valid_report
        and entry.bounty_amount is not None
        and entry.bounty_amount > 0
        for entry in reviewed
    )
    researcher_minutes = sum(entry.researcher_minutes for entry in reviewed)
    bounty_total = sum(entry.bounty_amount or 0 for entry in reviewed)
    bounty_per_researcher_hour = (
        round(bounty_total * 60 / researcher_minutes, 2)
        if researcher_minutes
        else 0.0
    )
    engagement_count = len(
        {(entry.program_id, entry.engagement_alias) for entry in reviewed}
    )
    program_count = len({entry.program_id for entry in reviewed})

    field_pilot_ready = (
        engagement_count >= 5
        and len(reviewed) >= 30
        and precision >= 0.30
        and safety_incident_count == 0
    )
    outcome_proven = (
        field_pilot_ready
        and externally_valid_report_count >= 10
        and externally_valid_program_count >= 3
        and bounty_outcome_count >= 5
    )
    status: FieldPilotStatusValue = (
        "outcome_proven"
        if outcome_proven
        else "field_pilot"
        if field_pilot_ready
        else "collecting_evidence"
    )
    return FieldPilotStatus(
        status=status,
        metrics=FieldPilotMetrics(
            independent_engagement_count=engagement_count,
            program_count=program_count,
            manually_reviewed_candidate_count=len(reviewed),
            top_10_reviewed_count=len(top_10),
            top_10_valid_count=top_10_valid_count,
            top_10_submit_worthy_precision=precision,
            safety_incident_count=safety_incident_count,
            externally_valid_report_count=externally_valid_report_count,
            externally_valid_program_count=externally_valid_program_count,
            bounty_outcome_count=bounty_outcome_count,
            researcher_minutes=researcher_minutes,
            bounty_total=bounty_total,
            bounty_per_researcher_hour=bounty_per_researcher_hour,
        ),
        requirements=FieldPilotRequirements(
            field_pilot=field_pilot_ready,
            outcome_proven=outcome_proven,
        ),
    )


def _entry_from_record(record: Any) -> FieldPilotFeedbackEntry | None:
    metadata = getattr(record, "field_pilot_feedback", None)
    if not isinstance(metadata, dict) or set(metadata) != FIELD_PILOT_METADATA_KEYS:
        return None
    if metadata.get("schema_version") != FIELD_PILOT_SCHEMA_VERSION:
        return None
    try:
        entry = FieldPilotFeedbackEntry(
            learning_signal_id=record.id,
            program_id=record.program_id,
            engagement_alias=metadata["engagement_alias"],
            candidate_alias=metadata["candidate_alias"],
            playbook_id=record.playbook_id,
            candidate_rank=metadata["candidate_rank"],
            label=metadata["label"],
            researcher_minutes=metadata["researcher_minutes"],
            bounty_amount=record.bounty_amount,
            externally_valid_report=metadata["externally_valid_report"],
            safety_incident=metadata["safety_incident"],
            operator_confirmed=metadata["operator_confirmed"],
            created_at=record.created_at.isoformat(),
        )
    except (KeyError, TypeError, ValueError):
        return None
    if (
        record.outcome != LEARNING_OUTCOME_BY_LABEL[entry.label]
        or record.surface_key != entry.candidate_alias
        or record.notes != _feedback_notes(entry.label)
        or record.severity_delta is not None
        or record.evidence_quality is not None
        or record.triager_feedback is not None
        or record.target_relationships != []
    ):
        return None
    return entry


def _entry_matches_request(
    entry: FieldPilotFeedbackEntry,
    request: FieldPilotFeedbackRequest,
) -> bool:
    return (
        entry.program_id == request.program_id
        and entry.engagement_alias == request.engagement_alias
        and entry.candidate_alias == request.candidate_alias
        and entry.playbook_id == request.playbook_id
        and entry.candidate_rank == request.candidate_rank
        and entry.label == request.label
        and entry.researcher_minutes == request.researcher_minutes
        and entry.bounty_amount == request.bounty_amount
        and entry.externally_valid_report == request.externally_valid_report
        and entry.safety_incident == request.safety_incident
        and entry.operator_confirmed is request.operator_confirmed
    )


def _feedback_response(entry: FieldPilotFeedbackEntry) -> FieldPilotFeedbackResponse:
    return FieldPilotFeedbackResponse(
        **entry.model_dump(),
        learning_outcome=LEARNING_OUTCOME_BY_LABEL[entry.label],
    )


def _feedback_notes(label: FieldPilotLabel) -> str:
    return f"operator-reviewed field-pilot label: {label}"
