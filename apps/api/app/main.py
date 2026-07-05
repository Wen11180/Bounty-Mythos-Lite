from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from app.db import get_session
from app.db_models import ArtifactRecord, LearningSignalRecord, PipelineRunRecord
from app.hunter_intelligence import (
    HunterIntelligence,
)
from app.llm.base import LLMRequest, LLMResponse
from app.llm.registry import UnknownProviderError, build_default_registry
from app.models import Finding, Program, ReportDraft
from app.mythos_brain import (
    LearningEvidenceQuality,
    LearningOutcome,
    LearningSignal,
    LearningSeverityDelta,
    LessonRecommendation,
    LessonScopeType,
    MythosLesson,
    ProgramIntelligenceProfile,
    build_learning_signal_from_outcome,
    build_mythos_lessons,
    build_program_intelligence,
)
from app.mythos_finding import promote_pipeline_run_to_finding_candidate
from app.mythos_pipeline import (
    MythosPipelineDryRunRequest,
    MythosPipelineDryRunResponse,
    PipelineArtifactSummary,
    PipelineStage,
    PipelineValidationGate,
    artifact_payload_summary,
    artifact_source_hash,
    build_mythos_pipeline_dry_run,
    count_blocked,
)
from app.mythos_report import (
    ClaimLedgerEntry,
    ClaimReviewDecisionValue,
    ClaimReviewDecisionResponse,
    ReportPreviewResponse,
    best_finding_candidate_claim,
    build_report_preview_response,
    review_evidence_refs_are_report_safe,
    safe_preview_lines,
    safe_preview_text,
    safe_string_list,
)
from app.repository import DatabaseRepository
from app.scope_guard import (
    ScopeGuardDecision,
    ScopeGuardRule,
    ValidationRequest,
    evaluate_validation_request,
)
from pydantic import BaseModel, Field


app = FastAPI(title="Bounty Mythos-Lite API")


class ScopeGuardEvaluationRequest(BaseModel):
    rule: ScopeGuardRule
    request: ValidationRequest


class MythosPipelineRunSummary(BaseModel):
    id: str
    program_id: str | None = None
    asset: str
    policy_text_hash: str
    scope_status: str
    hypothesis_count: int
    blocked_count: int
    evidence_count: int
    report_title: str | None
    created_at: str
    timeline: list[PipelineStage] = Field(default_factory=list)
    artifact: PipelineArtifactSummary | None = None
    validation_gate: PipelineValidationGate | None = None
    hunter_intelligence: HunterIntelligence | None = None
    evidence_support_summary: dict | None = None


class MythosPipelineRunDetail(MythosPipelineRunSummary):
    payload: dict


class ArtifactResponse(BaseModel):
    id: str
    program_id: str | None
    asset: str
    kind: str
    source_type: str
    source_hash: str
    ingestion_status: str
    provenance: dict
    payload_summary: dict
    derived_facts: dict
    sensitivity_label: str
    redaction_status: str
    report_chain_allowed: bool
    safety_blockers: list[str] = Field(default_factory=list)
    usage_records: list[dict] = Field(default_factory=list)
    created_at: str


class ClaimReviewDecisionRequest(BaseModel):
    claim_id: str
    decision: ClaimReviewDecisionValue
    reviewer: str = Field(min_length=1, max_length=100)
    rationale: str = Field(default="", max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)

ManualObservationType = Literal[
    "manual_observation",
    "role_matrix_observation",
    "request_response_diff",
    "redaction_note",
]


class ManualObservationRequest(BaseModel):
    claim_id: str
    observation_type: ManualObservationType = "manual_observation"
    observer: str = Field(min_length=1, max_length=100)
    observation: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    safety_notes: list[str] = Field(default_factory=list, max_length=20)


class ManualObservationResponse(BaseModel):
    observation_id: str
    claim_id: str
    observation_type: ManualObservationType
    observer: str
    observation: str
    evidence_refs: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    redaction_status: str = "redacted"
    execution_allowed: bool = False
    report_chain_blocked: bool = True
    created_at: str


class LearningSignalRequest(BaseModel):
    program_id: str
    playbook_id: str
    outcome: LearningOutcome
    surface_key: str | None = None
    notes: str = Field(default="", max_length=1000)
    bounty_amount: int | None = Field(default=None, ge=0)
    severity_delta: LearningSeverityDelta | None = None
    evidence_quality: LearningEvidenceQuality | None = None
    triager_feedback: str | None = Field(default=None, max_length=1000)
    target_relationships: list[str] = Field(default_factory=list, max_length=20)


class LearningOutcomeRequest(BaseModel):
    outcome: LearningOutcome
    program_id: str | None = None
    run_id: str | None = None
    playbook_id: str | None = None
    surface_key: str | None = None
    notes: str = Field(default="", max_length=1000)
    bounty_amount: int | None = Field(default=None, ge=0)
    severity_delta: LearningSeverityDelta | None = None
    evidence_quality: LearningEvidenceQuality | None = None
    triager_feedback: str | None = Field(default=None, max_length=1000)
    target_relationships: list[str] | None = Field(default=None, max_length=20)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "bounty-mythos-api"}


@app.get("/programs", response_model=list[Program])
def list_programs(session: Session = Depends(get_session)) -> list[Program]:
    return DatabaseRepository(session).list_programs()


@app.get("/programs/{program_id}", response_model=Program)
def get_program(program_id: str, session: Session = Depends(get_session)) -> Program:
    program = DatabaseRepository(session).get_program(program_id)
    if program is not None:
        return program
    raise HTTPException(status_code=404, detail="Program not found")


@app.get("/findings", response_model=list[Finding])
def list_findings(session: Session = Depends(get_session)) -> list[Finding]:
    return DatabaseRepository(session).list_findings()


@app.get("/findings/{finding_id}", response_model=Finding)
def get_finding(finding_id: str, session: Session = Depends(get_session)) -> Finding:
    finding = DatabaseRepository(session).get_finding(finding_id)
    if finding is not None:
        return finding
    raise HTTPException(status_code=404, detail="Finding not found")


@app.get("/reports", response_model=list[ReportDraft])
def list_reports(session: Session = Depends(get_session)) -> list[ReportDraft]:
    return DatabaseRepository(session).list_reports()


@app.get("/reports/{report_id}", response_model=ReportDraft)
def get_report(report_id: str, session: Session = Depends(get_session)) -> ReportDraft:
    report = DatabaseRepository(session).get_report(report_id)
    if report is not None:
        return report
    raise HTTPException(status_code=404, detail="Report not found")


@app.get("/mythos/artifacts", response_model=list[ArtifactResponse])
def list_mythos_artifacts(
    program_id: str | None = None,
    asset: str | None = None,
    source_type: str | None = None,
    ingestion_status: str | None = None,
    provenance_ref: str | None = None,
    fact_type: str | None = None,
    usage_type: str | None = None,
    usage_run_id: str | None = None,
    sensitivity_label: str | None = None,
    redaction_status: str | None = None,
    report_chain_allowed: bool | None = None,
    session: Session = Depends(get_session),
) -> list[ArtifactResponse]:
    return [
        _artifact_response(record)
        for record in DatabaseRepository(session).list_artifacts(
            program_id=program_id,
            asset=asset,
            source_type=source_type,
            ingestion_status=ingestion_status,
            provenance_ref=provenance_ref,
            fact_type=fact_type,
            usage_type=usage_type,
            usage_run_id=usage_run_id,
            sensitivity_label=sensitivity_label,
            redaction_status=redaction_status,
            report_chain_allowed=report_chain_allowed,
        )
    ]


@app.get("/mythos/artifacts/{artifact_id}", response_model=ArtifactResponse)
def get_mythos_artifact(
    artifact_id: str,
    session: Session = Depends(get_session),
) -> ArtifactResponse:
    record = DatabaseRepository(session).get_artifact(artifact_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _artifact_response(record)


@app.get(
    "/mythos/brain/programs/{program_id}",
    response_model=ProgramIntelligenceProfile,
)
def get_mythos_brain_program(
    program_id: str,
    session: Session = Depends(get_session),
) -> ProgramIntelligenceProfile:
    repository = DatabaseRepository(session)
    program = repository.get_program(program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    return _program_intelligence_profile(repository, program_id)


@app.post("/mythos/brain/learning-signals", response_model=LearningSignal)
def create_mythos_brain_learning_signal(
    request: LearningSignalRequest,
    session: Session = Depends(get_session),
) -> LearningSignal:
    repository = DatabaseRepository(session)
    if repository.get_program(request.program_id) is None:
        raise HTTPException(status_code=404, detail="Program not found")
    record = repository.save_learning_signal(
        program_id=request.program_id,
        playbook_id=request.playbook_id,
        outcome=request.outcome,
        surface_key=request.surface_key,
        notes=request.notes,
        bounty_amount=request.bounty_amount,
        severity_delta=request.severity_delta,
        evidence_quality=request.evidence_quality,
        triager_feedback=request.triager_feedback,
        target_relationships=request.target_relationships,
    )
    return _learning_signal_response(record)


@app.get("/mythos/brain/lessons", response_model=list[MythosLesson])
def list_mythos_brain_lessons(
    program_id: str | None = None,
    scope_type: LessonScopeType | None = None,
    playbook_id: str | None = None,
    surface_pattern: str | None = None,
    recommendation: LessonRecommendation | None = None,
    session: Session = Depends(get_session),
) -> list[MythosLesson]:
    repository = DatabaseRepository(session)
    records = (
        repository.list_learning_signals(program_id)
        if program_id is not None
        else repository.list_all_learning_signals()
    )
    lessons = build_mythos_lessons([_learning_signal_response(record) for record in records])
    return [
        lesson
        for lesson in lessons
        if (scope_type is None or lesson.scope_type == scope_type)
        and (playbook_id is None or lesson.playbook_id == playbook_id)
        and (surface_pattern is None or lesson.surface_pattern == surface_pattern)
        and (recommendation is None or lesson.recommendation == recommendation)
    ]


@app.post("/mythos/brain/outcomes", response_model=ProgramIntelligenceProfile)
def create_mythos_brain_outcome(
    request: LearningOutcomeRequest,
    session: Session = Depends(get_session),
) -> ProgramIntelligenceProfile:
    repository = DatabaseRepository(session)
    run_record = None
    if request.run_id is not None:
        run_record = repository.get_pipeline_run(request.run_id)
        if run_record is None:
            raise HTTPException(status_code=404, detail="Pipeline run not found")

    program_id = request.program_id or (run_record.program_id if run_record else None)
    if program_id is None:
        raise HTTPException(status_code=422, detail="program_id or run_id is required")
    if run_record is not None and run_record.program_id not in {None, program_id}:
        raise HTTPException(status_code=409, detail="Outcome program does not match run")
    if repository.get_program(program_id) is None:
        raise HTTPException(status_code=404, detail="Program not found")

    evidence_quality = request.evidence_quality
    if evidence_quality is None and run_record is not None:
        evidence_quality = _evidence_quality_from_reviewed_claims(run_record)

    signal = build_learning_signal_from_outcome(
        program_id=program_id,
        outcome=request.outcome,
        notes=request.notes,
        pipeline_run=_pipeline_run_brain_payload(run_record) if run_record else None,
        playbook_id=request.playbook_id,
        surface_key=request.surface_key,
        bounty_amount=request.bounty_amount,
        severity_delta=request.severity_delta,
        evidence_quality=evidence_quality,
        triager_feedback=request.triager_feedback,
        target_relationships=request.target_relationships,
    )
    signal_record = repository.save_learning_signal(
        program_id=signal.program_id,
        playbook_id=signal.playbook_id,
        outcome=signal.outcome,
        surface_key=signal.surface_key,
        notes=signal.notes,
        bounty_amount=signal.bounty_amount,
        severity_delta=signal.severity_delta,
        evidence_quality=signal.evidence_quality,
        triager_feedback=signal.triager_feedback,
        target_relationships=signal.target_relationships,
    )
    if run_record is not None:
        usage_record = _artifact_usage_record_for_learning_signal(
            record=run_record,
            signal=_learning_signal_response(signal_record),
        )
        if usage_record is not None:
            artifact_id, usage = usage_record
            repository.append_artifact_usage_records(
                artifact_id=artifact_id,
                usage_records=[usage],
            )
    return _program_intelligence_profile(repository, program_id)


@app.post("/internal/llm/generate", response_model=LLMResponse)
async def generate_with_llm(
    request: LLMRequest,
    session: Session = Depends(get_session),
) -> LLMResponse:
    registry = build_default_registry()
    try:
        response = await registry.generate(request)
    except UnknownProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    DatabaseRepository(session).save_llm_run(
        provider=response.provider,
        model=response.model,
        purpose=request.purpose,
        prompt_hash=response.prompt_hash,
        mode=response.mode,
        latency_ms=response.latency_ms,
        error=response.error,
        safety_notes=_llm_audit_safety_notes(response),
    )
    if response.error:
        raise HTTPException(status_code=503, detail=response.model_dump(mode="json"))
    return response


@app.post("/scope-guard/evaluate", response_model=ScopeGuardDecision)
def evaluate_scope_guard(request: ScopeGuardEvaluationRequest) -> ScopeGuardDecision:
    return evaluate_validation_request(request.rule, request.request)


@app.post("/mythos/pipeline/dry-run", response_model=MythosPipelineDryRunResponse)
def run_mythos_pipeline_dry_run(
    request: MythosPipelineDryRunRequest,
    session: Session = Depends(get_session),
) -> MythosPipelineDryRunResponse:
    repository = DatabaseRepository(session)
    if request.program_id is not None and repository.get_program(request.program_id) is None:
        raise HTTPException(status_code=404, detail="Program not found")
    try:
        response, payload, openapi_like = build_mythos_pipeline_dry_run(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if request.program_id is not None:
        learning_signals = repository.list_learning_signals(request.program_id)
        (
            applied_reasons,
            skipped_reasons,
            lesson_traces,
        ) = _apply_program_learning_to_hunter_intelligence(
            response.hunter_intelligence,
            learning_signals,
        )
        if response.hunter_intelligence is not None:
            _sync_hypothesis_assessment_hunter_scores(response)
            payload["hunter_intelligence"] = response.hunter_intelligence.model_dump(mode="json")
            payload["hypothesis_assessments"] = [
                item.model_dump(mode="json")
                for item in response.hypothesis_assessments
            ]
        if applied_reasons or skipped_reasons:
            learning_stage = _program_learning_stage(
                len(learning_signals),
                applied_reasons or skipped_reasons,
                "completed" if applied_reasons else "skipped",
                lesson_traces,
            )
            response.timeline.append(learning_stage)
            payload["timeline"] = [stage.model_dump(mode="json") for stage in response.timeline]
    artifact_record = repository.save_artifact(
        program_id=request.program_id,
        asset=request.asset,
        kind=response.artifact_kind,
        source_type="dry_run_inline",
        source_hash=artifact_source_hash(request, response.artifact_kind),
        ingestion_status="normalized",
        provenance={
            "source": "dry-run inline artifact",
            "asset": request.asset,
            "kind": response.artifact_kind,
        },
        payload_summary=artifact_payload_summary(openapi_like, response.target_model),
        derived_facts={
            "paths": sorted(openapi_like.get("paths", {}).keys()),
            "objects": [
                item.model_dump(mode="json")
                for item in response.target_model.objects
            ],
            "sensitive_actions": [
                item.model_dump(mode="json")
                for item in response.target_model.sensitive_actions
            ],
            "relationships": [
                item.model_dump(mode="json")
                for item in response.target_model.relationships
            ],
        },
    )
    response.artifact = _pipeline_artifact_summary(
        artifact_record,
        evidence_count=_count_evidence_items(payload),
    )
    payload["artifact"] = response.artifact.model_dump(mode="json")
    record = repository.save_pipeline_run(
        program_id=request.program_id,
        asset=request.asset,
        policy_text=request.policy_text,
        scope_status=response.scope_rule.scope_status,
        hypothesis_count=len(response.hypotheses),
        blocked_count=count_blocked(response.hypothesis_assessments),
        report_title=response.report_draft.title if response.report_draft else None,
        payload=payload,
    )
    repository.append_artifact_usage_records(
        artifact_id=artifact_record.id,
        usage_records=_artifact_usage_records_for_run(record, artifact_record.id),
    )
    response.run_id = record.id
    return response


@app.get("/mythos/pipeline/runs", response_model=list[MythosPipelineRunSummary])
def list_mythos_pipeline_runs(
    session: Session = Depends(get_session),
) -> list[MythosPipelineRunSummary]:
    return [_pipeline_run_summary(record) for record in DatabaseRepository(session).list_pipeline_runs()]


@app.get("/mythos/pipeline/runs/{run_id}", response_model=MythosPipelineRunDetail)
def get_mythos_pipeline_run(
    run_id: str,
    session: Session = Depends(get_session),
) -> MythosPipelineRunDetail:
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return _pipeline_run_detail(record, repository)


@app.get(
    "/mythos/pipeline/runs/{run_id}/report-preview",
    response_model=ReportPreviewResponse,
)
def get_mythos_pipeline_report_preview(
    run_id: str,
    session: Session = Depends(get_session),
) -> ReportPreviewResponse:
    record = DatabaseRepository(session).get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return _build_report_preview_response_or_404(record)


@app.post(
    "/mythos/pipeline/runs/{run_id}/claim-review-decisions",
    response_model=ClaimReviewDecisionResponse,
)
def create_claim_review_decision(
    run_id: str,
    request: ClaimReviewDecisionRequest,
    session: Session = Depends(get_session),
) -> ClaimReviewDecisionResponse:
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")

    preview = _build_report_preview_response_or_404(record)
    claims_by_id = {claim.claim_id: claim for claim in preview.claim_ledger}
    claim = claims_by_id.get(request.claim_id)
    if claim is None:
        raise HTTPException(status_code=404, detail="Claim not found")

    decision = ClaimReviewDecisionResponse(
        claim_id=safe_preview_text(request.claim_id),
        decision=request.decision,
        reviewer=safe_preview_text(request.reviewer),
        rationale=safe_preview_text(request.rationale),
        evidence_refs=safe_preview_lines(request.evidence_refs),
        reviewed_at=datetime.now(UTC).isoformat(),
    )
    updated_record = repository.append_claim_review_decision(
        run_id=run_id,
        decision=decision.model_dump(mode="json"),
    )
    if updated_record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    usage_record = _artifact_usage_record_for_claim_review_decision(
        record=updated_record,
        claim=claim,
        decision=decision,
    )
    if usage_record is not None:
        artifact_id, usage = usage_record
        repository.append_artifact_usage_records(
            artifact_id=artifact_id,
            usage_records=[usage],
        )
    return decision


@app.post("/mythos/pipeline/runs/{run_id}/finding-candidates", response_model=Finding)
def create_finding_candidate_from_pipeline_run(
    run_id: str,
    session: Session = Depends(get_session),
) -> Finding:
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")

    preview = _build_report_preview_response_or_404(record)
    try:
        finding = promote_pipeline_run_to_finding_candidate(
            repository=repository,
            record=record,
            preview=preview,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    claim = best_finding_candidate_claim(preview)
    if claim is not None:
        usage_record = _artifact_usage_record_for_finding_candidate(
            record=record,
            claim=claim,
            finding=finding,
        )
        if usage_record is not None:
            artifact_id, usage = usage_record
            repository.append_artifact_usage_records(
                artifact_id=artifact_id,
                usage_records=[usage],
            )
    return finding


@app.post(
    "/mythos/pipeline/runs/{run_id}/manual-observations",
    response_model=ManualObservationResponse,
)
def create_manual_observation(
    run_id: str,
    request: ManualObservationRequest,
    session: Session = Depends(get_session),
) -> ManualObservationResponse:
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")

    preview = _build_report_preview_response_or_404(record)
    claims_by_id = {claim.claim_id: claim for claim in preview.claim_ledger}
    claim = claims_by_id.get(request.claim_id)
    if claim is None:
        raise HTTPException(status_code=404, detail="Claim not found")

    observation = ManualObservationResponse(
        observation_id=f"manual_observation_{uuid4().hex}",
        claim_id=safe_preview_text(request.claim_id),
        observation_type=request.observation_type,
        observer=safe_preview_text(request.observer),
        observation=safe_preview_text(request.observation),
        evidence_refs=safe_preview_lines(request.evidence_refs),
        safety_notes=safe_preview_lines(request.safety_notes),
        created_at=datetime.now(UTC).isoformat(),
    )
    updated_record = repository.append_manual_observation(
        run_id=run_id,
        observation=observation.model_dump(mode="json"),
    )
    if updated_record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    usage_record = _artifact_usage_record_for_manual_observation(
        record=updated_record,
        claim=claim,
        observation=observation,
    )
    if usage_record is not None:
        artifact_id, usage = usage_record
        repository.append_artifact_usage_records(
            artifact_id=artifact_id,
            usage_records=[usage],
        )
    return observation


def _pipeline_artifact_summary(
    record: ArtifactRecord,
    *,
    evidence_count: int,
) -> PipelineArtifactSummary:
    source = str(record.provenance.get("source", "dry-run inline artifact"))
    safety = _artifact_safety(record)
    return PipelineArtifactSummary(
        artifact_id=record.id,
        kind=record.kind,
        source_type=record.source_type,
        source=source,
        provenance=f"{source}; source hash recorded for provenance.",
        summary=(
            f"{record.payload_summary.get('path_count', 0)} path(s), "
            f"{record.payload_summary.get('endpoint_count', 0)} endpoint(s)."
        ),
        evidence_count=evidence_count,
        digest=record.source_hash,
        sensitivity_label=safety["sensitivity_label"],
        redaction_status=safety["redaction_status"],
        report_chain_allowed=safety["report_chain_allowed"],
        safety_blockers=safety["safety_blockers"],
    )


def _artifact_response(record: ArtifactRecord) -> ArtifactResponse:
    safety = _artifact_safety(record)
    return ArtifactResponse(
        id=record.id,
        program_id=record.program_id,
        asset=record.asset,
        kind=record.kind,
        source_type=record.source_type,
        source_hash=record.source_hash,
        ingestion_status=record.ingestion_status,
        provenance=record.provenance,
        payload_summary=record.payload_summary,
        derived_facts=record.derived_facts,
        sensitivity_label=safety["sensitivity_label"],
        redaction_status=safety["redaction_status"],
        report_chain_allowed=safety["report_chain_allowed"],
        safety_blockers=safety["safety_blockers"],
        usage_records=_artifact_usage_records(record),
        created_at=record.created_at.isoformat(),
    )


def _artifact_safety(record: ArtifactRecord) -> dict:
    safety = record.provenance.get("safety")
    if not isinstance(safety, dict):
        return {
            "sensitivity_label": "unknown",
            "redaction_status": "unknown",
            "report_chain_allowed": False,
            "safety_blockers": ["missing_safety_metadata"],
        }

    blockers = safety.get("safety_blockers", [])
    return {
        "sensitivity_label": safe_preview_text(safety.get("sensitivity_label", "unknown")),
        "redaction_status": safe_preview_text(safety.get("redaction_status", "unknown")),
        "report_chain_allowed": safety.get("report_chain_allowed") is True,
        "safety_blockers": _artifact_safety_blockers(blockers),
    }


def _artifact_safety_blockers(value: object) -> list[str]:
    if not isinstance(value, list):
        return []

    known_blockers = {
        "contains_secret_like_value",
        "contains_real_user_data_risk",
        "missing_safety_metadata",
    }
    blockers: list[str] = []
    for item in value:
        blocker = str(item)
        blockers.append(blocker if blocker in known_blockers else safe_preview_text(blocker))
    return blockers


def _artifact_usage_records(record: ArtifactRecord) -> list[dict]:
    usage_records = record.provenance.get("usage_records", [])
    if not isinstance(usage_records, list):
        return []
    return [usage_record for usage_record in usage_records if isinstance(usage_record, dict)]


def _artifact_usage_records_for_run(
    record: PipelineRunRecord,
    artifact_id: str,
) -> list[dict]:
    usage_records = [
        {
            "usage_type": "pipeline_run",
            "ref": f"run:{record.id}",
            "run_id": record.id,
            "stage": "pipeline_persistence",
        }
    ]

    evidence_bundle = record.payload.get("evidence_bundle")
    evidence_items = evidence_bundle.get("items", []) if isinstance(evidence_bundle, dict) else []
    for index, item in enumerate(evidence_items, start=1):
        if not isinstance(item, dict):
            continue
        evidence_type = safe_preview_text(item.get("type", "evidence_item"))
        usage_records.append(
            {
                "usage_type": "evidence_bundle",
                "ref": f"evidence:{record.id}:{index}",
                "run_id": record.id,
                "stage": "evidence_model",
                "evidence_type": evidence_type,
            }
        )

    hypothesis_assessments = record.payload.get("hypothesis_assessments", [])
    if isinstance(hypothesis_assessments, list):
        for index, assessment in enumerate(hypothesis_assessments, start=1):
            if not isinstance(assessment, dict):
                continue
            hypothesis = assessment.get("hypothesis")
            hunter_assessment = assessment.get("hunter_assessment")
            refutation = assessment.get("refutation")
            candidate_id = safe_preview_text(
                assessment.get("candidate_id", f"hypothesis_{index}")
            )
            usage_records.append(
                {
                    "usage_type": "hypothesis_candidate",
                    "ref": f"candidate:{record.id}:{candidate_id}",
                    "run_id": record.id,
                    "stage": "hypothesis_lifecycle",
                    "candidate_id": candidate_id,
                    "candidate_index": index - 1,
                    "candidate_status": safe_preview_text(
                        assessment.get("candidate_status", "unknown")
                    ),
                    "validation_mode": safe_preview_text(
                        hypothesis.get("validation_mode", "unknown")
                        if isinstance(hypothesis, dict)
                        else "unknown"
                    ),
                    "refutation_status": safe_preview_text(
                        refutation.get("status", "unknown")
                        if isinstance(refutation, dict)
                        else "unknown"
                    ),
                    "playbook_id": safe_preview_text(
                        hunter_assessment.get("playbook_id", "unknown")
                        if isinstance(hunter_assessment, dict)
                        else "unknown"
                    ),
                    "hunter_priority_score": (
                        hunter_assessment.get("hunter_priority_score")
                        if isinstance(hunter_assessment, dict)
                        else None
                    ),
                }
            )

    try:
        preview = build_report_preview_response(record)
    except ValueError:
        return usage_records
    for claim in preview.claim_ledger:
        if artifact_id not in claim.provenance_refs:
            continue
        usage_records.append(
            {
                "usage_type": "report_claim",
                "ref": f"claim:{claim.claim_id}",
                "run_id": record.id,
                "stage": "report_preview",
                "claim_id": claim.claim_id,
                "claim_type": claim.claim_type,
            }
        )
    return usage_records


def _artifact_usage_record_for_manual_observation(
    *,
    record: PipelineRunRecord,
    claim: ClaimLedgerEntry,
    observation: ManualObservationResponse,
) -> tuple[str, dict] | None:
    artifact = record.payload.get("artifact")
    if not isinstance(artifact, dict):
        return None

    artifact_id = artifact.get("artifact_id")
    if not artifact_id or str(artifact_id) not in claim.provenance_refs:
        return None

    return str(artifact_id), {
        "usage_type": "manual_observation",
        "ref": f"manual_observation:{observation.observation_id}",
        "run_id": record.id,
        "stage": "validation_workspace",
        "claim_id": observation.claim_id,
        "observation_id": observation.observation_id,
        "observation_type": observation.observation_type,
        "evidence_refs": observation.evidence_refs,
        "safety_notes": observation.safety_notes,
    }


def _artifact_usage_record_for_claim_review_decision(
    *,
    record: PipelineRunRecord,
    claim: ClaimLedgerEntry,
    decision: ClaimReviewDecisionResponse,
) -> tuple[str, dict] | None:
    artifact = record.payload.get("artifact")
    if not isinstance(artifact, dict):
        return None

    artifact_id = artifact.get("artifact_id")
    if not artifact_id or str(artifact_id) not in claim.provenance_refs:
        return None

    return str(artifact_id), {
        "usage_type": "claim_review_decision",
        "ref": f"claim_review:{decision.claim_id}",
        "run_id": record.id,
        "stage": "report_review",
        "claim_id": decision.claim_id,
        "decision": decision.decision,
        "reviewer": decision.reviewer,
        "reviewed_at": decision.reviewed_at,
        "evidence_refs": decision.evidence_refs,
    }


def _artifact_usage_record_for_finding_candidate(
    *,
    record: PipelineRunRecord,
    claim: ClaimLedgerEntry,
    finding: Finding,
) -> tuple[str, dict] | None:
    artifact = record.payload.get("artifact")
    if not isinstance(artifact, dict):
        return None

    artifact_id = artifact.get("artifact_id")
    if not artifact_id or str(artifact_id) not in claim.provenance_refs:
        return None

    return str(artifact_id), {
        "usage_type": "finding_candidate",
        "ref": f"finding_candidate:{finding.id}",
        "run_id": record.id,
        "stage": "finding_promotion",
        "claim_id": claim.claim_id,
        "finding_id": finding.id,
        "submission_recommendation": finding.submission_recommendation,
        "evidence_refs": finding.evidence_refs,
    }


def _artifact_usage_record_for_learning_signal(
    *,
    record: PipelineRunRecord,
    signal: LearningSignal,
) -> tuple[str, dict] | None:
    artifact = record.payload.get("artifact")
    if not isinstance(artifact, dict):
        return None

    artifact_id = artifact.get("artifact_id")
    if not artifact_id or signal.id is None:
        return None

    usage = {
        "usage_type": "learning_signal",
        "ref": f"learning_signal:{signal.id}",
        "run_id": record.id,
        "stage": "mythos_brain",
        "learning_signal_id": signal.id,
        "outcome": signal.outcome,
        "playbook_id": signal.playbook_id,
        "surface_key": signal.surface_key,
    }
    if signal.bounty_amount is not None:
        usage["bounty_amount"] = signal.bounty_amount
    if signal.severity_delta is not None:
        usage["severity_delta"] = signal.severity_delta
    if signal.evidence_quality is not None:
        usage["evidence_quality"] = signal.evidence_quality
    if signal.target_relationships:
        usage["target_relationships"] = signal.target_relationships
    return str(artifact_id), usage


def _learning_signal_response(record: LearningSignalRecord) -> LearningSignal:
    return LearningSignal(
        id=record.id,
        program_id=record.program_id,
        playbook_id=record.playbook_id,
        outcome=record.outcome,
        surface_key=record.surface_key,
        notes=record.notes,
        bounty_amount=record.bounty_amount,
        severity_delta=record.severity_delta,
        evidence_quality=record.evidence_quality,
        triager_feedback=record.triager_feedback,
        target_relationships=record.target_relationships,
        created_at=record.created_at.isoformat(),
    )


def _evidence_quality_from_reviewed_claims(
    record: PipelineRunRecord,
) -> LearningEvidenceQuality | None:
    try:
        preview = build_report_preview_response(record)
    except ValueError:
        return None

    weak_evidence_seen = False
    for claim in preview.claim_ledger:
        if claim.claim_type != "observed_fact":
            continue
        if claim.review_status == "needs_evidence":
            weak_evidence_seen = True
            continue
        if claim.review_status != "confirmed_observed_fact":
            continue
        has_security_impact_observation = (
            "has_security_impact_observation" in claim.quality_reasons
            and "missing_security_impact_observation" not in claim.readiness_blockers
        )
        if not has_security_impact_observation:
            weak_evidence_seen = True
            continue
        if review_evidence_refs_are_report_safe(claim.review_evidence_refs):
            return "strong"

    for claim in preview.claim_ledger:
        if (
            claim.claim_type == "observed_fact"
            and claim.review_status == "confirmed_observed_fact"
            and claim.quality_score >= 80
            and (claim.provenance_edges or claim.provenance_refs)
            and "has_security_impact_observation" in claim.quality_reasons
            and "missing_security_impact_observation" not in claim.readiness_blockers
        ):
            return "adequate"
    if weak_evidence_seen:
        return "weak"
    return None


def _apply_program_learning_to_hunter_intelligence(
    intelligence: HunterIntelligence | None,
    learning_signals: list[LearningSignalRecord],
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    if intelligence is None:
        return [], [], []

    lesson_inputs = [_learning_signal_response(signal) for signal in learning_signals]
    lessons = build_mythos_lessons(lesson_inputs)
    lessons_by_playbook: dict[str, list[MythosLesson]] = {}
    for lesson in lessons:
        lessons_by_playbook.setdefault(lesson.playbook_id, []).append(lesson)
    weak_accepted_playbooks = {
        signal.playbook_id
        for signal in learning_signals
        if signal.outcome == "accepted" and signal.evidence_quality == "weak"
    }
    lesson_candidate_playbooks = {signal.playbook_id for signal in learning_signals}

    applied_reasons: list[str] = []
    skipped_reasons: list[str] = []
    lesson_traces: list[dict[str, Any]] = []
    for assessment in intelligence.assessments:
        matching_lessons = lessons_by_playbook.get(assessment.playbook_id, [])
        hard_gate_blocked = (
            assessment.recommendation == "blocked"
            or assessment.rejection_risk_score >= 90
        )
        if hard_gate_blocked:
            if matching_lessons:
                skipped_reasons.append("learning:safety_gate_blocked")
                for lesson in matching_lessons:
                    lesson_traces.append(_lesson_trace(lesson, action="skipped"))
            continue
        if not matching_lessons:
            if assessment.playbook_id in weak_accepted_playbooks:
                skipped_reasons.append("learning:weak_accepted_evidence_not_boosted")
            elif assessment.playbook_id in lesson_candidate_playbooks:
                skipped_reasons.append("learning:lesson_not_ready")
            continue
        for lesson in matching_lessons:
            delta = max(-10, min(10, lesson.score_delta))
            if lesson.recommendation == "boost":
                assessment.hunter_priority_score = min(
                    100,
                    assessment.hunter_priority_score + delta,
                )
                if "learning:accepted_history" not in assessment.reasons:
                    assessment.reasons.append("learning:accepted_history")
                applied_reasons.append("learning:accepted_history")
                lesson_traces.append(_lesson_trace(lesson, action="applied"))
            elif lesson.recommendation == "duplicate_watch":
                assessment.duplicate_risk_score = min(
                    100,
                    assessment.duplicate_risk_score + abs(delta),
                )
                assessment.hunter_priority_score = max(
                    0,
                    assessment.hunter_priority_score - round(abs(delta) * 0.25),
                )
                if "learning:duplicate_history" not in assessment.reasons:
                    assessment.reasons.append("learning:duplicate_history")
                applied_reasons.append("learning:duplicate_history")
                lesson_traces.append(_lesson_trace(lesson, action="applied"))
            elif lesson.recommendation == "penalize":
                assessment.hunter_priority_score = max(
                    0,
                    assessment.hunter_priority_score + delta,
                )
                if "learning:rejection_history" not in assessment.reasons:
                    assessment.reasons.append("learning:rejection_history")
                applied_reasons.append("learning:rejection_history")
                lesson_traces.append(_lesson_trace(lesson, action="applied"))
            elif lesson.recommendation == "evidence_needed":
                skipped_reasons.append("learning:weak_accepted_evidence_not_boosted")
                lesson_traces.append(_lesson_trace(lesson, action="skipped"))
            for reason in lesson.reasons:
                if reason not in assessment.reasons:
                    assessment.reasons.append(reason)
        if "advisory_memory_only" not in assessment.safety_notes:
            assessment.safety_notes.append("advisory_memory_only")
    return sorted(set(applied_reasons)), sorted(set(skipped_reasons)), lesson_traces


def _lesson_trace(lesson: MythosLesson, *, action: str) -> dict[str, Any]:
    return {
        "lesson_id": (
            f"{lesson.scope_type}:{lesson.scope_key}:{lesson.playbook_id}:"
            f"{lesson.surface_pattern}:{lesson.recommendation}"
        ),
        "playbook_id": lesson.playbook_id,
        "surface_pattern": lesson.surface_pattern,
        "recommendation": lesson.recommendation,
        "action": action,
        "source_signal_count": len(lesson.source_signal_ids),
        "source_signal_ids": lesson.source_signal_ids,
        "reasons": lesson.reasons,
    }


def _program_learning_stage(
    signal_count: int,
    reasons: list[str],
    status: str,
    lesson_traces: list[dict[str, Any]] | None = None,
) -> PipelineStage:
    action = "adjusted hunter intelligence priorities" if status == "completed" else "left hunter intelligence unchanged"
    return PipelineStage(
        name="program_learning",
        status=status,
        input_summary=f"{signal_count} program learning signal(s) reviewed.",
        output_summary=(
            f"Program memory {action}: "
            f"{', '.join(reasons)}."
        ),
        safety_notes=[
            "advisory_memory_only",
            "human_review_required",
            "no_execution_permission",
        ],
        details={"lesson_traces": lesson_traces or []},
    )


def _sync_hypothesis_assessment_hunter_scores(
    response: MythosPipelineDryRunResponse,
) -> None:
    if response.hunter_intelligence is None:
        return
    for index, assessment in enumerate(response.hunter_intelligence.assessments):
        if index >= len(response.hypothesis_assessments):
            break
        response.hypothesis_assessments[index].hunter_assessment = assessment


def _pipeline_run_brain_payload(record: PipelineRunRecord) -> dict:
    return {
        "id": record.id,
        "program_id": record.program_id,
        "asset": record.asset,
        "payload": record.payload,
    }


def _program_intelligence_profile(
    repository: DatabaseRepository,
    program_id: str,
) -> ProgramIntelligenceProfile:
    program = repository.get_program(program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    pipeline_runs = [
        _pipeline_run_brain_payload(record)
        for record in repository.list_pipeline_runs_for_program(program_id)
    ]
    learning_signals = [
        _learning_signal_response(record)
        for record in repository.list_learning_signals(program_id)
    ]
    lesson_signals = [
        _learning_signal_response(record)
        for record in repository.list_all_learning_signals()
    ]
    return build_program_intelligence(
        program=program,
        pipeline_runs=pipeline_runs,
        learning_signals=learning_signals,
        lesson_signals=lesson_signals,
    )


def _llm_audit_safety_notes(response: LLMResponse) -> list[str]:
    notes = [
        "prompt_hash_only",
        "no_prompt_storage",
        "provider_response_not_fact",
    ]
    if response.mode == "dry_run":
        notes.append("dry_run_no_provider_call")
    if response.error:
        notes.append("provider_error_recorded")
    return notes


def _build_report_preview_response_or_404(
    record: PipelineRunRecord,
) -> ReportPreviewResponse:
    try:
        return build_report_preview_response(record)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


SECURITY_IMPACT_REQUIRED_OBSERVATION_TYPES = [
    "request_response_diff",
    "role_matrix_observation",
]


def _pipeline_run_detail_payload(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> dict:
    payload = dict(record.payload)
    workspace = payload.get("validation_workspace")
    if isinstance(workspace, dict):
        enriched_workspace = dict(workspace)
        enriched_workspace["claim_validation_tasks"] = _claim_validation_tasks(record)
        payload["validation_workspace"] = enriched_workspace
    payload["evidence_support_summary"] = _evidence_support_summary(record)
    payload["closed_loop_summary"] = _closed_loop_summary(record, repository)
    return payload


def _claim_validation_tasks(record: PipelineRunRecord) -> list[dict]:
    try:
        preview = build_report_preview_response(record)
    except ValueError:
        return []

    eligible_claim = best_finding_candidate_claim(preview)
    eligible_claim_id = eligible_claim.claim_id if eligible_claim is not None else None
    return [
        _claim_validation_task(
            claim,
            eligible_claim_id,
            _claim_relationship_contexts(record.payload, claim),
        )
        for claim in preview.claim_ledger
    ]


def _evidence_support_summary(record: PipelineRunRecord) -> dict:
    try:
        preview = build_report_preview_response(record)
    except ValueError:
        claims = []
    else:
        claims = preview.claim_ledger

    statuses = [_claim_evidence_support_status(claim) for claim in claims]
    status_counts = {status: statuses.count(status) for status in sorted(set(statuses))}

    return {
        "total_count": len(claims),
        "status_counts": status_counts,
        "missing_required_count": status_counts.get("missing_required_evidence", 0),
        "partially_supported_count": status_counts.get("partially_supported", 0),
        "satisfied_human_gated_count": status_counts.get("human_gated_supported", 0),
        "unsafe_or_redacted_requirement_count": status_counts.get(
            "unsafe_or_redacted_evidence",
            0,
        ),
        "top_support_status": _top_evidence_support_status(status_counts),
        "safety_notes": [
            "claim_ledger_derived",
            "advisory_only",
            "human_review_required",
            "no_submission_unblock",
        ],
    }


def _claim_evidence_support_status(claim: ClaimLedgerEntry) -> str:
    evidence_refs = list(claim.evidence_refs) + list(claim.review_evidence_refs)
    if any(ref == "[REDACTED]" for ref in evidence_refs):
        return "unsafe_or_redacted_evidence"
    if (
        claim.review_status == "confirmed_observed_fact"
        and claim.evidence_refs
        and claim.review_evidence_refs
    ):
        return "human_gated_supported"
    if "missing_evidence_refs" in claim.readiness_blockers or not claim.evidence_refs:
        return "missing_required_evidence"
    return "partially_supported"


def _top_evidence_support_status(status_counts: dict[str, int]) -> str | None:
    for status in [
        "unsafe_or_redacted_evidence",
        "human_gated_supported",
        "missing_required_evidence",
        "partially_supported",
    ]:
        if status_counts.get(status, 0) > 0:
            return status
    return None


def _closed_loop_summary(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> dict:
    payload = record.payload
    manual_observations = _safe_record_list(payload.get("manual_observations"))
    claim_review_decisions = _safe_record_list(payload.get("claim_review_decisions"))
    usage_records = _closed_loop_artifact_usage_records(record, repository)
    finding_candidate_count = _closed_loop_usage_count(
        usage_records,
        "finding_candidate",
        record.id,
    )
    learning_signal_count = _closed_loop_usage_count(
        usage_records,
        "learning_signal",
        record.id,
    )
    run_learning_signals = _closed_loop_learning_signals(
        usage_records,
        record,
        repository,
    )
    memory_lessons = build_mythos_lessons(run_learning_signals)
    lesson_count = len(memory_lessons)
    brain_memory_status = _closed_loop_brain_memory_status(
        learning_signal_count=learning_signal_count,
        lesson_count=lesson_count,
    )
    blocked_reasons = _closed_loop_blocked_reasons(record)

    return {
        "status": _closed_loop_status(
            manual_observation_count=len(manual_observations),
            reviewed_claim_count=len(claim_review_decisions),
            finding_candidate_count=finding_candidate_count,
            learning_signal_count=learning_signal_count,
            brain_memory_status=brain_memory_status,
            blocked_reasons=blocked_reasons,
        ),
        "manual_observation_count": len(manual_observations),
        "reviewed_claim_count": len(claim_review_decisions),
        "finding_candidate_count": finding_candidate_count,
        "learning_signal_count": learning_signal_count,
        "lesson_count": lesson_count,
        "brain_memory_status": brain_memory_status,
        "memory_lessons": [
            _closed_loop_memory_lesson(lesson) for lesson in memory_lessons
        ],
        "blocked_reasons": blocked_reasons,
        "safety_notes": [
            "no_live_requests",
            "test_accounts_only",
            "human_review_required",
            "candidate_not_validated",
        ],
        "steps": _closed_loop_steps(
            manual_observation_count=len(manual_observations),
            reviewed_claim_count=len(claim_review_decisions),
            finding_candidate_count=finding_candidate_count,
            learning_signal_count=learning_signal_count,
            lesson_count=lesson_count,
            brain_memory_status=brain_memory_status,
            blocked_reasons=blocked_reasons,
        ),
    }


def _closed_loop_status(
    *,
    manual_observation_count: int,
    reviewed_claim_count: int,
    finding_candidate_count: int,
    learning_signal_count: int,
    brain_memory_status: str,
    blocked_reasons: list[str],
) -> str:
    if blocked_reasons:
        return "blocked"
    if brain_memory_status == "lesson_ready":
        return "brain_memory_ready"
    if learning_signal_count:
        return "candidate_learning_recorded"
    if finding_candidate_count:
        return "finding_candidate_created"
    if reviewed_claim_count:
        return "claim_reviewed"
    if manual_observation_count:
        return "manual_observation_recorded"
    return "not_started"


def _closed_loop_steps(
    *,
    manual_observation_count: int,
    reviewed_claim_count: int,
    finding_candidate_count: int,
    learning_signal_count: int,
    lesson_count: int,
    brain_memory_status: str,
    blocked_reasons: list[str],
) -> list[dict]:
    claim_blocked = "no_promotion_eligible_claim" in blocked_reasons
    promotion_blocked = bool(blocked_reasons)

    return [
        {
            "key": "manual_observation",
            "label": "Manual Observation",
            "status": "complete" if manual_observation_count else "waiting",
            "reason": (
                f"{manual_observation_count} sanitized manual observation recorded."
                if manual_observation_count
                else "No sanitized manual observation recorded yet."
            ),
            "safety_gate": "test_accounts_only",
            "next_allowed_action": (
                "Review the observed claim against redacted evidence."
                if manual_observation_count
                else "Record a sanitized manual observation."
            ),
        },
        {
            "key": "claim_review",
            "label": "Claim Review",
            "status": (
                "blocked"
                if claim_blocked
                else "complete"
                if reviewed_claim_count
                else "waiting"
            ),
            "reason": (
                "Reviewed claim is not promotion eligible."
                if claim_blocked
                else f"{reviewed_claim_count} claim review decision recorded."
                if reviewed_claim_count
                else "No human claim review decision recorded yet."
            ),
            "safety_gate": (
                "no_promotion_eligible_claim" if claim_blocked else "human_review_required"
            ),
            "next_allowed_action": (
                "Resolve blockers before promotion."
                if claim_blocked
                else "Promote eligible observed claims to finding candidates."
                if reviewed_claim_count
                else "Review the observed claim with redacted evidence."
            ),
        },
        {
            "key": "finding_candidate",
            "label": "Finding Candidate",
            "status": (
                "blocked"
                if promotion_blocked and finding_candidate_count == 0
                else "complete"
                if finding_candidate_count
                else "waiting"
            ),
            "reason": (
                "Promotion is blocked by the current safety gate."
                if promotion_blocked and finding_candidate_count == 0
                else f"{finding_candidate_count} finding candidate created."
                if finding_candidate_count
                else "No finding candidate created yet."
            ),
            "safety_gate": "candidate_not_validated",
            "next_allowed_action": (
                "Resolve blockers before promotion."
                if promotion_blocked and finding_candidate_count == 0
                else "Record an advisory learning outcome without changing validation state."
                if finding_candidate_count
                else "Create a candidate from an eligible reviewed observed claim."
            ),
        },
        {
            "key": "learning_signal",
            "label": "Learning Signal",
            "status": "complete" if learning_signal_count else "waiting",
            "reason": (
                f"{learning_signal_count} learning signal linked to this run."
                if learning_signal_count
                else "No advisory learning signal linked yet."
            ),
            "safety_gate": "advisory_memory_only",
            "next_allowed_action": (
                "Refresh the Mythos Brain profile for future prioritization."
                if learning_signal_count
                else "Record an accepted, duplicate, informative, N/A, or rejected outcome."
            ),
        },
        {
            "key": "brain_memory",
            "label": "Brain Memory",
            "status": "complete" if brain_memory_status == "lesson_ready" else "waiting",
            "reason": _closed_loop_brain_memory_reason(
                learning_signal_count=learning_signal_count,
                lesson_count=lesson_count,
            ),
            "safety_gate": "no_execution_permission",
            "next_allowed_action": _closed_loop_brain_memory_next_action(
                brain_memory_status,
            ),
        },
    ]


def _closed_loop_brain_memory_status(
    *,
    learning_signal_count: int,
    lesson_count: int,
) -> str:
    if lesson_count:
        return "lesson_ready"
    if learning_signal_count:
        return "learning_recorded"
    return "waiting_for_learning"


def _closed_loop_brain_memory_reason(
    *,
    learning_signal_count: int,
    lesson_count: int,
) -> str:
    if lesson_count:
        return (
            f"{lesson_count} reusable advisory lesson available for future prioritization."
        )
    if learning_signal_count:
        return "Learning signal is recorded; reusable lesson needs more evidence."
    return "Program brain is waiting for a learning signal."


def _closed_loop_brain_memory_next_action(status: str) -> str:
    if status == "lesson_ready":
        return "Use lesson memory as advisory context only."
    if status == "learning_recorded":
        return "Record another corroborating outcome before advisory lesson use."
    return "Keep the candidate gated until outcome memory exists."


def _closed_loop_memory_lesson(lesson: MythosLesson) -> dict:
    return {
        "lesson_id": _closed_loop_readable_lesson_id(lesson),
        "scope_type": lesson.scope_type,
        "scope_key": lesson.scope_key,
        "playbook_id": lesson.playbook_id,
        "surface_pattern": lesson.surface_pattern,
        "recommendation": lesson.recommendation,
        "confidence": lesson.confidence,
        "source_signal_count": len(lesson.source_signal_ids),
        "source_signal_ids": lesson.source_signal_ids,
        "reasons": lesson.reasons,
        "safety_notes": sorted(lesson.safety_notes),
    }


def _closed_loop_readable_lesson_id(lesson: MythosLesson) -> str:
    return ":".join(
        [
            lesson.scope_type,
            lesson.scope_key,
            lesson.playbook_id,
            lesson.surface_pattern,
            lesson.recommendation,
        ]
    )


def _closed_loop_artifact_usage_records(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> list[dict]:
    artifact = record.payload.get("artifact")
    artifact_id = artifact.get("artifact_id") if isinstance(artifact, dict) else None
    if not artifact_id:
        return []

    artifact_record = repository.get_artifact(str(artifact_id))
    if artifact_record is None:
        return []
    return _artifact_usage_records(artifact_record)


def _closed_loop_learning_signals(
    usage_records: list[dict],
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> list[LearningSignal]:
    if record.program_id is None:
        return []

    run_signal_ids = {
        str(usage.get("learning_signal_id"))
        for usage in usage_records
        if usage.get("usage_type") == "learning_signal"
        and usage.get("run_id") == record.id
        and usage.get("learning_signal_id")
    }
    if not run_signal_ids:
        return []

    return [
        _learning_signal_response(signal)
        for signal in repository.list_learning_signals(record.program_id)
        if signal.id in run_signal_ids
    ]


def _closed_loop_usage_count(
    usage_records: list[dict],
    usage_type: str,
    run_id: str,
) -> int:
    return sum(
        1
        for usage in usage_records
        if usage.get("usage_type") == usage_type and usage.get("run_id") == run_id
    )


def _closed_loop_blocked_reasons(record: PipelineRunRecord) -> list[str]:
    payload = record.payload
    try:
        preview = build_report_preview_response(record)
    except ValueError:
        return ["report_preview_unavailable"]

    claim_review_decisions = _safe_record_list(payload.get("claim_review_decisions"))
    if claim_review_decisions and best_finding_candidate_claim(preview) is None:
        return ["no_promotion_eligible_claim"]

    return []


def _safe_record_list(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _claim_validation_task(
    claim: ClaimLedgerEntry,
    eligible_claim_id: str | None,
    relationship_contexts: list[str] | None = None,
) -> dict:
    relationship_contexts = relationship_contexts or []
    required_observation_types = (
        SECURITY_IMPACT_REQUIRED_OBSERVATION_TYPES.copy()
        if "missing_security_impact_observation" in claim.readiness_blockers
        else []
    )
    return {
        "claim_id": claim.claim_id,
        "claim_type": claim.claim_type,
        "claim_text": claim.text,
        "status": _claim_validation_task_status(
            claim,
            eligible_claim_id,
            relationship_contexts,
        ),
        "promotion_eligible": claim.claim_id == eligible_claim_id,
        "required_observation_types": required_observation_types,
        "relationship_contexts": relationship_contexts,
        "evidence_focus": (
            ["parent_child_authorization_matrix"]
            if relationship_contexts
            else []
        ),
        "evidence_refs": claim.evidence_refs,
        "review_evidence_refs": claim.review_evidence_refs,
        "readiness_blockers": claim.readiness_blockers,
        "quality_reasons": claim.quality_reasons,
        "quality_score": claim.quality_score,
        "readiness_level": claim.readiness_level,
        "review_status": claim.review_status,
        "human_review_required": claim.human_review_required,
        "execution_allowed": False,
        "safety_notes": [
            "advisory_only",
            "human_review_required",
            "test_accounts_only",
            "no_live_requests",
            "no_real_user_data",
        ],
    }


def _claim_validation_task_status(
    claim: ClaimLedgerEntry,
    eligible_claim_id: str | None,
    relationship_contexts: list[str] | None = None,
) -> str:
    blockers = set(claim.readiness_blockers)
    if claim.claim_id == eligible_claim_id:
        return "promotion_eligible"
    if "artifact_report_chain_blocked" in blockers:
        return "blocked_report_chain"
    if claim.claim_type != "observed_fact":
        return "not_reportable"
    if "missing_security_impact_observation" in blockers:
        if relationship_contexts:
            return "needs_boundary_matrix_observation"
        return "needs_security_impact_observation"
    if blockers & {"missing_evidence_refs", "missing_provenance_refs"}:
        return "needs_evidence"
    if claim.review_status == "confirmed_observed_fact":
        return "human_reviewed_gated"
    return "needs_human_review"


def _claim_relationship_contexts(
    payload: dict,
    claim: ClaimLedgerEntry,
) -> list[str]:
    target_model = payload.get("target_model")
    if not isinstance(target_model, dict):
        return []

    claim_refs = {str(ref) for ref in claim.provenance_refs if ref}
    claim_edge_refs = {
        edge.ref
        for edge in claim.provenance_edges
        if edge.fact_type == "object_relationship" and edge.ref
    }
    if not claim_refs and not claim_edge_refs:
        return []

    relationships = [
        relationship
        for relationship in target_model.get("relationships", [])
        if _relationship_matches_claim(relationship, claim_refs, claim_edge_refs)
    ]
    return _relationship_context_chains(relationships)


def _relationship_matches_claim(
    relationship: object,
    claim_refs: set[str],
    claim_edge_refs: set[str],
) -> bool:
    if not isinstance(relationship, dict):
        return False
    refs = {
        str(ref)
        for ref in relationship.get("provenance_refs", [])
        if ref
    }
    for edge in relationship.get("provenance_edges", []):
        if isinstance(edge, dict) and edge.get("ref"):
            refs.add(str(edge["ref"]))
    return bool(refs & (claim_refs | claim_edge_refs))


def _relationship_context_chains(relationships: list[dict]) -> list[str]:
    children_by_parent: dict[str, list[str]] = {}
    parents: set[str] = set()
    children: set[str] = set()

    for relationship in relationships:
        if relationship.get("relationship", "contains") != "contains":
            continue
        parent = safe_preview_text(relationship.get("parent_object", ""))
        child = safe_preview_text(relationship.get("child_object", ""))
        if not parent or not child or "[REDACTED]" in {parent, child}:
            continue
        children_by_parent.setdefault(parent, [])
        if child not in children_by_parent[parent]:
            children_by_parent[parent].append(child)
        parents.add(parent)
        children.add(child)

    roots = sorted(parents - children) or sorted(parents)
    contexts: list[str] = []
    for root in roots:
        for path in _relationship_context_paths(root, children_by_parent, []):
            if len(path) < 2:
                continue
            context = ">".join(path)
            if context not in contexts:
                contexts.append(context)
    return contexts


def _relationship_context_paths(
    node: str,
    children_by_parent: dict[str, list[str]],
    path: list[str],
) -> list[list[str]]:
    if node in path:
        return [path]

    next_path = [*path, node]
    children = children_by_parent.get(node, [])
    if not children:
        return [next_path]

    paths: list[list[str]] = []
    for child in sorted(children):
        paths.extend(_relationship_context_paths(child, children_by_parent, next_path))
    return paths


def _pipeline_run_summary(record: PipelineRunRecord) -> MythosPipelineRunSummary:
    payload = record.payload
    return MythosPipelineRunSummary(
        id=record.id,
        program_id=record.program_id,
        asset=record.asset,
        policy_text_hash=record.policy_text_hash,
        scope_status=record.scope_status,
        hypothesis_count=record.hypothesis_count,
        blocked_count=record.blocked_count,
        evidence_count=_count_evidence_items(payload),
        report_title=record.report_title,
        created_at=record.created_at.isoformat(),
        timeline=payload.get("timeline", []),
        artifact=payload.get("artifact"),
        validation_gate=payload.get("validation_gate"),
        hunter_intelligence=payload.get("hunter_intelligence"),
        evidence_support_summary=_evidence_support_summary(record),
    )


def _pipeline_run_detail(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> MythosPipelineRunDetail:
    summary = _pipeline_run_summary(record)
    payload = _pipeline_run_detail_payload(record, repository)
    return MythosPipelineRunDetail(
        id=summary.id,
        program_id=summary.program_id,
        asset=summary.asset,
        policy_text_hash=summary.policy_text_hash,
        scope_status=summary.scope_status,
        hypothesis_count=summary.hypothesis_count,
        blocked_count=summary.blocked_count,
        evidence_count=summary.evidence_count,
        report_title=summary.report_title,
        created_at=summary.created_at,
        timeline=summary.timeline,
        artifact=summary.artifact,
        validation_gate=summary.validation_gate,
        hunter_intelligence=summary.hunter_intelligence,
        evidence_support_summary=summary.evidence_support_summary,
        payload=payload,
    )


def _count_evidence_items(payload: dict) -> int:
    evidence_bundle = payload.get("evidence_bundle")
    if not isinstance(evidence_bundle, dict):
        return 0
    items = evidence_bundle.get("items")
    return len(items) if isinstance(items, list) else 0


def _safe_string_list(value: object) -> list[str]:
    return safe_string_list(value)
