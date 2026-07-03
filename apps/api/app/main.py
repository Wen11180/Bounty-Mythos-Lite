from hashlib import sha256
import json

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from app.artifact_ingestion import normalize_artifact
from app.db import get_session
from app.db_models import ArtifactRecord, PipelineRunRecord
from app.evidence import EvidenceBundle, build_evidence_bundle
from app.llm.base import LLMRequest, LLMResponse
from app.llm.registry import UnknownProviderError, build_default_registry
from app.models import Finding, Program, ReportDraft
from app.mythos_hypothesis import (
    SecurityInvariant,
    VulnerabilityHypothesis,
    generate_hypotheses,
    generate_invariants,
)
from app.mythos_triage import (
    RefutationResult,
    ReportDraftCandidate,
    ValidationPlan,
    build_report_draft,
    build_validation_plan,
    refute_hypothesis,
)
from app.policy_ingestion import parse_policy_text
from app.repository import DatabaseRepository
from app.scope_guard import (
    ScopeGuardDecision,
    ScopeGuardRule,
    ValidationRequest,
    evaluate_validation_request,
)
from app.target_model import TargetModel, build_target_model
from app.validation_workspace import ValidationWorkspace, build_validation_workspace
from pydantic import BaseModel, Field


app = FastAPI(title="Bounty Mythos-Lite API")


class ScopeGuardEvaluationRequest(BaseModel):
    rule: ScopeGuardRule
    request: ValidationRequest


class MythosPipelineDryRunRequest(BaseModel):
    asset: str
    policy_text: str
    openapi: dict | None = None
    artifact_kind: str | None = None
    artifact_payload: dict | None = None


class PipelineStage(BaseModel):
    name: str
    status: str
    input_summary: str
    output_summary: str
    safety_notes: list[str]


class PipelineArtifactSummary(BaseModel):
    artifact_id: str
    kind: str
    source_type: str
    source: str
    provenance: str
    summary: str
    evidence_count: int
    digest: str


class PipelineValidationGate(BaseModel):
    status: str
    label: str
    approval_required: bool
    approved_by: str | None = None
    summary: str
    evidence_count: int


class MythosPipelineDryRunResponse(BaseModel):
    run_id: str | None = None
    artifact_kind: str = "openapi"
    scope_rule: ScopeGuardRule
    target_model: TargetModel
    invariants: list[SecurityInvariant]
    hypotheses: list[VulnerabilityHypothesis]
    refutation: RefutationResult | None
    validation_plan: ValidationPlan | None
    report_draft: ReportDraftCandidate | None
    evidence_bundle: EvidenceBundle | None = None
    timeline: list[PipelineStage]
    artifact: PipelineArtifactSummary | None = None
    validation_workspace: ValidationWorkspace | None = None
    validation_gate: PipelineValidationGate | None = None


class MythosPipelineRunSummary(BaseModel):
    id: str
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
    created_at: str


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
def list_mythos_artifacts(session: Session = Depends(get_session)) -> list[ArtifactResponse]:
    return [_artifact_response(record) for record in DatabaseRepository(session).list_artifacts()]


@app.get("/mythos/artifacts/{artifact_id}", response_model=ArtifactResponse)
def get_mythos_artifact(
    artifact_id: str,
    session: Session = Depends(get_session),
) -> ArtifactResponse:
    record = DatabaseRepository(session).get_artifact(artifact_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _artifact_response(record)


@app.post("/internal/llm/generate", response_model=LLMResponse)
async def generate_with_llm(request: LLMRequest) -> LLMResponse:
    registry = build_default_registry()
    try:
        response = await registry.generate(request)
    except UnknownProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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
    response, payload, openapi_like = _build_mythos_pipeline_dry_run(request)
    artifact_record = repository.save_artifact(
        program_id=None,
        asset=request.asset,
        kind=response.artifact_kind,
        source_type="dry_run_inline",
        source_hash=_artifact_source_hash(request, response.artifact_kind),
        ingestion_status="normalized",
        provenance={
            "source": "dry-run inline artifact",
            "asset": request.asset,
            "kind": response.artifact_kind,
        },
        payload_summary=_artifact_payload_summary(openapi_like, response.target_model),
        derived_facts={
            "paths": sorted(openapi_like.get("paths", {}).keys()),
            "objects": [item.name for item in response.target_model.objects],
            "sensitive_actions": [
                item.model_dump(mode="json")
                for item in response.target_model.sensitive_actions
            ],
        },
    )
    response.artifact = _pipeline_artifact_summary(
        artifact_record,
        evidence_count=_count_evidence_items(payload),
    )
    payload["artifact"] = response.artifact.model_dump(mode="json")
    record = repository.save_pipeline_run(
        asset=request.asset,
        policy_text=request.policy_text,
        scope_status=response.scope_rule.scope_status,
        hypothesis_count=len(response.hypotheses),
        blocked_count=_count_blocked(response.refutation),
        report_title=response.report_draft.title if response.report_draft else None,
        payload=payload,
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
    record = DatabaseRepository(session).get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return _pipeline_run_detail(record)


def _build_mythos_pipeline_dry_run(
    request: MythosPipelineDryRunRequest,
) -> tuple[MythosPipelineDryRunResponse, dict, dict]:
    scope_rule = parse_policy_text(request.policy_text, request.asset)
    artifact_kind, openapi_like = _normalize_pipeline_input(request)
    target_model = build_target_model(openapi_like)
    target_model_payload = target_model.model_dump(mode="json")
    invariants = generate_invariants(target_model_payload)
    hypotheses = generate_hypotheses(invariants)

    scope_decision = None
    refutation = None
    validation_plan = None
    report_draft = None
    if hypotheses:
        hypothesis_payload = hypotheses[0].model_dump(mode="json")
        validation_type = hypothesis_payload["validation_mode"]
        scope_decision = evaluate_validation_request(
            scope_rule,
            ValidationRequest(
                asset=request.asset,
                validation_type=validation_type,
                human_approved=False,
            ),
        )
        refutation = refute_hypothesis(
            hypothesis_payload,
            scope_decision.model_dump(mode="json"),
        )
        validation_plan = build_validation_plan(hypothesis_payload, refutation)
        report_draft = build_report_draft(hypothesis_payload, validation_plan, refutation)
    evidence_bundle = _build_dry_run_evidence_bundle(report_draft, validation_plan)
    validation_workspace = _build_dry_run_validation_workspace(
        scope_decision=scope_decision,
        refutation=refutation,
        validation_plan=validation_plan,
        hypotheses=hypotheses,
    )
    validation_gate = _build_validation_gate(validation_workspace, evidence_bundle)
    timeline = _build_pipeline_timeline(
        request=request,
        artifact_kind=artifact_kind,
        openapi_like=openapi_like,
        scope_rule=scope_rule,
        target_model=target_model,
        invariants=invariants,
        hypotheses=hypotheses,
        scope_decision=scope_decision,
        refutation=refutation,
        validation_plan=validation_plan,
        report_draft=report_draft,
        evidence_bundle=evidence_bundle,
    )

    response = MythosPipelineDryRunResponse(
        artifact_kind=artifact_kind,
        scope_rule=scope_rule,
        target_model=target_model,
        invariants=invariants,
        hypotheses=hypotheses,
        refutation=refutation,
        validation_plan=validation_plan,
        report_draft=report_draft,
        evidence_bundle=evidence_bundle,
        timeline=timeline,
        validation_workspace=validation_workspace,
        validation_gate=validation_gate,
    )
    payload = response.model_dump(mode="json", exclude={"run_id"})
    return response, payload, openapi_like


def _normalize_pipeline_input(request: MythosPipelineDryRunRequest) -> tuple[str, dict]:
    if request.artifact_kind is not None or request.artifact_payload is not None:
        if request.artifact_kind is None or request.artifact_payload is None:
            raise HTTPException(
                status_code=422,
                detail="artifact_kind and artifact_payload must be provided together",
            )
        try:
            artifact = normalize_artifact(request.artifact_kind, request.artifact_payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return artifact.kind, artifact.openapi_like

    if request.openapi is None:
        raise HTTPException(
            status_code=422,
            detail="openapi or artifact_kind/artifact_payload is required",
        )
    return "openapi", normalize_artifact("openapi", request.openapi).openapi_like


def _build_dry_run_evidence_bundle(
    report_draft: ReportDraftCandidate | None,
    validation_plan: ValidationPlan | None,
) -> EvidenceBundle | None:
    if report_draft is None or validation_plan is None:
        return None
    return build_evidence_bundle(
        "dry_run_candidate",
        [
            {
                "type": "request_response_diff",
                "content": {
                    "status": validation_plan.status,
                    "steps": validation_plan.steps,
                    "note": "Dry-run placeholder; no live request was executed.",
                },
            }
        ],
    )


def _build_dry_run_validation_workspace(
    *,
    scope_decision: ScopeGuardDecision | None,
    refutation: RefutationResult | None,
    validation_plan: ValidationPlan | None,
    hypotheses: list[VulnerabilityHypothesis],
) -> ValidationWorkspace | None:
    if validation_plan is None or refutation is None or scope_decision is None:
        return None

    evidence_hints = [
        {"type": "evidence_needed", "purpose": item}
        for item in (hypotheses[0].evidence_needed if hypotheses else [])
    ]
    return build_validation_workspace(
        validation_plan=validation_plan.model_dump(mode="json"),
        scope_decision=scope_decision.model_dump(mode="json"),
        refutation=refutation.model_dump(mode="json"),
        evidence_hints=evidence_hints,
        human_approved=False,
    )


def _build_validation_gate(
    workspace: ValidationWorkspace | None,
    evidence_bundle: EvidenceBundle | None,
) -> PipelineValidationGate | None:
    if workspace is None:
        return None

    evidence_count = len(evidence_bundle.items) if evidence_bundle else 0
    return PipelineValidationGate(
        status=workspace.approval_gate.status,
        label=workspace.approval_gate.reason,
        approval_required=workspace.approval_gate.human_approval_required,
        approved_by=None,
        summary=(
            "Validation workspace is prepared for human-controlled review; "
            "no live execution is allowed by this dry-run."
        ),
        evidence_count=evidence_count,
    )


def _artifact_source_hash(
    request: MythosPipelineDryRunRequest,
    artifact_kind: str,
) -> str:
    source_payload = request.artifact_payload if request.artifact_payload is not None else request.openapi
    serialized = json.dumps(
        {
            "asset": request.asset,
            "kind": artifact_kind,
            "payload": source_payload,
        },
        default=str,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(serialized.encode("utf-8")).hexdigest()


def _artifact_payload_summary(openapi_like: dict, target_model: TargetModel) -> dict:
    paths = openapi_like.get("paths", {})
    endpoint_count = 0
    if isinstance(paths, dict):
        for path_item in paths.values():
            if isinstance(path_item, dict):
                endpoint_count += len(path_item)

    return {
        "path_count": len(paths) if isinstance(paths, dict) else 0,
        "endpoint_count": endpoint_count,
        "object_count": len(target_model.objects),
        "sensitive_action_count": len(target_model.sensitive_actions),
    }


def _pipeline_artifact_summary(
    record: ArtifactRecord,
    *,
    evidence_count: int,
) -> PipelineArtifactSummary:
    source = str(record.provenance.get("source", "dry-run inline artifact"))
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
    )


def _artifact_response(record: ArtifactRecord) -> ArtifactResponse:
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
        created_at=record.created_at.isoformat(),
    )


def _build_pipeline_timeline(
    *,
    request: MythosPipelineDryRunRequest,
    artifact_kind: str,
    openapi_like: dict,
    scope_rule: ScopeGuardRule,
    target_model: TargetModel,
    invariants: list[SecurityInvariant],
    hypotheses: list[VulnerabilityHypothesis],
    scope_decision: ScopeGuardDecision | None,
    refutation: RefutationResult | None,
    validation_plan: ValidationPlan | None,
    report_draft: ReportDraftCandidate | None,
    evidence_bundle: EvidenceBundle | None,
) -> list[PipelineStage]:
    path_count = len(openapi_like.get("paths", {}))

    if refutation is None:
        refutation_stage = PipelineStage(
            name="refutation",
            status="skipped",
            input_summary="No hypotheses available.",
            output_summary="No refutation performed.",
            safety_notes=["no_live_requests"],
        )
    else:
        scope_notes = []
        if scope_decision is not None and not scope_decision.allowed:
            scope_notes.append(f"scope_guard:{scope_decision.reason}")
        if refutation.human_review_required:
            scope_notes.append("human_review_required")
        refutation_stage = PipelineStage(
            name="refutation",
            status=refutation.status,
            input_summary=(
                f"First hypothesis validation mode: {hypotheses[0].validation_mode}."
            ),
            output_summary=(
                f"Refutation {refutation.status}; reasons: "
                f"{', '.join(refutation.reasons) if refutation.reasons else 'none'}."
            ),
            safety_notes=_safety_notes(scope_notes, ["no_live_requests"]),
        )

    if validation_plan is None:
        validation_plan_stage = PipelineStage(
            name="validation_plan",
            status="skipped",
            input_summary=f"{len(hypotheses)} hypothesis/hypotheses.",
            output_summary="No validation plan generated.",
            safety_notes=["no_live_requests"],
        )
    else:
        validation_plan_stage = PipelineStage(
            name="validation_plan",
            status=validation_plan.status,
            input_summary=f"{len(hypotheses)} hypothesis/hypotheses.",
            output_summary=(
                f"{validation_plan.status}; {len(validation_plan.steps)} step(s) planned."
            ),
            safety_notes=_safety_notes(
                ["no_live_requests"],
                ["human_approval_required"]
                if validation_plan.human_approval_required
                else [],
            ),
        )

    if report_draft is None:
        report_draft_stage = PipelineStage(
            name="report_draft",
            status="skipped",
            input_summary="No validation plan available.",
            output_summary="No report draft generated.",
            safety_notes=["human_review_required"],
        )
    else:
        report_draft_stage = PipelineStage(
            name="report_draft",
            status=(
                "human_review_required"
                if report_draft.human_review_required
                else "completed"
            ),
            input_summary=(
                f"Validation result for {report_draft.severity} severity candidate."
            ),
            output_summary=f"Drafted report candidate: {report_draft.title}.",
            safety_notes=_safety_notes(
                report_draft.safety_notes,
                ["human_review_required"] if report_draft.human_review_required else [],
            ),
        )

    if evidence_bundle is None:
        evidence_stage = PipelineStage(
            name="evidence",
            status="skipped",
            input_summary="No report draft available.",
            output_summary="No evidence bundle generated.",
            safety_notes=["no_live_requests"],
        )
    else:
        evidence_stage = PipelineStage(
            name="evidence",
            status="completed",
            input_summary=evidence_bundle.finding_id,
            output_summary=f"Bundled {len(evidence_bundle.items)} evidence item(s).",
            safety_notes=_safety_notes(evidence_bundle.safety_notes, ["no_live_requests"]),
        )

    return [
        PipelineStage(
            name="policy_ingestion",
            status="completed",
            input_summary=f"Policy text for {request.asset}.",
            output_summary=(
                f"Scope status {scope_rule.scope_status}; automation {scope_rule.automation}."
            ),
            safety_notes=_safety_notes(
                ["human_review_required"] if scope_rule.human_approval_required else [],
                [f"forbidden:{item}" for item in scope_rule.forbidden],
            ),
        ),
        PipelineStage(
            name="artifact_normalization",
            status="completed",
            input_summary=f"Dry-run {artifact_kind} artifact.",
            output_summary=f"Normalized {path_count} path(s).",
            safety_notes=["local_artifact_only", "no_live_requests"],
        ),
        PipelineStage(
            name="target_model",
            status="completed",
            input_summary=f"Normalized {artifact_kind} paths.",
            output_summary=(
                f"{len(target_model.endpoints)} endpoint(s), "
                f"{len(target_model.objects)} object(s), "
                f"{len(target_model.sensitive_actions)} sensitive action(s)."
            ),
            safety_notes=["static_analysis_only"],
        ),
        PipelineStage(
            name="invariants",
            status="completed",
            input_summary="Target model facts.",
            output_summary=f"Generated {len(invariants)} security invariant(s).",
            safety_notes=["policy_risk_preserved"],
        ),
        PipelineStage(
            name="hypotheses",
            status="completed",
            input_summary=f"{len(invariants)} security invariant(s).",
            output_summary=f"Generated {len(hypotheses)} vulnerability candidate(s).",
            safety_notes=["non_destructive_candidates_only"],
        ),
        refutation_stage,
        validation_plan_stage,
        report_draft_stage,
        evidence_stage,
    ]


def _safety_notes(*groups: list[str]) -> list[str]:
    notes: list[str] = []
    for group in groups:
        for note in group:
            if note not in notes:
                notes.append(note)
    return notes


def _count_blocked(refutation: RefutationResult | None) -> int:
    return 1 if refutation is not None and refutation.status == "blocked" else 0


def _pipeline_run_summary(record: PipelineRunRecord) -> MythosPipelineRunSummary:
    payload = record.payload
    return MythosPipelineRunSummary(
        id=record.id,
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
    )


def _pipeline_run_detail(record: PipelineRunRecord) -> MythosPipelineRunDetail:
    summary = _pipeline_run_summary(record)
    return MythosPipelineRunDetail(
        id=summary.id,
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
        payload=record.payload,
    )


def _count_evidence_items(payload: dict) -> int:
    evidence_bundle = payload.get("evidence_bundle")
    if not isinstance(evidence_bundle, dict):
        return 0
    items = evidence_bundle.get("items")
    return len(items) if isinstance(items, list) else 0
