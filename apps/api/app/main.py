from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from app.artifact_ingestion import normalize_artifact
from app.db import get_session
from app.db_models import PipelineRunRecord
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
from pydantic import BaseModel


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


class MythosPipelineRunDetail(MythosPipelineRunSummary):
    payload: dict


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
    response, payload = _build_mythos_pipeline_dry_run(request)
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
) -> tuple[MythosPipelineDryRunResponse, dict]:
    scope_rule = parse_policy_text(request.policy_text, request.asset)
    artifact_kind, openapi_like = _normalize_pipeline_input(request)
    target_model = build_target_model(openapi_like)
    target_model_payload = target_model.model_dump(mode="json")
    invariants = generate_invariants(target_model_payload)
    hypotheses = generate_hypotheses(invariants)

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
    )
    payload = response.model_dump(mode="json", exclude={"run_id"})
    return response, payload


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


def _count_blocked(refutation: RefutationResult | None) -> int:
    return 1 if refutation is not None and refutation.status == "blocked" else 0


def _pipeline_run_summary(record: PipelineRunRecord) -> MythosPipelineRunSummary:
    return MythosPipelineRunSummary(
        id=record.id,
        asset=record.asset,
        policy_text_hash=record.policy_text_hash,
        scope_status=record.scope_status,
        hypothesis_count=record.hypothesis_count,
        blocked_count=record.blocked_count,
        evidence_count=_count_evidence_items(record.payload),
        report_title=record.report_title,
        created_at=record.created_at.isoformat(),
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
        payload=record.payload,
    )


def _count_evidence_items(payload: dict) -> int:
    evidence_bundle = payload.get("evidence_bundle")
    if not isinstance(evidence_bundle, dict):
        return 0
    items = evidence_bundle.get("items")
    return len(items) if isinstance(items, list) else 0
