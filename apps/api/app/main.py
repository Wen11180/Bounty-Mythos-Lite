from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from app.db import get_session
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
    openapi: dict


class MythosPipelineDryRunResponse(BaseModel):
    scope_rule: ScopeGuardRule
    target_model: TargetModel
    invariants: list[SecurityInvariant]
    hypotheses: list[VulnerabilityHypothesis]
    refutation: RefutationResult | None
    validation_plan: ValidationPlan | None
    report_draft: ReportDraftCandidate | None


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
) -> MythosPipelineDryRunResponse:
    scope_rule = parse_policy_text(request.policy_text, request.asset)
    target_model = build_target_model(request.openapi)
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

    return MythosPipelineDryRunResponse(
        scope_rule=scope_rule,
        target_model=target_model,
        invariants=invariants,
        hypotheses=hypotheses,
        refutation=refutation,
        validation_plan=validation_plan,
        report_draft=report_draft,
    )
