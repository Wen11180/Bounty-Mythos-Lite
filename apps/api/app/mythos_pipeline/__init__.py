from hashlib import sha256
import json

from pydantic import BaseModel, Field

from app.artifact_ingestion import normalize_artifact
from app.evidence import EvidenceBundle, build_evidence_bundle
from app.hunter_intelligence import (
    HunterAssessment,
    HunterIntelligence,
    assess_hunter_intelligence,
)
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
from app.scope_guard import (
    ScopeGuardDecision,
    ScopeGuardRule,
    ValidationRequest,
    evaluate_validation_request,
)
from app.target_model import TargetModel, build_target_model
from app.validation_workspace import ValidationWorkspace, build_validation_workspace


class MythosPipelineDryRunRequest(BaseModel):
    program_id: str | None = None
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
    details: dict = Field(default_factory=dict)


def bounded_stage(
    *,
    name: str,
    status: str,
    input_summary: str,
    output_summary: str,
    safety_notes: list[str],
    role: str,
    allowed_actions: list[str],
    requires_human_review: bool = False,
    details: dict | None = None,
) -> PipelineStage:
    stage_details = dict(details or {})
    stage_details["agent_boundary"] = {
        "role": role,
        "allowed_actions": allowed_actions,
        "blocked_actions": [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ],
        "requires_human_review": requires_human_review,
    }
    return PipelineStage(
        name=name,
        status=status,
        input_summary=input_summary,
        output_summary=output_summary,
        safety_notes=safety_notes,
        details=stage_details,
    )


class PipelineArtifactSummary(BaseModel):
    artifact_id: str
    kind: str
    source_type: str
    source: str
    provenance: str
    summary: str
    evidence_count: int
    digest: str
    sensitivity_label: str = "unknown"
    redaction_status: str = "unknown"
    report_chain_allowed: bool = False
    safety_blockers: list[str] = Field(default_factory=list)


class PipelineValidationGate(BaseModel):
    status: str
    label: str
    approval_required: bool
    approved_by: str | None = None
    summary: str
    evidence_count: int


class ExploitChainReasoning(BaseModel):
    primitives: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    impact: str
    confidence: float
    safety_notes: list[str] = Field(default_factory=list)


class HypothesisLifecycleAssessment(BaseModel):
    candidate_id: str
    hypothesis_index: int
    hypothesis: VulnerabilityHypothesis
    scope_decision: ScopeGuardDecision
    refutation: RefutationResult
    exploit_chain: ExploitChainReasoning
    validation_plan: ValidationPlan
    report_draft: ReportDraftCandidate
    evidence_hints: list[dict[str, str]] = Field(default_factory=list)
    hunter_assessment: HunterAssessment | None = None
    candidate_status: str


class AutonomousHuntQueueItem(BaseModel):
    queue_id: str
    candidate_id: str
    playbook_id: str
    priority_score: int
    status: str
    next_action: str
    human_approval_required: bool
    blocked_actions: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)


class MythosPipelineDryRunResponse(BaseModel):
    run_id: str | None = None
    program_id: str | None = None
    artifact_kind: str = "openapi"
    scope_rule: ScopeGuardRule
    target_model: TargetModel
    invariants: list[SecurityInvariant]
    hypotheses: list[VulnerabilityHypothesis]
    hypothesis_assessments: list[HypothesisLifecycleAssessment] = Field(default_factory=list)
    refutation: RefutationResult | None
    validation_plan: ValidationPlan | None
    report_draft: ReportDraftCandidate | None
    evidence_bundle: EvidenceBundle | None = None
    timeline: list[PipelineStage]
    artifact: PipelineArtifactSummary | None = None
    validation_workspace: ValidationWorkspace | None = None
    validation_gate: PipelineValidationGate | None = None
    hunter_intelligence: HunterIntelligence | None = None
    autonomous_hunt_queue: list[AutonomousHuntQueueItem] = Field(default_factory=list)


def build_mythos_pipeline_dry_run(
    request: MythosPipelineDryRunRequest,
) -> tuple[MythosPipelineDryRunResponse, dict, dict]:
    scope_rule = parse_policy_text(request.policy_text, request.asset)
    artifact_kind, openapi_like = normalize_pipeline_input(request)
    target_model = build_target_model(openapi_like)
    target_model_payload = target_model.model_dump(mode="json")
    invariants = generate_invariants(target_model_payload)
    hypotheses = generate_hypotheses(invariants)
    hypothesis_assessments = build_hypothesis_lifecycle_assessments(
        asset=request.asset,
        scope_rule=scope_rule,
        target_model_payload=target_model_payload,
        hypotheses=hypotheses,
    )
    top_assessment = select_top_hypothesis_assessment(hypothesis_assessments)

    scope_decision = None
    refutation = None
    validation_plan = None
    report_draft = None
    if top_assessment is not None:
        scope_decision = top_assessment.scope_decision
        refutation = top_assessment.refutation
        validation_plan = top_assessment.validation_plan
        report_draft = top_assessment.report_draft
    evidence_bundle = build_dry_run_evidence_bundle(report_draft, validation_plan)
    validation_workspace = build_dry_run_validation_workspace(
        scope_decision=scope_decision,
        refutation=refutation,
        validation_plan=validation_plan,
        hypotheses=hypotheses,
        hypothesis_assessment=top_assessment,
    )
    validation_gate = build_validation_gate(validation_workspace, evidence_bundle)
    hunter_intelligence = build_hunter_intelligence(hypothesis_assessments)
    autonomous_hunt_queue = build_autonomous_hunt_queue(hypothesis_assessments)
    timeline = build_pipeline_timeline(
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
        hypothesis_assessments=hypothesis_assessments,
    )

    response = MythosPipelineDryRunResponse(
        program_id=request.program_id,
        artifact_kind=artifact_kind,
        scope_rule=scope_rule,
        target_model=target_model,
        invariants=invariants,
        hypotheses=hypotheses,
        hypothesis_assessments=hypothesis_assessments,
        refutation=refutation,
        validation_plan=validation_plan,
        report_draft=report_draft,
        evidence_bundle=evidence_bundle,
        timeline=timeline,
        validation_workspace=validation_workspace,
        validation_gate=validation_gate,
        hunter_intelligence=hunter_intelligence,
        autonomous_hunt_queue=autonomous_hunt_queue,
    )
    payload = response.model_dump(mode="json", exclude={"run_id"})
    return response, payload, openapi_like


def build_hypothesis_lifecycle_assessments(
    *,
    asset: str,
    scope_rule: ScopeGuardRule,
    target_model_payload: dict,
    hypotheses: list[VulnerabilityHypothesis],
) -> list[HypothesisLifecycleAssessment]:
    assessments: list[HypothesisLifecycleAssessment] = []

    for index, hypothesis in enumerate(hypotheses):
        hypothesis_payload = hypothesis.model_dump(mode="json")
        validation_type = hypothesis.validation_mode
        scope_decision = evaluate_validation_request(
            scope_rule,
            ValidationRequest(
                asset=asset,
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
        hunter_intelligence = assess_hunter_intelligence(
            target_model=target_model_payload,
            hypotheses=[hypothesis_payload],
            refutation=refutation.model_dump(mode="json"),
        )
        hunter_assessment = (
            hunter_intelligence.assessments[0]
            if hunter_intelligence.assessments
            else None
        )
        assessments.append(
            HypothesisLifecycleAssessment(
                candidate_id=f"hypothesis_{index + 1}",
                hypothesis_index=index,
                hypothesis=hypothesis,
                scope_decision=scope_decision,
                refutation=refutation,
                exploit_chain=build_exploit_chain_reasoning(hypothesis, refutation),
                validation_plan=validation_plan,
                report_draft=report_draft,
                evidence_hints=[
                    {"type": "evidence_needed", "purpose": evidence}
                    for evidence in hypothesis.evidence_needed
                ],
                hunter_assessment=hunter_assessment,
                candidate_status=candidate_status(refutation, validation_plan),
            )
        )

    return assessments


def build_exploit_chain_reasoning(
    hypothesis: VulnerabilityHypothesis,
    refutation: RefutationResult,
) -> ExploitChainReasoning:
    primitives = _chain_primitives(hypothesis.vuln_type)
    preconditions = [
        "authorized test accounts only",
        "human approval before validation",
        "synthetic fixtures only",
    ]
    if refutation.status == "blocked":
        preconditions.append("refutation blockers resolved before validation")
    confidence = _chain_confidence(hypothesis, refutation)
    return ExploitChainReasoning(
        primitives=primitives,
        preconditions=preconditions,
        impact=_chain_impact(hypothesis),
        confidence=confidence,
        safety_notes=[
            "non_executable_chain_summary",
            "no_payloads_or_requests",
            "human_review_required",
        ],
    )


def _chain_primitives(vuln_type: str) -> list[str]:
    primitives_by_type = {
        "broken_access_control": [
            "identifier authorization boundary",
            "cross-account object access comparison",
        ],
        "privilege_escalation": [
            "role boundary comparison",
            "admin action authorization check",
        ],
        "business_logic_authorization": [
            "server trust boundary",
            "non-destructive parameter review",
        ],
    }
    return primitives_by_type.get(
        vuln_type,
        ["security invariant mismatch", "non-destructive evidence comparison"],
    )


def _chain_impact(hypothesis: VulnerabilityHypothesis) -> str:
    impact_by_risk = {
        "critical": "Potential critical impact if the invariant is broken.",
        "high": "Potential high impact if the invariant is broken.",
        "medium": "Potential medium impact if the invariant is broken.",
        "low": "Potential low impact if the invariant is broken.",
    }
    return impact_by_risk.get(
        hypothesis.risk_level,
        "Potential impact depends on reviewed evidence.",
    )


def _chain_confidence(
    hypothesis: VulnerabilityHypothesis,
    refutation: RefutationResult,
) -> float:
    score = 0.35 if refutation.status == "blocked" else 0.55
    if hypothesis.risk_level in {"high", "critical"}:
        score += 0.1
    if hypothesis.validation_mode in {
        "two_account_authorization_check",
        "role_based_authorization_check",
    }:
        score += 0.05
    return min(score, 0.85)


def select_top_hypothesis_assessment(
    assessments: list[HypothesisLifecycleAssessment],
) -> HypothesisLifecycleAssessment | None:
    if not assessments:
        return None
    return sorted(
        assessments,
        key=lambda item: (
            item.hunter_assessment.hunter_priority_score
            if item.hunter_assessment is not None
            else 0,
            item.hunter_assessment.impact_score
            if item.hunter_assessment is not None
            else 0,
            -item.hypothesis_index,
        ),
        reverse=True,
    )[0]


def build_hunter_intelligence(
    assessments: list[HypothesisLifecycleAssessment],
) -> HunterIntelligence:
    hunter_assessments = [
        item.hunter_assessment
        for item in assessments
        if item.hunter_assessment is not None
    ]
    return HunterIntelligence(
        top_recommendation=top_hunter_recommendation(hunter_assessments),
        assessments=hunter_assessments,
    )


def top_hunter_recommendation(assessments: list[HunterAssessment]) -> str:
    if not assessments:
        return "no_candidates"
    if all(assessment.recommendation == "blocked" for assessment in assessments):
        return "blocked"
    for recommendation in ("pursue", "needs_human_review", "pursue_with_care", "park"):
        if any(assessment.recommendation == recommendation for assessment in assessments):
            return recommendation
    return assessments[0].recommendation


def build_autonomous_hunt_queue(
    assessments: list[HypothesisLifecycleAssessment],
) -> list[AutonomousHuntQueueItem]:
    sorted_assessments = sorted(
        assessments,
        key=lambda item: (
            item.hunter_assessment.hunter_priority_score
            if item.hunter_assessment is not None
            else 0,
            -item.hypothesis_index,
        ),
        reverse=True,
    )
    queue: list[AutonomousHuntQueueItem] = []
    for assessment in sorted_assessments:
        if not _scope_decision_allows_queueing(assessment.scope_decision):
            continue
        hunter_assessment = assessment.hunter_assessment
        priority_score = (
            hunter_assessment.hunter_priority_score
            if hunter_assessment is not None
            else 0
        )
        playbook_id = (
            hunter_assessment.playbook_id
            if hunter_assessment is not None
            else "unknown_playbook"
        )
        human_approval_required = (
            assessment.validation_plan.human_approval_required
            or assessment.scope_decision.reason == "human_approval_required"
        )
        queue.append(
            AutonomousHuntQueueItem(
                queue_id=f"hunt_queue_{assessment.candidate_id}",
                candidate_id=assessment.candidate_id,
                playbook_id=playbook_id,
                priority_score=priority_score,
                status=(
                    "awaiting_human_approval"
                    if human_approval_required
                    else assessment.candidate_status
                ),
                next_action=(
                    "review_validation_plan"
                    if human_approval_required
                    else "review_refutation"
                ),
                human_approval_required=human_approval_required,
                blocked_actions=[
                    "execute_live_validation",
                    "touch_real_user_data",
                    "submit_report",
                    "bypass_scope_guard",
                ],
                safety_notes=[
                    "scope_guard_required",
                    "non_destructive_validation_only",
                    "human_review_required",
                ],
            )
        )
    return queue


def _scope_decision_allows_queueing(scope_decision: ScopeGuardDecision) -> bool:
    return scope_decision.allowed or scope_decision.reason == "human_approval_required"


def candidate_status(
    refutation: RefutationResult,
    validation_plan: ValidationPlan,
) -> str:
    hard_blockers = {
        "out_of_scope",
        "forbidden_validation",
        "validation_not_allowed",
        "requires_real_user_data",
        "high_policy_risk",
        "self_impact_only",
        "best_practice_only",
    }
    reasons = set(refutation.reasons)
    if reasons & hard_blockers:
        return "blocked"
    if "human_approval_required" in reasons:
        return "awaiting_human_approval"
    return validation_plan.status


def normalize_pipeline_input(request: MythosPipelineDryRunRequest) -> tuple[str, dict]:
    if request.artifact_kind is not None or request.artifact_payload is not None:
        if request.artifact_kind is None or request.artifact_payload is None:
            raise ValueError("artifact_kind and artifact_payload must be provided together")
        artifact = normalize_artifact(request.artifact_kind, request.artifact_payload)
        return artifact.kind, artifact.openapi_like

    if request.openapi is None:
        raise ValueError("openapi or artifact_kind/artifact_payload is required")
    return "openapi", normalize_artifact("openapi", request.openapi).openapi_like


def build_dry_run_evidence_bundle(
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


def build_dry_run_validation_workspace(
    *,
    scope_decision: ScopeGuardDecision | None,
    refutation: RefutationResult | None,
    validation_plan: ValidationPlan | None,
    hypotheses: list[VulnerabilityHypothesis],
    hypothesis_assessment: HypothesisLifecycleAssessment | None = None,
) -> ValidationWorkspace | None:
    if validation_plan is None or refutation is None or scope_decision is None:
        return None

    evidence_hints = (
        hypothesis_assessment.evidence_hints
        if hypothesis_assessment is not None
        else [
            {"type": "evidence_needed", "purpose": item}
            for item in (hypotheses[0].evidence_needed if hypotheses else [])
        ]
    )
    return build_validation_workspace(
        validation_plan=validation_plan.model_dump(mode="json"),
        scope_decision=scope_decision.model_dump(mode="json"),
        refutation=refutation.model_dump(mode="json"),
        evidence_hints=evidence_hints,
        human_approved=False,
    )


def build_validation_gate(
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


def artifact_source_hash(
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


def artifact_payload_summary(openapi_like: dict, target_model: TargetModel) -> dict:
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
        "relationship_count": len(target_model.relationships),
    }


def count_blocked(
    refutation: RefutationResult | list[HypothesisLifecycleAssessment] | None,
) -> int:
    if isinstance(refutation, list):
        return sum(1 for item in refutation if item.refutation.status == "blocked")
    return 1 if refutation is not None and refutation.status == "blocked" else 0


def build_pipeline_timeline(
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
    hypothesis_assessments: list[HypothesisLifecycleAssessment],
) -> list[PipelineStage]:
    path_count = len(openapi_like.get("paths", {}))

    if refutation is None:
        refutation_stage = bounded_stage(
            name="refutation",
            status="skipped",
            input_summary="No hypotheses available.",
            output_summary="No refutation performed.",
            safety_notes=["no_live_requests"],
            role="Refutation Agent",
            allowed_actions=["review_candidate_against_scope", "record_block_reasons"],
        )
    else:
        scope_notes = []
        if scope_decision is not None and not scope_decision.allowed:
            scope_notes.append(f"scope_guard:{scope_decision.reason}")
        if refutation.human_review_required:
            scope_notes.append("human_review_required")
        refutation_stage = bounded_stage(
            name="refutation",
            status=refutation.status,
            input_summary=(
                f"First hypothesis validation mode: {hypotheses[0].validation_mode}."
            ),
            output_summary=(
                f"Refutation {refutation.status}; reasons: "
                f"{', '.join(refutation.reasons) if refutation.reasons else 'none'}."
            ),
            safety_notes=safety_notes(scope_notes, ["no_live_requests"]),
            role="Refutation Agent",
            allowed_actions=["review_candidate_against_scope", "record_block_reasons"],
            requires_human_review=refutation.human_review_required,
        )

    if validation_plan is None:
        validation_plan_stage = bounded_stage(
            name="validation_plan",
            status="skipped",
            input_summary=f"{len(hypotheses)} hypothesis/hypotheses.",
            output_summary="No validation plan generated.",
            safety_notes=["no_live_requests"],
            role="Validation Planner Agent",
            allowed_actions=["draft_non_destructive_manual_steps", "record_evidence_needs"],
        )
    else:
        validation_plan_stage = bounded_stage(
            name="validation_plan",
            status=validation_plan.status,
            input_summary=f"{len(hypotheses)} hypothesis/hypotheses.",
            output_summary=(
                f"{validation_plan.status}; {len(validation_plan.steps)} step(s) planned."
            ),
            safety_notes=safety_notes(
                ["no_live_requests"],
                ["human_approval_required"]
                if validation_plan.human_approval_required
                else [],
            ),
            role="Validation Planner Agent",
            allowed_actions=["draft_non_destructive_manual_steps", "record_evidence_needs"],
            requires_human_review=validation_plan.human_approval_required,
        )

    if report_draft is None:
        report_draft_stage = bounded_stage(
            name="report_draft",
            status="skipped",
            input_summary="No validation plan available.",
            output_summary="No report draft generated.",
            safety_notes=["human_review_required"],
            role="Report Agent",
            allowed_actions=["draft_report_preview", "separate_claim_types"],
            requires_human_review=True,
        )
    else:
        report_draft_stage = bounded_stage(
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
            safety_notes=safety_notes(
                report_draft.safety_notes,
                ["human_review_required"] if report_draft.human_review_required else [],
            ),
            role="Report Agent",
            allowed_actions=["draft_report_preview", "separate_claim_types"],
            requires_human_review=report_draft.human_review_required,
        )

    if evidence_bundle is None:
        evidence_stage = bounded_stage(
            name="evidence",
            status="skipped",
            input_summary="No report draft available.",
            output_summary="No evidence bundle generated.",
            safety_notes=["no_live_requests"],
            role="Evidence Agent",
            allowed_actions=["bundle_redacted_evidence_refs", "preserve_provenance_refs"],
        )
    else:
        evidence_stage = bounded_stage(
            name="evidence",
            status="completed",
            input_summary=evidence_bundle.finding_id,
            output_summary=f"Bundled {len(evidence_bundle.items)} evidence item(s).",
            safety_notes=safety_notes(evidence_bundle.safety_notes, ["no_live_requests"]),
            role="Evidence Agent",
            allowed_actions=["bundle_redacted_evidence_refs", "preserve_provenance_refs"],
        )

    return [
        bounded_stage(
            name="policy_ingestion",
            status="completed",
            input_summary=f"Policy text for {request.asset}.",
            output_summary=(
                f"Scope status {scope_rule.scope_status}; automation {scope_rule.automation}."
            ),
            safety_notes=safety_notes(
                ["human_review_required"] if scope_rule.human_approval_required else [],
                [f"forbidden:{item}" for item in scope_rule.forbidden],
            ),
            role="Policy Agent",
            allowed_actions=["parse_program_policy", "record_scope_constraints"],
            requires_human_review=scope_rule.human_approval_required,
        ),
        bounded_stage(
            name="artifact_normalization",
            status="completed",
            input_summary=f"Dry-run {artifact_kind} artifact.",
            output_summary=f"Normalized {path_count} path(s).",
            safety_notes=["local_artifact_only", "no_live_requests"],
            role="Artifact Agent",
            allowed_actions=["normalize_authorized_artifact", "record_source_digest"],
        ),
        bounded_stage(
            name="target_model",
            status="completed",
            input_summary=f"Normalized {artifact_kind} paths.",
            output_summary=(
                f"{len(target_model.endpoints)} endpoint(s), "
                f"{len(target_model.objects)} object(s), "
                f"{len(target_model.sensitive_actions)} sensitive action(s)."
            ),
            safety_notes=["static_analysis_only"],
            role="Target Modeling Agent",
            allowed_actions=["extract_static_target_facts", "link_provenance_edges"],
        ),
        bounded_stage(
            name="invariants",
            status="completed",
            input_summary="Target model facts.",
            output_summary=f"Generated {len(invariants)} security invariant(s).",
            safety_notes=["policy_risk_preserved"],
            role="Invariant Agent",
            allowed_actions=["derive_security_invariants", "preserve_policy_risk"],
        ),
        bounded_stage(
            name="hypotheses",
            status="completed",
            input_summary=f"{len(invariants)} security invariant(s).",
            output_summary=(
                f"Generated {len(hypotheses)} vulnerability candidate(s); "
                f"assessed {len(hypothesis_assessments)} candidate lifecycle(s)."
            ),
            safety_notes=[
                "non_destructive_candidates_only",
                "non_executable_chain_summary",
            ],
            role="Hypothesis Agent",
            allowed_actions=["generate_candidates", "attach_evidence_requirements"],
            details={
                "reasoning_summary": hypothesis_reasoning_summary(
                    hypothesis_assessments,
                ),
            },
        ),
        refutation_stage,
        validation_plan_stage,
        report_draft_stage,
        evidence_stage,
    ]


def safety_notes(*groups: list[str]) -> list[str]:
    notes: list[str] = []
    for group in groups:
        for note in group:
            if note not in notes:
                notes.append(note)
    return notes


def hypothesis_reasoning_summary(
    assessments: list[HypothesisLifecycleAssessment],
) -> dict[str, int]:
    return {
        "chain_mapped_count": sum(
            1 for assessment in assessments if assessment.exploit_chain.primitives
        ),
        "refutation_question_count": sum(
            len(assessment.refutation.questions) for assessment in assessments
        ),
        "human_review_required_count": sum(
            1 for assessment in assessments if assessment.refutation.human_review_required
        ),
    }


__all__ = [
    "MythosPipelineDryRunRequest",
    "MythosPipelineDryRunResponse",
    "PipelineArtifactSummary",
    "PipelineStage",
    "PipelineValidationGate",
    "artifact_payload_summary",
    "artifact_source_hash",
    "build_mythos_pipeline_dry_run",
    "count_blocked",
]
