import re
from typing import Literal

from pydantic import BaseModel, Field

from app.db_models import PipelineRunRecord
from app.provenance import ProvenanceEdge


class ReportPreviewSections(BaseModel):
    observed_facts: list[str] = Field(default_factory=list)
    model_reasoning: list[str] = Field(default_factory=list)
    unverified_claims: list[str] = Field(default_factory=list)


ClaimReadinessLevel = Literal[
    "needs_human_review",
    "human_reviewed_gated",
    "needs_evidence",
    "model_reasoning_only",
    "unverified_claim",
    "not_reportable",
    "ready_for_human_review",
]

ClaimReviewDecisionValue = Literal[
    "confirmed_observed_fact",
    "needs_evidence",
    "refuted",
    "not_reportable",
]

PROMOTION_BLOCKING_READINESS_BLOCKERS = {
    "artifact_report_chain_blocked",
    "missing_security_impact_observation",
}

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
SECURITY_IMPACT_OBSERVATION_TYPES = {
    "request_response_diff",
    "role_matrix_observation",
}
REPORT_SAFE_REVIEW_EVIDENCE_REFS = {
    "local_code_reference",
    "log_ref",
    "request_response_diff",
    "role_matrix_snapshot",
    "sanitized_cross_account_diff",
    "sanitized_parent_child_matrix",
    "sanitized_request_response",
    "sanitized_role_matrix",
    "screenshot_ref",
}
BLACK_BOX_REVIEW_EVIDENCE_REFS = {
    "sanitized_cross_account_diff",
    "sanitized_parent_child_matrix",
}


def build_black_box_report_review_packet(candidate: dict) -> dict:
    """Build a review-only packet from a redacted black-box candidate."""
    if not isinstance(candidate, dict):
        raise ValueError("black_box_candidate_required")
    if candidate.get("status") != "review_ready":
        raise ValueError("review_ready_candidate_required")
    if candidate.get("human_review_required") is not True:
        raise ValueError("human_review_required")
    if candidate.get("submission_blocked") is not True:
        raise ValueError("submission_blocked_required")
    if any(
        candidate.get(field) is not False
        for field in (
            "human_confirmed",
            "finding_promotion_allowed",
            "execution_allowed",
            "validation_allowed",
            "report_submission_allowed",
            "submitted",
        )
    ):
        raise ValueError("black_box_candidate_permissions_must_be_false")
    raw_evidence_refs = candidate.get("evidence_refs")
    if not isinstance(raw_evidence_refs, list):
        raise ValueError("sanitized_black_box_evidence_required")
    evidence_refs = [safe_preview_text(ref) for ref in raw_evidence_refs]
    if not evidence_refs or any(
        ref not in BLACK_BOX_REVIEW_EVIDENCE_REFS for ref in evidence_refs
    ):
        raise ValueError("sanitized_black_box_evidence_required")
    route = candidate.get("route") if isinstance(candidate.get("route"), dict) else {}
    method = safe_preview_text(route.get("method", ""))
    path = safe_preview_text(route.get("path", ""))
    if not method or not path or "?" in path:
        raise ValueError("normalized_black_box_route_required")

    return {
        "candidate_id": safe_preview_text(candidate.get("candidate_id", "")),
        "status": "review_ready",
        "human_review_required": True,
        "submission_blocked": True,
        "human_confirmed": False,
        "finding_promotion_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "submitted": False,
        "evidence_refs": evidence_refs,
        "next_allowed_action": "Human review of redacted differential evidence.",
        "report_draft": {
            "title": "Potential authorization-boundary issue",
            "severity": "unconfirmed",
            "affected_route": f"{method} {path}",
            "safety_notes": [
                "submission_blocked",
                "not_human_confirmed",
                "redacted_local_lab_evidence_only",
            ],
        },
    }


class ClaimLedgerEntry(BaseModel):
    claim_id: str
    claim_type: str
    text: str
    status: str
    quality_score: int = Field(ge=0, le=100)
    quality_reasons: list[str] = Field(default_factory=list)
    readiness_level: ClaimReadinessLevel
    evidence_refs: list[str] = Field(default_factory=list)
    provenance_refs: list[str] = Field(default_factory=list)
    provenance_edges: list[ProvenanceEdge] = Field(default_factory=list)
    redaction_status: str
    human_review_required: bool
    readiness_blockers: list[str] = Field(default_factory=list)
    review_status: str = "unreviewed"
    reviewer: str | None = None
    review_rationale: str | None = None
    reviewed_at: str | None = None
    review_evidence_refs: list[str] = Field(default_factory=list)


class ReportPreviewResponse(BaseModel):
    run_id: str
    title: str
    severity: str
    scope_status: str
    human_review_required: bool
    submission_blocked: bool
    claim_labels: dict[str, str]
    sections: ReportPreviewSections
    claim_ledger: list[ClaimLedgerEntry]
    safety_notes: list[str]
    evidence_refs: list[str]
    safety_gate_summary: dict = Field(default_factory=dict)
    audit_gate_summary: dict = Field(default_factory=dict)


class ClaimReviewDecisionResponse(BaseModel):
    claim_id: str
    decision: ClaimReviewDecisionValue
    reviewer: str
    rationale: str
    evidence_refs: list[str] = Field(default_factory=list)
    reviewed_at: str


def build_report_preview_response(record: PipelineRunRecord) -> ReportPreviewResponse:
    payload = record.payload
    report_draft = payload.get("report_draft")
    if not isinstance(report_draft, dict):
        raise ValueError("Report draft not found")

    validation_gate = payload.get("validation_gate") if isinstance(payload.get("validation_gate"), dict) else {}
    evidence_bundle = payload.get("evidence_bundle") if isinstance(payload.get("evidence_bundle"), dict) else {}
    evidence_items = evidence_bundle.get("items", []) if isinstance(evidence_bundle, dict) else []
    hypotheses = payload.get("hypotheses", []) if isinstance(payload.get("hypotheses"), list) else []
    invariants = payload.get("invariants", []) if isinstance(payload.get("invariants"), list) else []
    timeline = payload.get("timeline", []) if isinstance(payload.get("timeline"), list) else []
    review_decisions = latest_claim_review_decisions(payload.get("claim_review_decisions", []))
    provenance_refs_by_claim_type = claim_provenance_refs_by_type(record)
    provenance_edges_by_claim_type = claim_provenance_edges_by_type(record)
    report_chain_blocked_refs = artifact_report_chain_blocked_refs(payload)
    manual_evidence_refs_by_claim = manual_observation_evidence_refs_by_claim(payload)
    evidence_refs = safe_evidence_bundle_refs(evidence_items)
    supported_observation_refs = unique_preview_refs(
        safe_preview_lines([
            *REPORT_SAFE_REVIEW_EVIDENCE_REFS,
            *evidence_refs,
        ])
    )
    impact_evidence_refs_by_claim = security_impact_observation_evidence_refs_by_claim(
        payload,
        supported_evidence_refs=supported_observation_refs,
    )
    impact_observation_claim_ids = set(impact_evidence_refs_by_claim)
    boundary_matrix_observation_claim_ids = (
        security_boundary_matrix_observation_claim_ids(
            payload,
            supported_evidence_refs=supported_observation_refs,
        )
    )
    manual_observation_missing_safe_evidence_claim_ids = (
        manual_observation_claim_ids_missing_safe_evidence(payload)
    )

    human_review_required = True
    submission_blocked = True
    sections = ReportPreviewSections(
        observed_facts=safe_preview_lines(
            observed_fact_lines(
                record,
                timeline,
                evidence_items,
                payload,
                supported_evidence_refs=supported_observation_refs,
            )
        ),
        model_reasoning=safe_preview_lines(
            model_reasoning_lines(hypotheses, invariants)
        ),
        unverified_claims=safe_preview_lines(
            unverified_claim_lines(report_draft, validation_gate)
        ),
    )

    return ReportPreviewResponse(
        run_id=record.id,
        title=safe_preview_text(
            report_draft.get("title", record.report_title or "Untitled report preview")
        ),
        severity=safe_preview_text(report_draft.get("severity", "unknown")),
        scope_status=safe_preview_text(report_draft.get("scope_status", record.scope_status)),
        human_review_required=human_review_required,
        submission_blocked=submission_blocked,
        claim_labels={
            "observed_facts": "observed_fact",
            "model_reasoning": "model_reasoning",
            "unverified_claims": "unverified_claim",
        },
        sections=sections,
        claim_ledger=claim_ledger_entries(
            sections=sections,
            run_id=record.id,
            evidence_refs=evidence_refs,
            human_review_required=human_review_required,
            validation_gate=validation_gate,
            review_decisions=review_decisions,
            provenance_refs_by_claim_type=provenance_refs_by_claim_type,
            provenance_edges_by_claim_type=provenance_edges_by_claim_type,
            report_chain_blocked_refs=report_chain_blocked_refs,
            manual_evidence_refs_by_claim=manual_evidence_refs_by_claim,
            impact_evidence_refs_by_claim=impact_evidence_refs_by_claim,
            impact_observation_claim_ids=impact_observation_claim_ids,
            boundary_matrix_observation_claim_ids=boundary_matrix_observation_claim_ids,
            manual_observation_missing_safe_evidence_claim_ids=(
                manual_observation_missing_safe_evidence_claim_ids
            ),
        ),
        safety_notes=safe_string_list(report_draft.get("safety_notes", [])),
        evidence_refs=evidence_refs,
        safety_gate_summary=(
            payload.get("safety_gate_summary")
            if isinstance(payload.get("safety_gate_summary"), dict)
            else {}
        ),
        audit_gate_summary=(
            payload.get("audit_gate_summary")
            if isinstance(payload.get("audit_gate_summary"), dict)
            else {}
        ),
    )


def best_finding_candidate_claim(preview: ReportPreviewResponse) -> ClaimLedgerEntry | None:
    candidates = [
        claim
        for claim in preview.claim_ledger
        if claim.claim_type == "observed_fact"
        and claim.review_status == "confirmed_observed_fact"
        and review_evidence_refs_are_report_safe(claim.review_evidence_refs)
        and claim.quality_score >= 80
        and claim.readiness_level in {
            "human_reviewed_gated",
            "needs_human_review",
            "ready_for_human_review",
        }
        and not (
            PROMOTION_BLOCKING_READINESS_BLOCKERS
            & set(claim.readiness_blockers)
        )
    ]
    if not candidates:
        return None
    return sorted(candidates, key=lambda claim: (-claim.quality_score, claim.claim_id))[0]


def observed_fact_lines(
    record: PipelineRunRecord,
    timeline: list,
    evidence_items: list,
    payload: dict | None = None,
    supported_evidence_refs: list[str] | None = None,
) -> list[str]:
    lines = [
        f"Pipeline run {record.id} was created for asset {record.asset}.",
        f"Scope status recorded as {record.scope_status}.",
        f"{len(evidence_items)} sanitized evidence item(s) are attached to this run.",
    ]
    for stage in timeline:
        if isinstance(stage, dict):
            name = stage.get("name")
            status = stage.get("status")
            if name and status:
                lines.append(f"Stage {name} recorded status {status}.")
    if payload is not None:
        lines.extend(
            security_impact_observation_lines(
                payload,
                supported_evidence_refs=supported_evidence_refs,
            )
        )
    return lines


def model_reasoning_lines(hypotheses: list, invariants: list) -> list[str]:
    lines: list[str] = []
    for invariant in invariants:
        if isinstance(invariant, dict) and invariant.get("invariant"):
            lines.append(f"Invariant considered: {invariant['invariant']}.")
    for hypothesis in hypotheses:
        if isinstance(hypothesis, dict) and hypothesis.get("hypothesis"):
            lines.append(f"Candidate reasoning: {hypothesis['hypothesis']}")
    return lines or ["No model reasoning was recorded for this run."]


def unverified_claim_lines(report_draft: dict, validation_gate: dict) -> list[str]:
    lines = [
        str(report_draft.get("actual_result", "Actual result still requires safe validation evidence.")),
        "This preview is not submission-ready until human review approves the validation evidence.",
    ]
    gate_status = validation_gate.get("status")
    if gate_status and gate_status != "approved":
        lines.append(f"Validation gate is {gate_status}; live execution remains blocked.")
    return lines


def claim_provenance_refs_by_type(record: PipelineRunRecord) -> dict[str, list[str]]:
    payload = record.payload
    artifact_refs = artifact_provenance_refs(payload)
    target_refs = target_model_provenance_refs(payload)

    return {
        "observed_fact": unique_preview_refs([f"run:{record.id}", *artifact_refs, *target_refs]),
        "model_reasoning": unique_preview_refs(["hypothesis_engine", *target_refs]),
        "unverified_claim": unique_preview_refs(
            ["report_draft", "validation_gate", *artifact_refs]
        ),
    }


def claim_provenance_edges_by_type(record: PipelineRunRecord) -> dict[str, list[ProvenanceEdge]]:
    target_edges = target_model_provenance_edges(record.payload)
    return {
        "observed_fact": target_edges,
        "model_reasoning": target_edges,
        "unverified_claim": [],
    }


def artifact_provenance_refs(payload: dict) -> list[str]:
    artifact = payload.get("artifact")
    if not isinstance(artifact, dict):
        return []

    refs: list[str] = []
    artifact_id = artifact.get("artifact_id")
    if artifact_id:
        refs.append(str(artifact_id))
    digest = artifact.get("digest")
    if digest:
        refs.append(f"artifact_digest:{digest}")
    return refs


def artifact_report_chain_blocked_refs(payload: dict) -> list[str]:
    artifact = payload.get("artifact")
    if not isinstance(artifact, dict):
        return []
    if artifact.get("report_chain_allowed") is True:
        return []
    return artifact_provenance_refs(payload)


def manual_observation_evidence_refs_by_claim(payload: dict) -> dict[str, list[str]]:
    observations = payload.get("manual_observations", [])
    if not isinstance(observations, list):
        return {}

    refs_by_claim: dict[str, list[str]] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        claim_id = safe_preview_text(observation.get("claim_id", ""))
        if not claim_id:
            continue
        refs = [
            ref
            for ref in safe_string_list(observation.get("evidence_refs", []))
            if ref != "[REDACTED]"
        ]
        if not refs:
            continue
        refs_by_claim[claim_id] = unique_preview_refs([
            *refs_by_claim.get(claim_id, []),
            *refs,
        ])
    return refs_by_claim


def manual_observation_claim_ids_missing_safe_evidence(payload: dict) -> set[str]:
    observations = payload.get("manual_observations", [])
    if not isinstance(observations, list):
        return set()

    observed_claim_ids: set[str] = set()
    claims_with_safe_refs: set[str] = set()
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        claim_id = safe_preview_text(observation.get("claim_id", ""))
        if not claim_id:
            continue
        observed_claim_ids.add(claim_id)
        refs = [
            ref
            for ref in safe_string_list(observation.get("evidence_refs", []))
            if ref != "[REDACTED]"
        ]
        if refs:
            claims_with_safe_refs.add(claim_id)

    return observed_claim_ids - claims_with_safe_refs


def security_impact_observation_claim_ids(
    payload: dict,
    *,
    supported_evidence_refs: list[str] | None = None,
) -> set[str]:
    return set(
        security_impact_observation_evidence_refs_by_claim(
            payload,
            supported_evidence_refs=supported_evidence_refs,
        )
    )


def security_impact_observation_evidence_refs_by_claim(
    payload: dict,
    *,
    supported_evidence_refs: list[str] | None = None,
) -> dict[str, list[str]]:
    observations = payload.get("manual_observations", [])
    if not isinstance(observations, list):
        return {}

    supported_refs = set(supported_evidence_refs or REPORT_SAFE_REVIEW_EVIDENCE_REFS)
    refs_by_claim: dict[str, list[str]] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        if observation.get("observation_type") not in SECURITY_IMPACT_OBSERVATION_TYPES:
            continue
        claim_id = safe_preview_text(observation.get("claim_id", ""))
        if not claim_id:
            continue
        safe_refs = [
            ref
            for ref in safe_string_list(observation.get("evidence_refs", []))
            if ref != "[REDACTED]" and ref in supported_refs
        ]
        if safe_refs:
            refs_by_claim[claim_id] = unique_preview_refs([
                *refs_by_claim.get(claim_id, []),
                *safe_refs,
            ])
    return refs_by_claim


def security_boundary_matrix_observation_claim_ids(
    payload: dict,
    *,
    supported_evidence_refs: list[str] | None = None,
) -> set[str]:
    target_model = payload.get("target_model")
    if not isinstance(target_model, dict):
        return set()
    relationships = target_model.get("relationships", [])
    if not isinstance(relationships, list) or not relationships:
        return set()

    observations = payload.get("manual_observations", [])
    if not isinstance(observations, list):
        return set()

    supported_refs = set(supported_evidence_refs or REPORT_SAFE_REVIEW_EVIDENCE_REFS)
    claim_ids: set[str] = set()
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        if observation.get("observation_type") != "role_matrix_observation":
            continue
        claim_id = safe_preview_text(observation.get("claim_id", ""))
        if not claim_id:
            continue
        safe_refs = [
            ref
            for ref in safe_string_list(observation.get("evidence_refs", []))
            if ref != "[REDACTED]" and ref in supported_refs
        ]
        if safe_refs:
            claim_ids.add(claim_id)
    return claim_ids


def security_impact_observation_lines(
    payload: dict,
    *,
    supported_evidence_refs: list[str] | None = None,
) -> list[str]:
    observations = payload.get("manual_observations", [])
    if not isinstance(observations, list):
        return []

    supported_refs = set(supported_evidence_refs or REPORT_SAFE_REVIEW_EVIDENCE_REFS)
    lines: list[str] = []
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        observation_type = safe_preview_text(observation.get("observation_type", ""))
        if observation_type not in SECURITY_IMPACT_OBSERVATION_TYPES:
            continue
        claim_id = safe_preview_text(observation.get("claim_id", ""))
        if not claim_id:
            continue
        safe_refs = [
            ref
            for ref in safe_string_list(observation.get("evidence_refs", []))
            if ref != "[REDACTED]" and ref in supported_refs
        ]
        if not safe_refs:
            continue
        lines.append(
            "Security impact observation "
            f"{observation_type} was recorded for {claim_id} "
            f"with evidence {', '.join(unique_preview_refs(safe_refs))}."
        )
    return lines


def target_model_provenance_edges(payload: dict) -> list[ProvenanceEdge]:
    target_model = payload.get("target_model")
    if not isinstance(target_model, dict):
        return []

    edges: list[ProvenanceEdge] = []
    for key in ("endpoints", "objects", "sensitive_actions", "relationships"):
        for item in target_model.get(key, []):
            if isinstance(item, dict):
                edges.extend(
                    _safe_provenance_edge(edge)
                    for edge in item.get("provenance_edges", [])
                    if isinstance(edge, dict)
                )
    return _unique_provenance_edges(edges)


def target_model_provenance_refs(payload: dict) -> list[str]:
    target_model = payload.get("target_model")
    if not isinstance(target_model, dict):
        return []

    refs: list[str] = []
    for key in ("endpoints", "objects", "sensitive_actions", "relationships"):
        for item in target_model.get(key, []):
            if isinstance(item, dict):
                refs.extend(str(ref) for ref in item.get("provenance_refs", []) if ref)
    return refs


def claim_ledger_entries(
    *,
    sections: ReportPreviewSections,
    run_id: str,
    evidence_refs: list[str],
    human_review_required: bool,
    validation_gate: dict,
    review_decisions: dict[str, ClaimReviewDecisionResponse],
    provenance_refs_by_claim_type: dict[str, list[str]] | None = None,
    provenance_edges_by_claim_type: dict[str, list[ProvenanceEdge]] | None = None,
    report_chain_blocked_refs: list[str] | None = None,
    manual_evidence_refs_by_claim: dict[str, list[str]] | None = None,
    impact_evidence_refs_by_claim: dict[str, list[str]] | None = None,
    impact_observation_claim_ids: set[str] | None = None,
    boundary_matrix_observation_claim_ids: set[str] | None = None,
    manual_observation_missing_safe_evidence_claim_ids: set[str] | None = None,
) -> list[ClaimLedgerEntry]:
    entries: list[ClaimLedgerEntry] = []
    provenance_refs_by_claim_type = provenance_refs_by_claim_type or {}
    provenance_edges_by_claim_type = provenance_edges_by_claim_type or {}
    report_chain_blocked_refs = report_chain_blocked_refs or []
    manual_evidence_refs_by_claim = manual_evidence_refs_by_claim or {}
    impact_evidence_refs_by_claim = impact_evidence_refs_by_claim or {}
    impact_observation_claim_ids = impact_observation_claim_ids or set()
    boundary_matrix_observation_claim_ids = boundary_matrix_observation_claim_ids or set()
    manual_observation_missing_safe_evidence_claim_ids = (
        manual_observation_missing_safe_evidence_claim_ids or set()
    )
    claim_groups = (
        (
            "observed_fact",
            sections.observed_facts,
            evidence_refs,
            provenance_refs_by_claim_type.get("observed_fact", [f"run:{run_id}"]),
            provenance_edges_by_claim_type.get("observed_fact", []),
        ),
        (
            "model_reasoning",
            sections.model_reasoning,
            [],
            provenance_refs_by_claim_type.get("model_reasoning", ["hypothesis_engine"]),
            provenance_edges_by_claim_type.get("model_reasoning", []),
        ),
        (
            "unverified_claim",
            sections.unverified_claims,
            [],
            provenance_refs_by_claim_type.get(
                "unverified_claim",
                ["report_draft", "validation_gate"],
            ),
            provenance_edges_by_claim_type.get("unverified_claim", []),
        ),
    )

    for claim_type, lines, group_evidence_refs, provenance_refs, provenance_edges in claim_groups:
        for index, line in enumerate(lines, start=1):
            claim_id = f"claim_{claim_type}_{index}"
            review_decision = review_decisions.get(claim_id)
            manual_evidence_refs = manual_evidence_refs_by_claim.get(claim_id, [])
            impact_evidence_refs = impact_evidence_refs_by_claim.get(claim_id, [])
            supported_review_refs = unique_preview_refs(
                safe_preview_lines([
                    *REPORT_SAFE_REVIEW_EVIDENCE_REFS,
                    *group_evidence_refs,
                    *impact_evidence_refs,
                ])
            )
            if not claim_review_decision_supported_for_claim(
                claim_type=claim_type,
                review_decision=review_decision,
                has_supported_manual_evidence=bool(impact_evidence_refs),
                supported_evidence_refs=supported_review_refs,
            ):
                review_decision = None
            review_evidence_refs = []
            if review_decision is not None:
                review_evidence_refs = review_decision.evidence_refs
            safe_text = safe_preview_text(line)
            safe_evidence_refs = unique_preview_refs(
                safe_preview_lines([*group_evidence_refs, *manual_evidence_refs])
            )
            safe_provenance_refs = safe_preview_lines(provenance_refs)
            blockers = claim_readiness_blockers(
                claim_type=claim_type,
                evidence_refs=safe_evidence_refs,
                provenance_refs=safe_provenance_refs,
                human_review_required=human_review_required,
                validation_gate=validation_gate,
                report_chain_blocked_refs=report_chain_blocked_refs,
                has_security_impact_observation=(
                    claim_id in impact_observation_claim_ids
                ),
            )
            quality_score, quality_reasons, readiness_level = claim_quality(
                claim_type=claim_type,
                evidence_refs=safe_evidence_refs,
                provenance_refs=safe_provenance_refs,
                readiness_blockers=blockers,
                review_decision=review_decision,
                has_manual_observation=bool(manual_evidence_refs),
                has_security_impact_observation=(
                    claim_id in impact_observation_claim_ids
                ),
                has_boundary_matrix_observation=(
                    claim_id in boundary_matrix_observation_claim_ids
                ),
                has_manual_observation_missing_safe_evidence=(
                    claim_id in manual_observation_missing_safe_evidence_claim_ids
                ),
            )
            entries.append(
                ClaimLedgerEntry(
                    claim_id=claim_id,
                    claim_type=claim_type,
                    text=safe_text,
                    status=claim_status(claim_type, blockers),
                    quality_score=quality_score,
                    quality_reasons=quality_reasons,
                    readiness_level=readiness_level,
                    evidence_refs=safe_evidence_refs,
                    provenance_refs=safe_provenance_refs,
                    provenance_edges=provenance_edges,
                    redaction_status="redacted",
                    human_review_required=human_review_required,
                    readiness_blockers=blockers,
                    review_status=(
                        review_decision.decision if review_decision is not None else "unreviewed"
                    ),
                    reviewer=review_decision.reviewer if review_decision is not None else None,
                    review_rationale=(
                        review_decision.rationale if review_decision is not None else None
                    ),
                    reviewed_at=review_decision.reviewed_at if review_decision is not None else None,
                    review_evidence_refs=review_evidence_refs,
                )
            )

    return entries


def claim_review_decision_supported_for_claim(
    *,
    claim_type: str,
    review_decision: ClaimReviewDecisionResponse | None,
    has_supported_manual_evidence: bool = False,
    supported_evidence_refs: list[str] | None = None,
) -> bool:
    if review_decision is None:
        return True
    if review_decision.decision != "confirmed_observed_fact":
        return True
    if claim_type != "observed_fact":
        return False
    if review_decision.evidence_refs:
        return (
            review_evidence_refs_are_report_safe(review_decision.evidence_refs)
            and set(review_decision.evidence_refs) <= set(supported_evidence_refs or [])
        )
    return has_supported_manual_evidence


def claim_quality(
    *,
    claim_type: str,
    evidence_refs: list[str],
    provenance_refs: list[str],
    readiness_blockers: list[str],
    review_decision: ClaimReviewDecisionResponse | None,
    has_manual_observation: bool = False,
    has_security_impact_observation: bool = False,
    has_boundary_matrix_observation: bool = False,
    has_manual_observation_missing_safe_evidence: bool = False,
) -> tuple[int, list[str], ClaimReadinessLevel]:
    score = 0
    reasons: list[str] = []

    if claim_type == "observed_fact":
        score += 25
        reasons.append("type:observed_fact")
    elif claim_type == "model_reasoning":
        score += 10
        reasons.append("type:model_reasoning")
    else:
        reasons.append("type:unverified_claim")

    if evidence_refs:
        score += 25
        reasons.append("has_evidence_refs")
    else:
        reasons.append("missing_evidence_refs")

    if provenance_refs:
        score += 20
        reasons.append("has_provenance_refs")
    else:
        reasons.append("missing_provenance_refs")

    score += 10
    reasons.append("redaction:redacted")

    if review_decision is None:
        reasons.append("review:unreviewed")
    else:
        reasons.append(f"review:{review_decision.decision}")
        if review_decision.decision == "confirmed_observed_fact":
            score += 15
        elif review_decision.decision == "needs_evidence":
            score -= 10
        elif review_decision.decision in {"refuted", "not_reportable"}:
            score -= 30
        safe_review_refs = safe_report_refs(review_decision.evidence_refs)
        if safe_review_refs:
            score += 10
            reasons.append("review:evidence_refs")
        elif review_decision.evidence_refs:
            reasons.append("review:redacted_evidence_refs")

    if "human_review_required" in readiness_blockers:
        reasons.append("gate:human_review_required")
    if "validation_gate_not_approved" in readiness_blockers:
        reasons.append("gate:validation_gate_not_approved")
    if "artifact_report_chain_blocked" in readiness_blockers:
        reasons.append("gate:artifact_report_chain_blocked")
    if "missing_security_impact_observation" in readiness_blockers:
        reasons.append("impact:missing_security_impact_observation")
    if has_manual_observation:
        reasons.append("has_manual_observation")
    if has_security_impact_observation:
        reasons.append("has_security_impact_observation")
    if has_boundary_matrix_observation:
        reasons.append("has_boundary_matrix_observation")
    if has_manual_observation_missing_safe_evidence:
        reasons.append("manual_observation_missing_safe_evidence")

    return (
        max(0, min(100, score)),
        reasons,
        claim_readiness_level(
            claim_type=claim_type,
            readiness_blockers=readiness_blockers,
            review_decision=review_decision,
        ),
    )


def claim_readiness_level(
    *,
    claim_type: str,
    readiness_blockers: list[str],
    review_decision: ClaimReviewDecisionResponse | None,
) -> ClaimReadinessLevel:
    if review_decision is not None and review_decision.decision in {"refuted", "not_reportable"}:
        return "not_reportable"
    if claim_type == "model_reasoning":
        return "model_reasoning_only"
    if claim_type == "unverified_claim":
        return "unverified_claim"
    if review_decision is not None and review_decision.decision == "needs_evidence":
        return "needs_evidence"
    if "missing_evidence_refs" in readiness_blockers or "missing_provenance_refs" in readiness_blockers:
        return "needs_evidence"
    if review_decision is not None and review_decision.decision == "confirmed_observed_fact":
        return "human_reviewed_gated"
    if "human_review_required" in readiness_blockers:
        return "needs_human_review"
    return "ready_for_human_review"


def latest_claim_review_decisions(value: object) -> dict[str, ClaimReviewDecisionResponse]:
    if not isinstance(value, list):
        return {}

    decisions: dict[str, ClaimReviewDecisionResponse] = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        try:
            decision = ClaimReviewDecisionResponse(
                claim_id=safe_preview_text(item.get("claim_id", "")),
                decision=item.get("decision"),
                reviewer=safe_preview_text(item.get("reviewer", "")),
                rationale=safe_preview_text(item.get("rationale", "")),
                evidence_refs=safe_string_list(item.get("evidence_refs", [])),
                reviewed_at=safe_preview_text(item.get("reviewed_at", "")),
            )
        except ValueError:
            continue
        decisions[decision.claim_id] = decision
    return decisions


def claim_readiness_blockers(
    *,
    claim_type: str,
    evidence_refs: list[str],
    provenance_refs: list[str],
    human_review_required: bool,
    validation_gate: dict,
    report_chain_blocked_refs: list[str] | None = None,
    has_security_impact_observation: bool = False,
) -> list[str]:
    blockers: list[str] = []
    report_chain_blocked_refs = report_chain_blocked_refs or []
    if claim_type != "observed_fact":
        blockers.append(f"{claim_type}_not_observed_fact")
    if not evidence_refs:
        blockers.append("missing_evidence_refs")
    if not provenance_refs:
        blockers.append("missing_provenance_refs")
    if human_review_required:
        blockers.append("human_review_required")
    if validation_gate.get("status") != "approved":
        blockers.append("validation_gate_not_approved")
    if set(provenance_refs) & set(report_chain_blocked_refs):
        blockers.append("artifact_report_chain_blocked")
    if claim_type == "observed_fact" and not has_security_impact_observation:
        blockers.append("missing_security_impact_observation")
    return [safe_preview_text(blocker) for blocker in blockers]


def claim_status(claim_type: str, readiness_blockers: list[str]) -> str:
    if claim_type == "observed_fact" and readiness_blockers:
        return "needs_human_review"
    if claim_type == "observed_fact":
        return "ready_for_human_review"
    if claim_type == "model_reasoning":
        return "model_reasoning_only"
    return "blocked"


def safe_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [safe_preview_text(item) for item in value]


def safe_preview_lines(lines: list[str]) -> list[str]:
    return [safe_preview_text(line) for line in lines]


def safe_preview_text(value: object) -> str:
    text = str(value)
    lowered = text.lower()
    secret_markers = (
        "authorization:",
        "api-key:",
        "bearer ",
        "cookie:",
        "set-cookie:",
        "policy_text",
        "api_key",
        "apikey",
        "password",
        "credential",
        "session=",
        "secret",
        "token",
        "x-api-key:",
        "real user data",
        "customer data",
        "production user",
        "live user",
        "personal data",
        "pii",
    )
    if (
        any(marker in lowered for marker in secret_markers)
        or re.search(r"\bsk-[a-z0-9]", lowered) is not None
        or EMAIL_PATTERN.search(text)
        or JWT_PATTERN.search(text)
    ):
        return "[REDACTED]"
    return text


def unique_preview_refs(values: list[str]) -> list[str]:
    refs: list[str] = []
    for value in values:
        safe_value = safe_preview_text(value)
        if safe_value not in refs:
            refs.append(safe_value)
    return refs


def safe_report_refs(values: list[str]) -> list[str]:
    return [value for value in values if value != "[REDACTED]"]


def safe_evidence_bundle_refs(evidence_items: object) -> list[str]:
    if not isinstance(evidence_items, list):
        return []
    refs: list[str] = []
    for item in evidence_items:
        if not isinstance(item, dict):
            continue
        ref = safe_preview_text(item.get("type", "evidence_item"))
        if ref not in REPORT_SAFE_REVIEW_EVIDENCE_REFS:
            continue
        if ref not in refs:
            refs.append(ref)
    return refs


def review_evidence_refs_are_report_safe(values: list[str]) -> bool:
    return bool(values) and len(safe_report_refs(values)) == len(values)


def _safe_provenance_edge(value: dict) -> ProvenanceEdge:
    return ProvenanceEdge(
        ref=safe_preview_text(value.get("ref", "")),
        source_type=safe_preview_text(value.get("source_type", "")),
        stage=safe_preview_text(value.get("stage", "")),
        source_path=safe_preview_text(value.get("source_path", "")),
        source_method=(
            safe_preview_text(value["source_method"])
            if value.get("source_method") is not None
            else None
        ),
        fact_type=safe_preview_text(value.get("fact_type", "")),
    )


def _unique_provenance_edges(values: list[ProvenanceEdge]) -> list[ProvenanceEdge]:
    edges: list[ProvenanceEdge] = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        key = (value.ref, value.fact_type)
        if key not in seen:
            seen.add(key)
            edges.append(value)
    return edges


__all__ = [
    "ClaimLedgerEntry",
    "ClaimReadinessLevel",
    "ClaimReviewDecisionResponse",
    "ClaimReviewDecisionValue",
    "ReportPreviewResponse",
    "ReportPreviewSections",
    "best_finding_candidate_claim",
    "build_report_preview_response",
    "safe_preview_lines",
    "safe_preview_text",
    "safe_string_list",
]
