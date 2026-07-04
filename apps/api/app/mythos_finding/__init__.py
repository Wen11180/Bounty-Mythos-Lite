from app.db_models import FindingRecord, PipelineRunRecord
from app.hunter_intelligence import HunterAssessment, recommend_hunter_operating_action
from app.models import Finding
from app.mythos_report import (
    ReportPreviewResponse,
    best_finding_candidate_claim,
    safe_preview_text,
)
from app.repository import DatabaseRepository


def promote_pipeline_run_to_finding_candidate(
    *,
    repository: DatabaseRepository,
    record: PipelineRunRecord,
    preview: ReportPreviewResponse,
) -> Finding:
    claim = best_finding_candidate_claim(preview)
    if claim is None:
        raise ValueError("No claim is ready for candidate promotion")

    assessment = first_hunter_assessment(record.payload.get("hunter_intelligence"))
    if assessment is None:
        raise ValueError("Hunter assessment not found")

    operating_signal = recommend_hunter_operating_action(
        assessment,
        claim_quality_score=claim.quality_score,
        readiness_level=claim.readiness_level,
    )
    operating_reasons = [
        *operating_signal.reasons,
        *candidate_claim_quality_reasons(claim.quality_reasons),
        *candidate_target_relationship_reasons(record.payload, claim),
    ]
    program = repository.get_program(record.program_id) if record.program_id else None
    finding_record = repository.save_finding_candidate(
        id=finding_candidate_id(record.id),
        program_id=record.program_id,
        program=program.name if program else "Unassigned Program",
        asset=record.asset,
        title=preview.title,
        vuln_type=first_hypothesis_value(record.payload, "vuln_type") or assessment.playbook_id,
        severity_estimate=preview.severity,
        confidence=candidate_confidence(claim.quality_score, assessment.hunter_priority_score),
        scope_status=record.scope_status,
        policy_status=candidate_policy_status(assessment, operating_signal.action),
        broken_invariant=candidate_broken_invariant(record.payload),
        validation_status="validation_plan_ready",
        refutation_status=refutation_status(record.payload),
        duplicate_likelihood=duplicate_likelihood_label(assessment.duplicate_risk_score),
        submission_recommendation=operating_signal.action,
        evidence_refs=claim.review_evidence_refs or claim.evidence_refs,
        operating_reasons=operating_reasons,
    )
    return finding_record_response(finding_record)


def first_hunter_assessment(value: object) -> HunterAssessment | None:
    if not isinstance(value, dict):
        return None
    assessments = value.get("assessments", [])
    if not isinstance(assessments, list) or not assessments:
        return None
    first = assessments[0]
    if not isinstance(first, dict):
        return None
    try:
        return HunterAssessment(**first)
    except ValueError:
        return None


def finding_candidate_id(run_id: str) -> str:
    suffix = run_id.removeprefix("pipeline_run_")
    return f"finding_candidate_{suffix}"[:100]


def candidate_confidence(claim_quality_score: int, hunter_priority_score: int) -> float:
    return round(min(0.99, max(0.01, claim_quality_score * 0.006 + hunter_priority_score * 0.003)), 2)


def candidate_policy_status(assessment: HunterAssessment, action: str) -> str:
    if action == "do_not_pursue_policy_blocked":
        return "blocked"
    if assessment.policy_risk_score >= 40:
        return "needs_review"
    return "allowed"


def candidate_broken_invariant(payload: dict) -> str:
    broken_invariant = first_hypothesis_value(payload, "broken_invariant")
    if broken_invariant:
        return broken_invariant
    invariants = payload.get("invariants", [])
    if isinstance(invariants, list):
        for invariant in invariants:
            if isinstance(invariant, dict) and invariant.get("invariant"):
                return safe_preview_text(invariant["invariant"])
    return "Candidate requires human-reviewed invariant mapping."


def first_hypothesis_value(payload: dict, key: str) -> str | None:
    hypotheses = payload.get("hypotheses", [])
    if not isinstance(hypotheses, list):
        return None
    for hypothesis in hypotheses:
        if isinstance(hypothesis, dict) and hypothesis.get(key):
            return safe_preview_text(hypothesis[key])
    return None


def refutation_status(payload: dict) -> str:
    refutation = payload.get("refutation")
    if isinstance(refutation, dict) and refutation.get("status"):
        return safe_preview_text(refutation["status"])
    return "pending"


def duplicate_likelihood_label(score: int) -> str:
    if score >= 50:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def candidate_claim_quality_reasons(quality_reasons: list[str]) -> list[str]:
    reasons: list[str] = []
    if "has_boundary_matrix_observation" in quality_reasons:
        reasons.append("claim_quality:boundary_matrix_observed")
    return reasons


def candidate_target_relationship_reasons(
    payload: dict,
    claim: object,
) -> list[str]:
    target_model = payload.get("target_model")
    if not isinstance(target_model, dict):
        return []

    claim_refs = {
        str(ref)
        for ref in getattr(claim, "provenance_refs", [])
        if ref
    }
    claim_edge_refs = {
        edge.ref
        for edge in getattr(claim, "provenance_edges", [])
        if getattr(edge, "fact_type", "") == "object_relationship" and edge.ref
    }
    relationships = [
        relationship
        for relationship in target_model.get("relationships", [])
        if _relationship_matches_claim(relationship, claim_refs, claim_edge_refs)
    ]
    return [
        f"target_relationship:{context}"
        for context in _relationship_context_chains(relationships)
    ]


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


def finding_record_response(record: FindingRecord) -> Finding:
    return Finding(
        id=record.id,
        program=record.program,
        asset=record.asset,
        title=record.title,
        vuln_type=record.vuln_type,
        severity_estimate=record.severity_estimate,
        confidence=record.confidence,
        scope_status=record.scope_status,
        policy_status=record.policy_status,
        broken_invariant=record.broken_invariant,
        validation_status=record.validation_status,
        refutation_status=record.refutation_status,
        duplicate_likelihood=record.duplicate_likelihood,
        submission_recommendation=record.submission_recommendation,
        evidence_refs=record.evidence_refs,
        operating_reasons=record.operating_reasons,
    )


__all__ = [
    "finding_record_response",
    "promote_pipeline_run_to_finding_candidate",
]
