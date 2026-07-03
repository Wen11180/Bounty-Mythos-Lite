from typing import Any

from pydantic import BaseModel, Field


class HunterPlaybook(BaseModel):
    id: str
    label: str
    match_reason: str
    evidence_focus: list[str]


class HunterAssessment(BaseModel):
    hypothesis: str
    playbook_id: str
    playbook_label: str
    hunter_priority_score: int = Field(ge=0, le=100)
    impact_score: int = Field(ge=0, le=100)
    duplicate_risk_score: int = Field(ge=0, le=100)
    policy_risk_score: int = Field(ge=0, le=100)
    rejection_risk_score: int = Field(ge=0, le=100)
    recommendation: str
    next_action: str
    reasons: list[str]
    evidence_focus: list[str]
    safety_notes: list[str]


class HunterIntelligence(BaseModel):
    top_recommendation: str
    assessments: list[HunterAssessment] = Field(default_factory=list)


_PLAYBOOKS = {
    "bola_idor": HunterPlaybook(
        id="bola_idor",
        label="BOLA / IDOR object boundary",
        match_reason="Object identifier access control with read/export/share behavior.",
        evidence_focus=[
            "two_test_accounts",
            "same_object_id_cross_account_diff",
            "request_response_diff",
        ],
    ),
    "role_boundary": HunterPlaybook(
        id="role_boundary",
        label="Role boundary / privilege escalation",
        match_reason="Member or low-privilege role may cross an admin boundary.",
        evidence_focus=[
            "role_matrix_snapshot",
            "member_vs_admin_request_diff",
            "permission_denial_expected_result",
        ],
    ),
    "money_flow_tampering": HunterPlaybook(
        id="money_flow_tampering",
        label="Server-authoritative money flow",
        match_reason="Payment, invoice, checkout, or refund logic needs server-side authority.",
        evidence_focus=[
            "local_request_review",
            "server_recalculation_evidence",
            "no_real_payment_or_refund",
        ],
    ),
    "generic_logic": HunterPlaybook(
        id="generic_logic",
        label="Generic business logic candidate",
        match_reason="Candidate needs more target understanding before validation.",
        evidence_focus=[
            "provenance_review",
            "scope_guard_review",
            "minimal_safe_reproduction_plan",
        ],
    ),
}


def assess_hunter_intelligence(
    *,
    target_model: dict[str, Any],
    hypotheses: list[dict[str, Any]],
    refutation: dict[str, Any] | None,
) -> HunterIntelligence:
    assessments = [
        _assess_hypothesis(target_model, hypothesis, refutation or {})
        for hypothesis in hypotheses
    ]
    return HunterIntelligence(
        top_recommendation=_top_recommendation(assessments),
        assessments=assessments,
    )


def _assess_hypothesis(
    target_model: dict[str, Any],
    hypothesis: dict[str, Any],
    refutation: dict[str, Any],
) -> HunterAssessment:
    playbook = _match_playbook(target_model, hypothesis)
    impact_score = _impact_score(str(hypothesis.get("risk_level", "medium")), playbook.id)
    duplicate_risk_score = _duplicate_risk_score(playbook.id)
    policy_risk_score = _policy_risk_score(str(hypothesis.get("policy_risk", "medium")))
    rejection_risk_score = _rejection_risk_score(refutation)
    hunter_priority_score = _priority_score(
        impact_score,
        duplicate_risk_score,
        policy_risk_score,
        rejection_risk_score,
    )
    recommendation = _recommendation(
        hunter_priority_score,
        policy_risk_score,
        rejection_risk_score,
        refutation,
    )

    return HunterAssessment(
        hypothesis=str(hypothesis.get("hypothesis", "Untitled hypothesis")),
        playbook_id=playbook.id,
        playbook_label=playbook.label,
        hunter_priority_score=hunter_priority_score,
        impact_score=impact_score,
        duplicate_risk_score=duplicate_risk_score,
        policy_risk_score=policy_risk_score,
        rejection_risk_score=rejection_risk_score,
        recommendation=recommendation,
        next_action=_next_action(recommendation, playbook.id),
        reasons=_reasons(playbook, hypothesis, refutation),
        evidence_focus=playbook.evidence_focus,
        safety_notes=[
            "no_live_requests",
            "test_accounts_only",
            "human_review_required",
            "no_real_user_data",
        ],
    )


def _match_playbook(target_model: dict[str, Any], hypothesis: dict[str, Any]) -> HunterPlaybook:
    text = " ".join(
        [
            str(hypothesis.get("hypothesis", "")),
            str(hypothesis.get("vuln_type", "")),
            str(hypothesis.get("validation_mode", "")),
            " ".join(_target_terms(target_model)),
        ]
    ).lower()

    if any(term in text for term in ("refund", "payment", "invoice", "checkout", "money")):
        return _PLAYBOOKS["money_flow_tampering"]
    if any(term in text for term in ("privilege", "admin", "member", "role", "invite", "settings")):
        return _PLAYBOOKS["role_boundary"]
    if any(term in text for term in ("file", "document", "attachment", "idor", "bola", "object")):
        return _PLAYBOOKS["bola_idor"]
    return _PLAYBOOKS["generic_logic"]


def _target_terms(target_model: dict[str, Any]) -> list[str]:
    terms: list[str] = []
    for item in target_model.get("objects", []):
        if isinstance(item, dict):
            terms.append(str(item.get("name", "")))
        else:
            terms.append(str(item))
    for item in target_model.get("sensitive_actions", []):
        if isinstance(item, dict):
            terms.extend([str(item.get("action", "")), str(item.get("path", ""))])
        else:
            terms.append(str(item))
    return terms


def _impact_score(risk_level: str, playbook_id: str) -> int:
    base_scores = {
        "critical": 95,
        "high": 82,
        "medium": 62,
        "low": 35,
    }
    score = base_scores.get(risk_level.lower(), 55)
    if playbook_id == "money_flow_tampering":
        score = max(score, 95)
    if playbook_id == "bola_idor":
        score = max(score, 85)
    return score


def _duplicate_risk_score(playbook_id: str) -> int:
    scores = {
        "bola_idor": 42,
        "role_boundary": 35,
        "money_flow_tampering": 30,
        "generic_logic": 55,
    }
    return scores.get(playbook_id, 50)


def _policy_risk_score(policy_risk: str) -> int:
    return {
        "low": 15,
        "medium": 45,
        "high": 80,
    }.get(policy_risk.lower(), 45)


def _rejection_risk_score(refutation: dict[str, Any]) -> int:
    reasons = {str(reason) for reason in refutation.get("reasons", [])}
    if reasons & {"out_of_scope", "requires_real_user_data"}:
        return 95
    if reasons & {"self_impact_only", "best_practice_only"}:
        return 85
    if "high_policy_risk" in reasons:
        return 75
    if reasons == {"human_approval_required"}:
        return 30
    if str(refutation.get("status", "passed")) == "blocked" and reasons:
        return 70
    return 15


def _priority_score(
    impact_score: int,
    duplicate_risk_score: int,
    policy_risk_score: int,
    rejection_risk_score: int,
) -> int:
    if rejection_risk_score >= 90:
        return 0

    score = (
        impact_score
        - duplicate_risk_score * 0.25
        - policy_risk_score * 0.35
        - rejection_risk_score * 0.4
    )
    return max(0, min(100, round(score)))


def _recommendation(
    hunter_priority_score: int,
    policy_risk_score: int,
    rejection_risk_score: int,
    refutation: dict[str, Any],
) -> str:
    reasons = {str(reason) for reason in refutation.get("reasons", [])}
    if rejection_risk_score >= 90:
        return "blocked"
    if reasons == {"human_approval_required"}:
        return "needs_human_review"
    if policy_risk_score >= 40:
        return "pursue_with_care"
    if hunter_priority_score >= 55:
        return "pursue"
    return "park"


def _next_action(recommendation: str, playbook_id: str) -> str:
    if recommendation == "blocked":
        return "Do not validate; resolve scope or policy blocker first."
    if recommendation == "needs_human_review":
        return "Prepare human-approved, test-account-only validation."
    if recommendation == "pursue_with_care" and playbook_id == "money_flow_tampering":
        return "Review requests locally before any human-approved validation."
    if recommendation in {"pursue", "pursue_with_care"}:
        return "Collect minimal safe evidence and keep Scope Guard in front."
    return "Park until stronger provenance or impact evidence appears."


def _reasons(
    playbook: HunterPlaybook,
    hypothesis: dict[str, Any],
    refutation: dict[str, Any],
) -> list[str]:
    reasons = [playbook.match_reason]
    risk_level = hypothesis.get("risk_level")
    policy_risk = hypothesis.get("policy_risk")
    if risk_level:
        reasons.append(f"impact:{risk_level}")
    if policy_risk:
        reasons.append(f"policy_risk:{policy_risk}")
    for reason in refutation.get("reasons", []):
        reasons.append(f"refutation:{reason}")
    return reasons


def _top_recommendation(assessments: list[HunterAssessment]) -> str:
    if not assessments:
        return "no_candidates"
    if all(assessment.recommendation == "blocked" for assessment in assessments):
        return "blocked"
    for recommendation in ("pursue", "needs_human_review", "pursue_with_care", "park"):
        if any(assessment.recommendation == recommendation for assessment in assessments):
            return recommendation
    return assessments[0].recommendation


__all__ = [
    "HunterAssessment",
    "HunterIntelligence",
    "HunterPlaybook",
    "assess_hunter_intelligence",
]
