"""Bridge retained A+B hunter cards into submission-blocked report draft candidates.

Lawful research only:
- Does not execute validation
- Does not submit reports
- Does not promote model output to confirmed findings
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.mythos_triage import (
    ReportDraftCandidate,
    RefutationResult,
    SAFE_VALIDATION_METHODS,
    ValidationPlan,
    build_report_draft,
    build_validation_plan,
)
from app.validation_workspace import build_validation_workspace
from app.falsification_engine import (
    project_falsification_summary,
    validate_falsification_card,
)
from app.advisory_static_engines import (
    ENGINE_CODEQL,
    ENGINE_SEMGREP,
    build_advisory_signals_for_candidate,
    load_package_advisory_bundle,
)
from app.multi_engine_verifier import verdict_from_hunter_and_map
from app.patch_suggestion import build_patch_suggestion


class CandidateReportBridgeError(ValueError):
    pass


def _falsification_summary_for_report_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    card = candidate.get("falsification_card")
    if isinstance(card, dict) and not validate_falsification_card(card):
        return project_falsification_summary(card)
    return project_falsification_summary(None)


def retained_candidates_from_normalized_output(
    normalized_output: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if not isinstance(normalized_output, dict):
        return []
    finals = normalized_output.get("final_candidates")
    if not isinstance(finals, list):
        return []
    retained: list[dict[str, Any]] = []
    for item in finals:
        if not isinstance(item, dict):
            continue
        # Only bridge retained terminal cards. Refuted/deduped should not appear in finals.
        if item.get("report_submission_allowed") is True:
            raise CandidateReportBridgeError("report_submission_allowed_must_be_false")
        if item.get("execution_allowed") is True:
            raise CandidateReportBridgeError("execution_allowed_must_be_false")
        if item.get("validation_allowed") is True:
            raise CandidateReportBridgeError("validation_allowed_must_be_false")
        retained.append(item)
    return retained


def candidate_to_hypothesis(candidate: dict[str, Any]) -> dict[str, Any]:
    route = candidate.get("route") if isinstance(candidate.get("route"), dict) else {}
    method = str(route.get("method") or "").upper()
    path = str(route.get("path") or "")
    route_label = f"{method} {path}".strip() or "unknown_route"
    root = str(candidate.get("root_cause_id") or "unknown_root")
    vuln_type = str(candidate.get("vuln_type") or "authorization")
    code_path = str(candidate.get("affected_code_path") or "")
    card = (
        candidate.get("falsification_card")
        if isinstance(candidate.get("falsification_card"), dict)
        else {}
    )
    summary = (
        candidate.get("falsification_summary")
        if isinstance(candidate.get("falsification_summary"), dict)
        else {}
    )
    broken_invariant = (
        str(candidate.get("broken_invariant") or "").strip()
        or str(card.get("broken_invariant") or "").strip()
        or str(summary.get("broken_invariant") or "").strip()
        or "Object access must enforce ownership/authorization before sensitive sinks."
    )
    why_still_alive = candidate.get("why_still_alive")
    if not isinstance(why_still_alive, list):
        why_still_alive = summary.get("why_still_alive")
    if not isinstance(why_still_alive, list) and isinstance(card.get("decision"), dict):
        why_still_alive = card["decision"].get("why_still_alive")
    if not isinstance(why_still_alive, list):
        why_still_alive = []
    validation_mode = str(
        candidate.get("validation_mode") or "non_destructive_request_review"
    ).strip()
    if validation_mode not in SAFE_VALIDATION_METHODS:
        validation_mode = "non_destructive_request_review"
    evidence_needed = candidate.get("evidence_needed")
    if not isinstance(evidence_needed, list):
        evidence_needed = list(candidate.get("source_fact_refs") or [])[:12]
    impact_rationale = str(candidate.get("impact_rationale") or "").strip()
    if not impact_rationale:
        impact_rationale = (
            f"Potential {vuln_type} impact requires human review of the cited local evidence."
        )
    impact_score = candidate.get("impact_score")
    if not isinstance(impact_score, (int, float)) or isinstance(impact_score, bool):
        impact_score = 0
    return {
        "hypothesis": (
            f"Possible {vuln_type} issue on {route_label} "
            f"(root={root}). Unverified hunter candidate; local review only."
        ),
        "vuln_type": vuln_type,
        "broken_invariant": broken_invariant,
        "why_still_alive": [str(item) for item in why_still_alive if str(item).strip()],
        "impact_rationale": impact_rationale,
        "impact_score": impact_score,
        "risk_level": "medium",
        "validation_mode": validation_mode,
        "self_impact_only": False,
        "best_practice_only": False,
        "requires_real_user_data": False,
        "policy_risk": "low",
        "evidence_needed": [str(item) for item in evidence_needed if str(item).strip()][
            :12
        ],
        "affected_route": route_label,
        "affected_code_path": code_path,
        "root_cause_id": root,
        "candidate_id": str(candidate.get("candidate_id") or ""),
    }


def build_submission_blocked_report_bundle(
    candidate: dict[str, Any],
    *,
    package_id: str = "",
    advisory_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert one retained hunter card into a human-review report draft bundle.

    Always forces submission blocked and non-executing posture.
    """
    if not isinstance(candidate, dict):
        raise CandidateReportBridgeError("candidate_must_be_object")
    affected_code_path = str(candidate.get("affected_code_path") or "").strip()
    affected_trace_ref = str(candidate.get("affected_trace_ref") or "").strip()
    source_fact_refs = candidate.get("source_fact_refs")
    has_cited_code_path = (
        affected_code_path.count(":") >= 2
        and affected_code_path.startswith("code:")
        and isinstance(source_fact_refs, list)
        and affected_code_path in source_fact_refs
    )
    has_autopilot_trace = (
        candidate.get("schema_version") == "bounty_autopilot_candidate_v1"
        and affected_trace_ref.startswith("autopilot:observation:")
        and isinstance(source_fact_refs, list)
        and affected_trace_ref in source_fact_refs
        and candidate.get("lineage_complete") is True
        and candidate.get("submission_blocked") is True
        and candidate.get("raw_payload_processed") is False
    )
    if not has_cited_code_path and not has_autopilot_trace:
        raise CandidateReportBridgeError(
            "affected_code_path_must_be_cited_source_fact_or_autopilot_trace"
        )

    hypothesis = candidate_to_hypothesis(candidate)
    refutation = RefutationResult(
        status="passed",
        reasons=[],
        questions=_refutation_questions(candidate),
        human_review_required=True,
    )
    validation_plan = build_validation_plan(hypothesis, refutation)
    # Prefer hunter-authored safe plan steps when present.
    hunter_plan = candidate.get("safe_validation_plan")
    if isinstance(hunter_plan, list) and hunter_plan:
        validation_plan = ValidationPlan(
            status="validation_plan_ready",
            methods=validation_plan.methods,
            steps=[str(step) for step in hunter_plan if str(step).strip()],
            human_approval_required=True,
        )
    draft = build_report_draft(hypothesis, validation_plan, refutation)

    safety_notes = list(draft.safety_notes)
    for note in (
        "submission_blocked",
        "not_a_confirmed_vulnerability",
        "hunter_candidate_only",
        "local_authorized_materials_only",
        "no_live_validation_executed",
    ):
        if note not in safety_notes:
            safety_notes.append(note)

    blockers = [
        str(item)
        for item in (candidate.get("safety_blockers") or [])
        if str(item).strip()
    ]
    for required in ("execute_live_validation", "touch_real_user_data", "submit_report"):
        if required not in blockers:
            blockers.append(required)

    evidence_hints = [
        {"type": "source_fact_ref", "ref": str(ref), "purpose": "local_authorized_evidence"}
        for ref in list(candidate.get("source_fact_refs") or [])[:12]
        if str(ref).strip()
    ]
    # Preparation-only workspace: human approval required; never auto-execute.
    workspace = build_validation_workspace(
        validation_plan=validation_plan.model_dump(),
        scope_decision={
            "allowed": True,
            "reason": "authorized_local_package_review",
        },
        refutation={"status": "passed", "reasons": []},
        evidence_hints=evidence_hints,
        human_approved=False,
    )
    workspace_payload = workspace.model_dump()
    # Fail-closed hard floor regardless of model defaults.
    workspace_payload["allowed_to_execute"] = False
    workspace_payload["test_accounts_only"] = True
    workspace_payload["no_real_user_data"] = True
    workspace_payload["non_destructive_only"] = True

    multi_engine = _multi_engine_payload_for_candidate(
        candidate,
        disposition=str(candidate.get("disposition") or "retained"),
        scope_allowed=True,
        advisory_bundle=advisory_bundle,
    )
    falsification_summary = _falsification_summary_for_report_candidate(candidate)

    patch_suggestion = build_patch_suggestion(
        package_id=package_id,
        candidate=candidate,
        multi_engine_verdict=multi_engine,
    ).model_dump()
    # Absolute safety floor for patch stage.
    patch_suggestion["auto_pr_allowed"] = False
    patch_suggestion["pr_opened"] = False
    patch_suggestion["exploit_poc_included"] = False
    patch_suggestion["patch_ready"] = False
    patch_suggestion["execution_allowed"] = False
    patch_suggestion["validation_allowed"] = False
    patch_suggestion["report_submission_allowed"] = False
    patch_suggestion["confirmed_vulnerability"] = False

    return {
        "package_id": package_id,
        "candidate_id": hypothesis["candidate_id"],
        "root_cause_id": hypothesis["root_cause_id"],
        "route": hypothesis["affected_route"],
        "affected_code_path": hypothesis["affected_code_path"],
        "vuln_type": hypothesis["vuln_type"],
        "broken_invariant": hypothesis["broken_invariant"],
        "validation_mode": hypothesis["validation_mode"],
        "evidence_needed": hypothesis["evidence_needed"],
        "impact_rationale": hypothesis["impact_rationale"],
        "impact_score": hypothesis["impact_score"],
        "status": "unverified_hypothesis",
        "human_review_required": True,
        "submission_blocked": True,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "next_allowed_action": str(
            candidate.get("next_allowed_action")
            or multi_engine.get("next_allowed_action")
            or "Human review of the cited local evidence."
        ),
        "safety_blockers": blockers,
        "refutation_questions": refutation.questions,
        "validation_plan": validation_plan.model_dump(),
        "validation_workspace": workspace_payload,
        "multi_engine_verdict": multi_engine,
        "falsification_summary": falsification_summary,
        "patch_suggestion": patch_suggestion,
        "report_draft": {
            **draft.model_dump(),
            "impact_rationale": hypothesis["impact_rationale"],
            "falsification_summary": dict(falsification_summary),
            "safety_notes": safety_notes,
            "actual_result": (
                "Not filled. No live validation was executed. "
                "Do not submit until human review and authorized evidence complete."
            ),
            "suggested_fix": (
                patch_suggestion.get("root_cause_summary")
                or "Advisory patch suggestion pending human review."
            ),
            "patch_suggestion_status": patch_suggestion.get("status"),
        },
        "source_fact_refs": list(candidate.get("source_fact_refs") or [])[:20],
        "evidence_trace_status": candidate.get("evidence_trace_status"),
        "human_validation_readiness": candidate.get("human_validation_readiness"),
    }


def bridge_operator_trial_result(
    trial_result: dict[str, Any],
    *,
    package_id: str | None = None,
    package_root: str | Path | None = None,
    advisory_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bridge a release-runner / operator-trial package result."""
    if not isinstance(trial_result, dict):
        raise CandidateReportBridgeError("trial_result_must_be_object")
    normalized = trial_result.get("normalized_output")
    # operator trial summary shape also supported
    if normalized is None and "final_candidates" in trial_result:
        normalized = {
            "final_candidates": trial_result.get("final_candidates") or [],
            "candidate_decisions": trial_result.get("candidate_decisions") or [],
        }
    retained = retained_candidates_from_normalized_output(
        normalized if isinstance(normalized, dict) else None
    )
    resolved_package_id = (
        package_id
        or str(trial_result.get("package_id") or trial_result.get("case_id") or "")
    )
    resolved_advisory = _resolve_advisory_bundle(
        trial_result,
        package_root=package_root,
        advisory_bundle=advisory_bundle,
    )
    drafts = [
        build_submission_blocked_report_bundle(
            candidate,
            package_id=resolved_package_id,
            advisory_bundle=resolved_advisory,
        )
        for candidate in retained
    ]
    decisions = []
    if isinstance(normalized, dict) and isinstance(normalized.get("candidate_decisions"), list):
        decisions = [
            item for item in normalized["candidate_decisions"] if isinstance(item, dict)
        ]
    elif isinstance(trial_result.get("candidate_decisions"), list):
        decisions = [
            item for item in trial_result["candidate_decisions"] if isinstance(item, dict)
        ]

    retained_by_id = {
        str(item.get("candidate_id") or ""): item
        for item in retained
        if str(item.get("candidate_id") or "")
    }
    multi_engine_verdicts = []
    for item in decisions:
        cid = str(item.get("candidate_id") or "")
        base = retained_by_id.get(cid) or {}
        merged = {
            **base,
            **item,
            "candidate_id": cid or str(base.get("candidate_id") or ""),
            "root_cause_id": item.get("root_cause_id") or base.get("root_cause_id") or "",
            "source_fact_refs": (
                item.get("source_fact_refs")
                or item.get("evidence_refs")
                or base.get("source_fact_refs")
                or []
            ),
            "evidence_refs": (
                item.get("evidence_refs")
                or item.get("source_fact_refs")
                or base.get("source_fact_refs")
                or []
            ),
            "refutation_questions": (
                item.get("refutation_questions")
                or base.get("refutation_questions")
                or []
            ),
        }
        multi_engine_verdicts.append(
            _multi_engine_payload_for_candidate(
                merged,
                disposition=str(item.get("disposition") or base.get("disposition") or ""),
                scope_allowed=True,
                advisory_bundle=resolved_advisory,
            )
        )
    if not multi_engine_verdicts:
        multi_engine_verdicts = [
            draft.get("multi_engine_verdict")
            for draft in drafts
            if isinstance(draft.get("multi_engine_verdict"), dict)
        ]

    return {
        "package_id": resolved_package_id,
        "retained_count": len(retained),
        "draft_count": len(drafts),
        "submission_blocked": True,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "advisory_bundle_present": bool(
            isinstance(resolved_advisory, dict) and resolved_advisory.get("present")
        ),
        "advisory_sources": list((resolved_advisory or {}).get("sources") or [])
        if isinstance(resolved_advisory, dict)
        else [],
        "multi_engine_verdicts": multi_engine_verdicts,
        "drafts": drafts,
    }



def _multi_engine_payload_for_candidate(
    candidate: dict[str, Any],
    *,
    disposition: str,
    scope_allowed: bool = True,
    advisory_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach non-executing multi-engine verdict for factory stage wiring.

    For retained finals, treat the candidate root as a matching local gap so
    engines can agree on local_static_consistent without live validation.
    For refuted decisions, prefer control evidence refs from the decision.
    """
    root = str(candidate.get("root_cause_id") or "")
    disposition_norm = disposition.lower().strip()
    evidence_refs = [
        str(ref)
        for ref in (
            candidate.get("evidence_refs")
            or candidate.get("source_fact_refs")
            or []
        )
        if str(ref).strip()
    ]

    gap_root_causes: list[str] = []
    control_refs: list[str] = []
    if disposition_norm in {"retained", "retain", ""}:
        if not disposition_norm:
            disposition_norm = "retained"
        if root:
            gap_root_causes = [root]
    elif disposition_norm in {"refuted", "refute"}:
        control_refs = evidence_refs[:12]
    elif disposition_norm in {"deduplicated", "deduplicate", "suppress", "suppressed"}:
        control_refs = evidence_refs[:12]

    card = {
        **candidate,
        "disposition": disposition_norm,
        "candidate_id": str(candidate.get("candidate_id") or ""),
        "root_cause_id": root,
        "source_fact_refs": list(candidate.get("source_fact_refs") or evidence_refs)[:12],
        "evidence_refs": evidence_refs[:12],
        "refutation_questions": candidate.get("refutation_questions") or [],
    }
    card["execution_allowed"] = False
    card["validation_allowed"] = False
    card["report_submission_allowed"] = False

    semgrep_signal = None
    codeql_signal = None
    if isinstance(advisory_bundle, dict) and advisory_bundle.get("present"):
        source_engines = {
            str(item.get("engine") or "")
            for item in (advisory_bundle.get("sources") or [])
            if isinstance(item, dict)
        }
        semgrep_findings = list(advisory_bundle.get("semgrep_findings") or [])
        codeql_findings = list(advisory_bundle.get("codeql_findings") or [])
        include_semgrep = ENGINE_SEMGREP in source_engines or bool(semgrep_findings)
        include_codeql = ENGINE_CODEQL in source_engines or bool(codeql_findings)
        signals = build_advisory_signals_for_candidate(
            candidate=card,
            semgrep_findings=semgrep_findings if include_semgrep else None,
            codeql_findings=codeql_findings if include_codeql else None,
        )
        semgrep_signal = signals.get(ENGINE_SEMGREP)
        codeql_signal = signals.get(ENGINE_CODEQL)

    verdict = verdict_from_hunter_and_map(
        candidate=card,
        gap_root_causes=gap_root_causes,
        control_refs=control_refs,
        report_submission_blocked=True,
        scope_allowed=scope_allowed,
        semgrep_signal=semgrep_signal,
        codeql_signal=codeql_signal,
    )
    payload = verdict.model_dump()
    payload["execution_allowed"] = False
    payload["validation_allowed"] = False
    payload["report_submission_allowed"] = False
    payload["finding_promotion_allowed"] = False
    payload["confirmed_vulnerability"] = False
    payload["advisory_attached"] = bool(semgrep_signal or codeql_signal)
    return payload




def _resolve_advisory_bundle(
    trial_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    advisory_bundle: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Prefer explicit advisory_bundle, then trial_result, then package_root load."""
    if isinstance(advisory_bundle, dict):
        return advisory_bundle
    trial_bundle = trial_result.get("advisory_bundle")
    if isinstance(trial_bundle, dict):
        return trial_bundle
    root = package_root or trial_result.get("package_root")
    if root:
        return load_package_advisory_bundle(root)
    return None


def _refutation_questions(candidate: dict[str, Any]) -> list[str]:
    questions = candidate.get("refutation_questions")
    if isinstance(questions, list) and questions:
        return [str(item) for item in questions if str(item).strip()]
    return [
        "Does an ownership or authorization guard run before the sensitive sink?",
        "Is the cited code path complete, or is control enforced in middleware/service layers?",
        "Can this be reviewed using only local authorized materials without real user data?",
        "What non-destructive evidence would refute the candidate before any report draft use?",
    ]
