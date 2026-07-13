"""Tests for retained-hunter -> submission-blocked report draft bridge."""

from __future__ import annotations

import pytest

from app.intelligence_benchmark.candidate_report_bridge import (
    CandidateReportBridgeError,
    bridge_operator_trial_result,
    build_submission_blocked_report_bundle,
    retained_candidates_from_normalized_output,
)
from app.multi_engine_verifier import (
    VERDICT_FALSE_POSITIVE_LIKELY,
    VERDICT_LOCAL_STATIC_CONSISTENT,
)


def _retain_card(**overrides):
    card = {
        "candidate_id": "H-001",
        "vuln_type": "authorization",
        "root_cause_id": "missing_object_ownership_check:export_local_dvwa_user",
        "route": {"method": "GET", "path": "/local/dvwa/users/:user_id/export"},
        "affected_code_path": "code:code.ts:export_local_dvwa_user",
        "source_fact_refs": ["scope:scope_context", "code:code.ts:export_local_dvwa_user"],
        "evidence_trace_status": "traceable",
        "human_validation_readiness": "ready",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "safety_blockers": ["execute_live_validation", "touch_real_user_data", "submit_report"],
        "refutation_questions": [
            "Is ownership checked before export?",
            "Can this be reviewed locally only?",
        ],
        "safe_validation_plan": [
            "Local review only for GET /local/dvwa/users/:user_id/export.",
            "Do not execute live validation or submit a report.",
        ],
        "next_allowed_action": "Human review of the cited local evidence.",
    }
    card.update(overrides)
    return card


def test_retained_candidates_filters_finals():
    retained = retained_candidates_from_normalized_output(
        {"final_candidates": [_retain_card(), "bad"]}
    )
    assert len(retained) == 1
    assert retained[0]["candidate_id"] == "H-001"


def test_bridge_rejects_submission_allowed_card():
    with pytest.raises(CandidateReportBridgeError, match="report_submission_allowed"):
        retained_candidates_from_normalized_output(
            {"final_candidates": [_retain_card(report_submission_allowed=True)]}
        )


def test_build_submission_blocked_report_bundle_shape():
    bundle = build_submission_blocked_report_bundle(
        _retain_card(),
        package_id="my-local-dvwa-authz-lab",
    )
    assert bundle["submission_blocked"] is True
    assert bundle["execution_allowed"] is False
    assert bundle["validation_allowed"] is False
    assert bundle["report_submission_allowed"] is False
    assert bundle["status"] == "unverified_hypothesis"
    assert bundle["human_review_required"] is True
    assert bundle["report_draft"]["human_review_required"] is True
    assert "submission_blocked" in bundle["report_draft"]["safety_notes"]
    assert "not_a_confirmed_vulnerability" in bundle["report_draft"]["safety_notes"]
    assert "submit_report" in bundle["safety_blockers"]
    assert bundle["validation_plan"]["human_approval_required"] is True
    patch = bundle["patch_suggestion"]
    assert patch["auto_pr_allowed"] is False
    assert patch["pr_opened"] is False
    assert patch["exploit_poc_included"] is False
    assert patch["patch_ready"] is False
    assert patch["report_submission_allowed"] is False
    assert patch["confirmed_vulnerability"] is False
    assert patch["suggested_changes"]
    assert any("Local review only" in step for step in bundle["validation_plan"]["steps"])
    assert "Do not submit" in bundle["report_draft"]["actual_result"]
    workspace = bundle["validation_workspace"]
    assert workspace["allowed_to_execute"] is False
    assert workspace["human_approval_required"] is True
    assert workspace["status"] == "awaiting_approval"
    assert workspace["approval_gate"]["status"] == "awaiting_approval"
    assert workspace["test_accounts_only"] is True
    assert workspace["no_real_user_data"] is True
    assert workspace["non_destructive_only"] is True
    assert workspace["scope_decision"]["reason"] == "authorized_local_package_review"
    assert any(
        hint.get("ref") == "code:code.ts:export_local_dvwa_user"
        for hint in workspace["evidence_hints"]
    )


def test_bundle_includes_multi_engine_verdict_safety_floor():
    bundle = build_submission_blocked_report_bundle(
        _retain_card(),
        package_id="my-local-dvwa-authz-lab",
    )
    verdict = bundle["multi_engine_verdict"]
    assert isinstance(verdict, dict)
    assert verdict["status"] == VERDICT_LOCAL_STATIC_CONSISTENT
    assert verdict["confirmed_vulnerability"] is False
    assert bundle["confirmed_vulnerability"] is False
    assert verdict["execution_allowed"] is False
    assert verdict["validation_allowed"] is False
    assert verdict["report_submission_allowed"] is False
    assert verdict["finding_promotion_allowed"] is False
    assert "submit_report" in verdict["safety_blockers"]
    assert "execute_live_validation" in verdict["safety_blockers"]
    assert verdict["agreement_score"] == 1.0


def test_bridge_operator_trial_result_from_summary_shape():
    result = bridge_operator_trial_result(
        {
            "case_id": "my-local-dvwa-authz-lab",
            "final_candidates": [_retain_card()],
            "candidate_decisions": [{"candidate_id": "H-001", "disposition": "retained"}],
        }
    )
    assert result["retained_count"] == 1
    assert result["draft_count"] == 1
    assert result["submission_blocked"] is True
    assert result["confirmed_vulnerability"] is False
    assert result["drafts"][0]["candidate_id"] == "H-001"
    assert result["drafts"][0]["validation_workspace"]["allowed_to_execute"] is False
    assert "multi_engine_verdicts" in result
    assert len(result["multi_engine_verdicts"]) == 1
    assert result["multi_engine_verdicts"][0]["status"] == VERDICT_LOCAL_STATIC_CONSISTENT
    assert result["multi_engine_verdicts"][0]["confirmed_vulnerability"] is False
    assert result["multi_engine_verdicts"][0]["report_submission_allowed"] is False


def test_bridge_operator_trial_refuted_decision_verdict():
    result = bridge_operator_trial_result(
        {
            "package_id": "my-gh-cal-ssrf",
            "normalized_output": {
                "final_candidates": [],
                "candidate_decisions": [
                    {
                        "candidate_id": "H-SSRF-1",
                        "disposition": "refuted",
                        "root_cause_id": "missing_ssrf_validation:fetch",
                        "evidence_refs": ["code:control.ts:url_allowlist"],
                        "source_fact_refs": ["code:control.ts:url_allowlist"],
                    }
                ],
            },
        }
    )
    assert result["retained_count"] == 0
    assert result["drafts"] == []
    assert len(result["multi_engine_verdicts"]) == 1
    verdict = result["multi_engine_verdicts"][0]
    assert verdict["status"] == VERDICT_FALSE_POSITIVE_LIKELY
    assert verdict["confirmed_vulnerability"] is False
    assert verdict["report_submission_allowed"] is False


def test_bridge_operator_trial_empty_finals_is_ok():
    result = bridge_operator_trial_result(
        {
            "package_id": "my-local-new-api-access-key-lab",
            "normalized_output": {"final_candidates": [], "candidate_decisions": []},
        }
    )
    assert result["retained_count"] == 0
    assert result["drafts"] == []
    assert result["report_submission_allowed"] is False
    assert result["confirmed_vulnerability"] is False
    assert result["multi_engine_verdicts"] == []
