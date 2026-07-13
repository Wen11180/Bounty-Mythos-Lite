"""Tests for advisory-only patch suggestion scaffold."""

from __future__ import annotations

from app.patch_suggestion import (
    STATUS_ADVISORY,
    STATUS_NOT_APPLICABLE,
    attach_patch_suggestions_to_bridge_result,
    build_patch_suggestion,
)


def test_ssrf_patch_suggestion_is_advisory_only():
    suggestion = build_patch_suggestion(
        package_id="pkg",
        candidate={
            "candidate_id": "H-1",
            "vuln_type": "ssrf",
            "root_cause_id": "missing_ssrf_validation:deliver",
            "affected_code_path": "code:code.ts:deliver",
            "route": {"method": "POST", "path": "/webhooks/deliver"},
        },
        multi_engine_verdict={"status": "local_static_consistent", "candidate_id": "H-1"},
    )
    assert suggestion.status == STATUS_ADVISORY
    assert suggestion.patch_ready is False
    assert suggestion.auto_pr_allowed is False
    assert suggestion.pr_opened is False
    assert suggestion.exploit_poc_included is False
    assert suggestion.execution_allowed is False
    assert suggestion.validation_allowed is False
    assert suggestion.report_submission_allowed is False
    assert suggestion.confirmed_vulnerability is False
    assert suggestion.human_review_required is True
    assert any("URL validation" in item or "url" in item.lower() for item in suggestion.suggested_changes)
    assert suggestion.regression_tests
    assert "auto_open_pull_request" in suggestion.safety_blockers
    assert "write_exploit_poc" in suggestion.safety_blockers


def test_authorization_family_detected():
    suggestion = build_patch_suggestion(
        candidate={
            "candidate_id": "H-2",
            "vuln_type": "authorization",
            "root_cause_id": "missing_object_ownership_check:export",
            "route": {"method": "GET", "path": "/users/:id/export"},
        }
    )
    assert any("ownership" in item.lower() for item in suggestion.suggested_changes)
    assert suggestion.auto_pr_allowed is False


def test_attach_to_bridge_enriches_drafts():
    bridge = {
        "package_id": "pkg",
        "drafts": [
            {
                "candidate_id": "H-1",
                "root_cause_id": "missing_ssrf_validation:x",
                "vuln_type": "ssrf",
                "affected_code_path": "code:x",
                "route": {"method": "POST", "path": "/x"},
                "execution_allowed": False,
                "report_submission_allowed": False,
                "confirmed_vulnerability": False,
                "multi_engine_verdict": {
                    "status": "local_static_consistent",
                    "candidate_id": "H-1",
                },
                "report_draft": {"title": "Possible SSRF"},
            }
        ],
        "multi_engine_verdicts": [],
        "submission_blocked": True,
    }
    out = attach_patch_suggestions_to_bridge_result(bridge)
    assert out["patch_suggestion_present"] is True
    assert out["auto_pr_allowed"] is False
    assert out["pr_opened"] is False
    assert out["exploit_poc_included"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert len(out["patch_suggestions"]) == 1
    assert out["drafts"][0]["patch_suggestion"]["status"] == STATUS_ADVISORY
    assert "suggested_fix" in out["drafts"][0]["report_draft"]
    assert "regression_test" in out["drafts"][0]["report_draft"]
    assert out["drafts"][0]["report_submission_allowed"] is False


def test_false_positive_verdict_not_applicable():
    bridge = {
        "package_id": "pkg-refute",
        "drafts": [],
        "multi_engine_verdicts": [
            {
                "candidate_id": "H-9",
                "root_cause_id": "missing_ssrf_validation:x",
                "vuln_type": "ssrf",
                "status": "false_positive_likely",
            }
        ],
    }
    out = attach_patch_suggestions_to_bridge_result(bridge)
    assert out["patch_suggestion_present"] is True
    assert out["patch_suggestions"][0]["status"] == STATUS_NOT_APPLICABLE
    assert out["patch_suggestions"][0]["auto_pr_allowed"] is False
    assert out["patch_suggestions"][0]["report_submission_allowed"] is False