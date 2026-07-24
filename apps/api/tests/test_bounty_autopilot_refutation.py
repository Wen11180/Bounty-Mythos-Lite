"""Phase 8 refutation tests."""

from app.bounty_autopilot.refutation import (
    REQUIRED_REFUTATION_CHECKS,
    RefutationCase,
    RefutationVerdict,
    refute_candidate,
)


def test_refutes_public_by_design_and_same_account():
    public = refute_candidate(
        RefutationCase(
            case_id="case_1",
            hypothesis_id="h1",
            branch_id="b1",
            counter_questions=("is_public_by_design?",),
            public_by_design=True,
        )
    )
    assert public.verdict is RefutationVerdict.REFUTED

    same = refute_candidate(
        RefutationCase(
            case_id="case_2",
            hypothesis_id="h2",
            branch_id="b1",
            counter_questions=("cross_account?",),
            same_account_only=True,
        )
    )
    assert same.verdict is RefutationVerdict.REFUTED


def test_retains_when_observations_present_without_refute_signal():
    result = refute_candidate(
        RefutationCase(
            case_id="case_3",
            hypothesis_id="h3",
            branch_id="b1",
            counter_questions=("middleware?", "ownership?"),
            observations_cited=("obs_1",),
            reproducible=True,
            completed_checks=REQUIRED_REFUTATION_CHECKS,
        )
    )
    assert result.verdict is RefutationVerdict.RETAINED
    assert result.report_submission_allowed is False


def test_does_not_retain_until_all_required_refutation_checks_are_recorded():
    result = refute_candidate(
        RefutationCase(
            case_id="case_missing_checks",
            hypothesis_id="h_missing_checks",
            branch_id="b1",
            counter_questions=("ownership?",),
            observations_cited=("obs_1",),
            reproducible=True,
        )
    )
    assert result.verdict is RefutationVerdict.NEEDS_EVIDENCE
    assert "missing_refutation_checks" in result.reasons


def test_duplicate_is_a_recorded_human_review_recommendation():
    result = refute_candidate(
        RefutationCase(
            case_id="case_4",
            hypothesis_id="h4",
            branch_id="b1",
            counter_questions=("duplicate_root_cause?",),
            observations_cited=("obs_1",),
            reproducible=True,
            duplicate_candidate_ids=("candidate_1",),
        )
    )
    assert result.verdict is RefutationVerdict.DUPLICATE_REVIEW
    assert result.duplicate_review_required is True
