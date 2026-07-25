"""Phase 8 refutation tests."""

from app.bounty_autopilot.refutation import RefutationCase, RefutationVerdict, refute_candidate


def test_refutes_public_by_design_and_same_account():
    public = refute_candidate(
        RefutationCase(
            case_id="case_1",
            hypothesis_id="h1",
            branch_id="b1",
            claim_summary="public profile visible",
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
            claim_summary="own object readable",
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
            claim_summary="object idor",
            counter_questions=("middleware?", "ownership?"),
            observations_cited=("obs_1",),
        )
    )
    assert result.verdict is RefutationVerdict.RETAINED
    assert result.report_submission_allowed is False


def test_marks_explicit_duplicate_without_promotion_or_submission():
    result = refute_candidate(
        RefutationCase(
            case_id="case_4",
            hypothesis_id="h4",
            branch_id="b1",
            claim_summary="same root cause as retained candidate",
            counter_questions=("same_root_cause?",),
            duplicate_of_hypothesis_id="h3",
            observations_cited=("obs_2",),
        )
    )

    assert result.verdict is RefutationVerdict.DUPLICATE
    assert result.duplicate_of_hypothesis_id == "h3"
    assert result.reasons == ("duplicate_hypothesis",)
    assert result.candidate_promotion_allowed is False
    assert result.report_submission_allowed is False
