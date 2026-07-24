from app.research_director import (
    ResearchDirectorContext,
    ResearchSignal,
    build_research_director_plan,
)
from app.scope_guard import ScopeGuardRule


def _rule(*, allowed_validation: list[str]):
    return ScopeGuardRule(
        asset="api.example.test",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=allowed_validation,
        forbidden=[],
        human_approval_required=False,
    )


def _context(**updates):
    payload = {
        "campaign_id": "campaign_director_1",
        "asset": "api.example.test",
        "autonomy_level": "level_1_local_validation",
        "source_snapshot_digest": f"sha256:{'a' * 64}",
        "scope_rule": _rule(allowed_validation=["static_analyzer"]),
        "campaign_allowed_tools": ["static_analyzer"],
        "has_authorized_local_root": True,
        "local_execution_authorized": True,
        "remaining_tool_calls": 3,
        "completed_action_ids": [],
        "signals": [],
    }
    payload.update(updates)
    return ResearchDirectorContext(**payload)


def test_director_prioritizes_high_value_local_evidence_collection():
    plan = build_research_director_plan(
        _context(
            signals=[
                ResearchSignal(
                    signal_id="candidate_ssrf",
                    state="needs_evidence",
                    priority=90,
                    tool_hints=["semgrep_local"],
                    evidence_refs=["fact:outbound_sink"],
                )
            ]
        )
    )

    assert plan.status == "ready"
    assert plan.action_kind == "local_tool"
    assert plan.action_id == "semgrep_local"
    assert plan.dispatch_allowed is True
    assert plan.execution_tier == "local"
    assert plan.source_snapshot_digest == f"sha256:{'a' * 64}"
    assert plan.candidate_promotion_allowed is False
    assert plan.report_submission_allowed is False


def test_director_uses_research_task_when_local_execution_is_not_authorized():
    plan = build_research_director_plan(
        _context(
            autonomy_level="level_0_read_only",
            local_execution_authorized=False,
            signals=[
                ResearchSignal(
                    signal_id="candidate_ssrf",
                    state="needs_evidence",
                    priority=90,
                    tool_hints=["semgrep_local"],
                )
            ],
        )
    )

    assert plan.status == "ready"
    assert plan.action_kind == "research_task"
    assert plan.action_id == "candidate_refutation"
    assert plan.dispatch_allowed is False
    assert "local_execution_autonomy_required" in plan.reasons


def test_director_never_dispatches_remote_tool_without_lease_runtime():
    plan = build_research_director_plan(
        _context(
            autonomy_level="level_2_test_account_validation",
            scope_rule=_rule(allowed_validation=["two_account_authorization_check"]),
            campaign_allowed_tools=["two_account_authorization_check"],
            signals=[
                ResearchSignal(
                    signal_id="candidate_idor",
                    state="needs_evidence",
                    priority=95,
                    tool_hints=["two_account_authorization_check"],
                )
            ],
        )
    )

    assert plan.status == "awaiting_human_review"
    assert plan.action_kind == "remote_tool"
    assert plan.action_id == "two_account_authorization_check"
    assert plan.dispatch_allowed is False
    assert "execution_lease_required" in plan.reasons


def test_director_uses_read_only_refutation_when_tool_budget_is_exhausted():
    plan = build_research_director_plan(
        _context(
            remaining_tool_calls=0,
            signals=[
                ResearchSignal(
                    signal_id="candidate_ssrf",
                    state="needs_evidence",
                    priority=90,
                    tool_hints=["semgrep_local"],
                )
            ],
        )
    )

    assert plan.status == "ready"
    assert plan.action_kind == "research_task"
    assert plan.action_id == "candidate_refutation"
    assert plan.dispatch_allowed is False
    assert "tool_budget_exhausted:semgrep_local" in plan.reasons


def test_director_keeps_retained_candidate_report_review_when_tool_budget_is_exhausted():
    plan = build_research_director_plan(
        _context(
            remaining_tool_calls=0,
            signals=[
                ResearchSignal(
                    signal_id="candidate_retained",
                    state="retained",
                    priority=80,
                )
            ],
        )
    )

    assert plan.status == "ready"
    assert plan.action_kind == "research_task"
    assert plan.action_id == "report_review"
    assert plan.dispatch_allowed is False


def test_director_routes_retained_candidate_to_report_review_without_execution():
    plan = build_research_director_plan(
        _context(
            signals=[
                ResearchSignal(
                    signal_id="candidate_retained",
                    state="retained",
                    priority=80,
                )
            ]
        )
    )

    assert plan.status == "ready"
    assert plan.action_kind == "research_task"
    assert plan.action_id == "report_review"
    assert plan.dispatch_allowed is False


def test_director_does_not_repeat_completed_local_tool():
    plan = build_research_director_plan(
        _context(
            completed_action_ids=["semgrep_local"],
            signals=[
                ResearchSignal(
                    signal_id="candidate_ssrf",
                    state="needs_evidence",
                    priority=90,
                    tool_hints=["semgrep_local", "codeql_local"],
                )
            ],
        )
    )

    assert plan.status == "ready"
    assert plan.action_kind == "local_tool"
    assert plan.action_id == "codeql_local"


def test_director_falls_back_when_a_local_hint_has_no_execution_adapter():
    plan = build_research_director_plan(
        _context(
            signals=[
                ResearchSignal(
                    signal_id="candidate_static_check",
                    state="needs_evidence",
                    priority=90,
                    tool_hints=["static_local_check"],
                )
            ]
        )
    )

    assert plan.status == "ready"
    assert plan.action_kind == "research_task"
    assert plan.action_id == "candidate_refutation"
    assert plan.dispatch_allowed is False
    assert "unregistered_tool_hint:static_local_check" in plan.reasons
