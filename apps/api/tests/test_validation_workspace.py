from app.validation_workspace import (
    ApprovalGate,
    ValidationStep,
    ValidationWorkspace,
    build_validation_workspace,
)


def test_build_validation_workspace_defaults_to_safe_preparation_mode():
    workspace = build_validation_workspace(
        validation_plan={
            "status": "validation_plan_ready",
            "methods": ["role_matrix_check", "request_response_diff"],
            "steps": [
                "Use only configured test accounts.",
                "Capture request/response difference without touching real user data.",
            ],
            "human_approval_required": True,
        },
        scope_decision={"allowed": True, "reason": "allowed_validation"},
        refutation={"status": "passed", "reasons": []},
        evidence_hints=[
            {"type": "role_matrix_snapshot", "purpose": "baseline roles"},
            {"type": "request_response_diff", "purpose": "prepared capture"},
        ],
        human_approved=True,
    )

    assert isinstance(workspace, ValidationWorkspace)
    assert isinstance(workspace.approval_gate, ApprovalGate)
    assert all(isinstance(step, ValidationStep) for step in workspace.steps)
    assert workspace.status == "ready_for_human_controlled_validation"
    assert workspace.human_approval_required is True
    assert workspace.allowed_to_execute is False
    assert workspace.test_accounts_only is True
    assert workspace.no_real_user_data is True
    assert workspace.non_destructive_only is True
    assert workspace.approval_gate.status == "approved"
    assert [step.status for step in workspace.steps] == ["ready", "ready"]
    assert [step.method for step in workspace.steps] == [
        "role_matrix_check",
        "request_response_diff",
    ]
    assert workspace.evidence_hints == [
        {"type": "role_matrix_snapshot", "purpose": "baseline roles"},
        {"type": "request_response_diff", "purpose": "prepared capture"},
    ]


def test_build_validation_workspace_marks_steps_awaiting_approval_when_approval_is_missing():
    workspace = build_validation_workspace(
        validation_plan={
            "status": "validation_plan_ready",
            "methods": ["two_account_authorization_check"],
            "steps": ["Prepare owner and member test accounts."],
            "human_approval_required": True,
        },
        scope_decision={"allowed": True, "reason": "allowed_validation"},
        refutation={"status": "passed", "reasons": []},
    )

    assert workspace.status == "awaiting_approval"
    assert workspace.approval_gate.status == "awaiting_approval"
    assert workspace.allowed_to_execute is False
    assert [step.status for step in workspace.steps] == ["awaiting_approval"]


def test_build_validation_workspace_treats_approval_refutation_as_awaiting_approval():
    workspace = build_validation_workspace(
        validation_plan={
            "status": "blocked",
            "methods": ["two_account_authorization_check"],
            "steps": ["Prepare owner and member test accounts."],
            "human_approval_required": True,
        },
        scope_decision={"allowed": False, "reason": "human_approval_required"},
        refutation={"status": "blocked", "reasons": ["human_approval_required"]},
    )

    assert workspace.status == "awaiting_approval"
    assert workspace.approval_gate.status == "awaiting_approval"
    assert workspace.blocked_reasons == []
    assert [step.status for step in workspace.steps] == ["awaiting_approval"]


def test_build_validation_workspace_blocks_steps_when_scope_decision_denies_validation():
    workspace = build_validation_workspace(
        validation_plan={
            "status": "validation_plan_ready",
            "methods": ["role_matrix_check"],
            "steps": ["Prepare role matrix using test accounts."],
            "human_approval_required": True,
        },
        scope_decision={"allowed": False, "reason": "out_of_scope"},
        refutation={"status": "passed", "reasons": []},
        human_approved=True,
    )

    assert workspace.status == "blocked"
    assert workspace.approval_gate.status == "blocked"
    assert workspace.blocked_reasons == ["out_of_scope"]
    assert [step.status for step in workspace.steps] == ["blocked"]


def test_build_validation_workspace_blocks_steps_when_refutation_is_blocked():
    workspace = build_validation_workspace(
        validation_plan={
            "status": "blocked",
            "methods": [],
            "steps": ["Do not validate until refutation findings are resolved."],
            "human_approval_required": True,
        },
        scope_decision={"allowed": False, "reason": "out_of_scope"},
        refutation={"status": "blocked", "reasons": ["out_of_scope"]},
        human_approved=True,
    )

    assert workspace.status == "blocked"
    assert workspace.approval_gate.status == "blocked"
    assert workspace.blocked_reasons == ["out_of_scope"]
    assert workspace.allowed_to_execute is False
    assert [step.status for step in workspace.steps] == ["blocked"]
