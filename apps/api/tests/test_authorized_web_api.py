import json

from app.authorized_web_api import build_authorized_bug_bounty_plan


def test_build_authorized_bug_bounty_plan_imports_scope_models_roles_and_stays_plan_only():
    plan = build_authorized_bug_bounty_plan(
        {
            "bug_bounty": {
                "allowed_assets": ["api.example.com"],
                "api_specs": [
                    {
                        "source": "program_openapi",
                        "openapi": {
                            "paths": {
                                "/api/orders/{order_id}": {
                                    "get": {"operationId": "getOrder"}
                                },
                                "/api/admin/users/{user_id}/role": {
                                    "post": {"operationId": "changeUserRole"}
                                },
                            }
                        },
                    }
                ],
                "test_accounts": [
                    {
                        "label": "buyer_a",
                        "role": "buyer",
                        "username": "alice@example.com",
                        "password": "super-secret-password",
                    },
                    {
                        "label": "admin_a",
                        "role": "admin",
                        "api_key": "live-api-key",
                    },
                ],
            }
        },
        [
            {
                "path": "app/routes.py",
                "content": "\n".join(
                    [
                        "from fastapi import APIRouter",
                        "router = APIRouter()",
                        '@router.get("/api/orders/{order_id}")',
                        "def get_order(order_id: str):",
                        "    return load_order(order_id)",
                    ]
                ),
            }
        ],
    )

    serialized = json.dumps(plan.to_dict())

    assert plan.stage == "v2_authorized_bug_bounty"
    assert plan.inspirations == ["XBOW"]
    assert plan.execution_mode == "plan_only"
    assert plan.allowed_assets[0].asset == "api.example.com"
    assert {operation.path for operation in plan.api_operations} == {
        "/api/admin/users/{user_id}/role",
        "/api/orders/{order_id}",
    }
    assert {role.role for role in plan.role_models} == {"admin", "buyer"}
    assert {role.account_label for role in plan.role_models} == {"admin_a", "buyer_a"}
    assert "alice@example.com" not in serialized
    assert "super-secret-password" not in serialized
    assert "live-api-key" not in serialized
    assert plan.role_diff_plans[0].execution_allowed is False
    assert plan.role_diff_plans[0].approval_required is True
    assert {candidate.vuln_type for candidate in plan.business_logic_candidates} >= {
        "bola_idor",
        "authorization",
    }
    assert plan.evidence_package.redaction_required is True
    assert plan.human_gate.status == "required"
    assert plan.human_gate.execution_allowed is False
    assert plan.human_gate.approval_required is True
    preflight_by_check = {check.check: check for check in plan.validation_preflight}
    assert preflight_by_check["authorized_asset_allowlist"].status == "passed"
    assert preflight_by_check["test_account_roles"].status == "passed"
    assert preflight_by_check["durable_human_approval"].status == "blocked"
    assert all(check.execution_allowed is False for check in plan.validation_preflight)
    assert all(check.approval_required is True for check in plan.validation_preflight)
    assert plan.report_draft.auto_submit_allowed is False
    assert "no_public_target_scanning" in plan.safety_invariants
    assert "no_automatic_report_submission" in plan.safety_invariants


def test_build_authorized_bug_bounty_plan_blocks_validation_without_allowed_assets():
    plan = build_authorized_bug_bounty_plan(
        {
            "bug_bounty": {
                "test_accounts": [
                    {"label": "buyer_a", "role": "buyer"},
                    {"label": "admin_a", "role": "admin"},
                ],
            }
        },
        [
            {
                "path": "app/routes.py",
                "content": "\n".join(
                    [
                        "from fastapi import APIRouter",
                        "router = APIRouter()",
                        '@router.get("/api/orders/{order_id}")',
                        "def get_order(order_id: str):",
                        "    return load_order(order_id)",
                    ]
                ),
            }
        ],
    )

    preflight_by_check = {check.check: check for check in plan.validation_preflight}

    assert plan.execution_mode == "plan_only"
    assert plan.api_operations[0].path == "/api/orders/{order_id}"
    assert plan.role_diff_plans[0].execution_allowed is False
    assert preflight_by_check["authorized_asset_allowlist"].status == "blocked"
    assert preflight_by_check["authorized_asset_allowlist"].reason == (
        "missing_authorized_asset_allowlist"
    )
    assert preflight_by_check["durable_human_approval"].status == "blocked"
    assert all(check.execution_allowed is False for check in plan.validation_preflight)
