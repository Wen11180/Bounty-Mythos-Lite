import json
from pathlib import Path

from app.authorized_web_api import (
    STATUS_READY,
    attach_authorized_web_api_to_bridge_result,
    build_authorized_bug_bounty_plan,
    load_package_scope_policy,
)
from app.industrial_scheduler import build_industrial_scheduler_plan


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"
PKG_CAL = ROOT / "authorized_packages" / "my-gh-cal-ssrf"


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
    assert plan.execution_allowed is False
    assert plan.report_submission_allowed is False


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
    assert preflight_by_check["test_account_roles"].status == "passed"
    assert plan.human_gate.execution_allowed is False
    assert plan.report_draft.auto_submit_allowed is False


def test_package_root_ingest_local_ssrf_retain_is_plan_only():
    plan = build_authorized_bug_bounty_plan(package_root=PKG_SSRF)
    serialized = json.dumps(plan.to_dict())

    assert plan.stage == "v2_authorized_bug_bounty_package_ingest"
    assert plan.status == STATUS_READY
    assert plan.execution_mode == "plan_only"
    assert plan.operation_count >= 2
    paths = {operation.path for operation in plan.api_operations}
    assert "/local/lab/webhooks/deliver" in paths
    assert "/local/lab/webhooks/test" in paths
    assets = {asset.asset for asset in plan.allowed_assets}
    assert "local_authorized_package" in assets
    assert "local_staged_code_root" in assets
    assert len(plan.role_models) >= 2
    assert all(diff.execution_allowed is False for diff in plan.role_diff_plans)
    assert plan.execution_allowed is False
    assert plan.validation_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.confirmed_vulnerability is False
    assert "password" not in serialized.lower() or "[REDACTED]" in serialized
    assert "live-api-key" not in serialized


def test_package_root_ingest_cal_ssrf_when_present():
    if not PKG_CAL.is_dir():
        return
    plan = build_authorized_bug_bounty_plan(package_root=PKG_CAL)
    assert plan.stage.startswith("v2_authorized_bug_bounty")
    assert plan.execution_allowed is False
    assert plan.report_submission_allowed is False
    if plan.operation_count:
        assert plan.status == STATUS_READY


def test_load_package_scope_policy_maps_scope_and_api():
    policy = load_package_scope_policy(PKG_SSRF)
    assert policy.get("local_only") is True
    assert "bug_bounty" in policy
    assert isinstance(policy["bug_bounty"].get("api_specs"), list)
    assert policy["bug_bounty"]["api_specs"][0]["source"] == "package_inputs_api_json"


def test_attach_authorized_web_api_to_bridge_result_is_safe_and_sets_v2_alias():
    bridged = attach_authorized_web_api_to_bridge_result(
        {
            "package_id": "my-local-ssrf-webhook-retain-lab",
            "package_root": str(PKG_SSRF),
            "submission_blocked": True,
        }
    )
    assert bridged["authorized_web_api_present"] is True
    assert bridged["authorized_bug_bounty_present"] is True
    assert isinstance(bridged["authorized_bug_bounty"], dict)
    assert bridged["authorized_web_api_status"] == STATUS_READY
    assert bridged["authorized_web_api_operation_count"] >= 2
    assert bridged["execution_allowed"] is False
    assert bridged["validation_allowed"] is False
    assert bridged["report_submission_allowed"] is False
    assert bridged["confirmed_vulnerability"] is False
    assert bridged["submission_blocked"] is True
    payload = bridged["authorized_bug_bounty"]
    assert payload["execution_allowed"] is False
    assert payload["report_submission_allowed"] is False
    assert payload["human_gate"]["execution_allowed"] is False


def test_scheduler_plans_t004_when_authorized_bug_bounty_present():
    bridged = attach_authorized_web_api_to_bridge_result(
        {
            "package_id": "demo",
            "package_root": str(PKG_SSRF),
        }
    )
    plan = build_industrial_scheduler_plan(bridged)
    tasks = {task.task_id: task for task in plan.dag_tasks}
    assert "T-004" in tasks
    assert tasks["T-004"].status == "planned"
    assert tasks["T-004"].requires_human_review is True
