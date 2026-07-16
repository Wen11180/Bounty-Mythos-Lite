from __future__ import annotations

import json

from app.cli import main
from app.intelligence_benchmark.ab_leadership_gate import (
    REQUIRED_METRICS,
    run_ab_leadership_gate,
)


def test_ab_leadership_gate_passes_on_hard_corpus():
    result = run_ab_leadership_gate()
    assert result["schema_version"] == "ab_leadership_gate_v1"
    assert result["claim_scope"] == "lab_ab_falsify_quality"
    assert result["passed"] is True
    assert result["failures"] == []
    assert result["scenario_count"] == 90
    assert result["execution_allowed"] is False
    assert result["report_submission_allowed"] is False
    for key in REQUIRED_METRICS:
        assert result["metrics"][key] == 1.0, key
    scenario_ids = {row["scenario_id"] for row in result["scenarios"]}
    assert "dedupe_multi_root_shared_service" in scenario_ids
    assert "held_out_transfer_ownership" in scenario_ids
    assert "rank_two_retained_by_priority" in scenario_ids
    assert "refute_nested_parent_ownership" in scenario_ids
    assert "refute_python_ownership_deny" in scenario_ids
    assert "refute_python_tenant_boundary" in scenario_ids
    assert "refute_python_inline_ownership" in scenario_ids
    assert "refute_python_async_ownership" in scenario_ids
    assert "refute_python_multihop_ownership" in scenario_ids
    assert "refute_python_role_owner_and" in scenario_ids
    assert "refute_python_membership" in scenario_ids
    assert "refute_python_bool_helper_guard" in scenario_ids
    assert "refute_python_workspace_boundary" in scenario_ids
    assert "refute_python_assert_ownership" in scenario_ids
    assert "refute_python_or_boundary" in scenario_ids
    assert "refute_python_gated_eq" in scenario_ids
    assert "refute_python_ownership_decorator" in scenario_ids
    assert "refute_python_query_filter" in scenario_ids
    assert "refute_python_depends_ownership" in scenario_ids
    assert "refute_ts_membership_includes" in scenario_ids
    assert "refute_python_cross_file_ownership" in scenario_ids
    assert "refute_python_cross_file_bool_helper" in scenario_ids
    assert "refute_python_class_method_ownership" in scenario_ids
    assert "refute_ts_cross_file_ownership" in scenario_ids
    assert "refute_python_assign_ownership_helper" in scenario_ids
    assert "refute_python_service_layer_ownership" in scenario_ids
    assert "refute_python_g_current_user" in scenario_ids
    assert "refute_python_or_admin_owner_allow" in scenario_ids
    assert "refute_python_team_boundary" in scenario_ids
    assert "refute_ts_middleware_ownership" in scenario_ids
    assert "refute_ts_service_layer_ownership" in scenario_ids
    assert "multi_engine_advisory_consistent" in scenario_ids
    assert "refute_python_author_id_boundary" in scenario_ids
    assert "refute_python_try_ensure_owner" in scenario_ids
    assert "refute_python_ternary_ownership" in scenario_ids
    assert "refute_python_response_403" in scenario_ids
    assert "refute_python_getattr_owner" in scenario_ids
    assert "refute_python_request_state_user" in scenario_ids
    assert "refute_python_graphql_context" in scenario_ids
    assert "refute_ts_prisma_owner_filter" in scenario_ids
    assert "retain_python_guard_after_sink" in scenario_ids
    assert "retain_python_login_only" in scenario_ids
    assert "retain_ts_guard_after_sink" in scenario_ids
    assert "refute_python_walrus_ownership" in scenario_ids
    assert "refute_python_match_ownership" in scenario_ids
    assert "retain_python_status_only" in scenario_ids
    assert "retain_python_wrong_field_compare" in scenario_ids
    assert "retain_python_role_only" in scenario_ids
    assert "retain_ts_login_only" in scenario_ids
    assert "retain_ts_role_only" in scenario_ids
    assert "retain_python_hardcoded_owner" in scenario_ids
    assert "retain_python_spoofable_header_principal" in scenario_ids
    assert "retain_python_wrong_object_unrelated" in scenario_ids
    assert "retain_ts_hardcoded_owner" in scenario_ids
    assert "retain_ts_status_only" in scenario_ids
    assert "retain_python_query_param_principal" in scenario_ids
    assert "refute_java_spring_ownership" in scenario_ids
    assert "refute_go_ownership" in scenario_ids
    assert "refute_rails_ownership" in scenario_ids
    assert "retain_java_role_only" in scenario_ids
    assert "retain_go_role_only" in scenario_ids
    assert "retain_rails_role_only" in scenario_ids
    assert "retain_java_status_only" in scenario_ids
    assert "refute_java_service_layer_ownership" in scenario_ids
    assert "refute_go_middleware_ownership" in scenario_ids
    assert "refute_rails_before_action_ownership" in scenario_ids
    assert "retain_java_guard_after_sink" in scenario_ids
    assert "retain_go_status_only" in scenario_ids
    assert "retain_rails_status_only" in scenario_ids
    assert "refute_csharp_ownership" in scenario_ids
    assert "refute_php_ownership" in scenario_ids
    assert "retain_csharp_role_only" in scenario_ids
    assert "retain_php_role_only" in scenario_ids
    assert "refute_kotlin_ownership" in scenario_ids
    assert "retain_kotlin_role_only" in scenario_ids
    assert "refute_csharp_service_layer_ownership" in scenario_ids
    assert "refute_php_controller_ownership" in scenario_ids
    assert "refute_rust_ownership" in scenario_ids
    assert "retain_rust_role_only" in scenario_ids
    assert "refute_scala_ownership" in scenario_ids
    assert "retain_scala_role_only" in scenario_ids

    nested = next(
        row
        for row in result["scenarios"]
        if row["scenario_id"] == "refute_nested_parent_ownership"
    )
    assert nested["disposition_ok"] is True
    assert nested["card_quality_ok"] is True
    multi = next(
        row
        for row in result["scenarios"]
        if row["scenario_id"] == "multi_engine_advisory_consistent"
    )
    assert multi["disposition_ok"] is True
    assert multi["card_quality_ok"] is True
    assert len(multi.get("multi_engine_details") or []) == 2
    assert all(detail.get("agree_ok") for detail in multi["multi_engine_details"])


def test_cli_ab_leadership_gate_writes_summary(tmp_path, capsys):
    out = tmp_path / "ab-leadership.json"
    code = main(
        [
            "ab-leadership-gate",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["metrics"]["falsify_coverage"] == 1.0
    assert payload["metrics"]["dedupe_kill"] == 1.0
    assert payload["metrics"]["rank_order_hit"] == 1.0
    assert payload["metrics"]["nested_refute_kill"] == 1.0
    assert payload["metrics"]["multi_engine_agree"] == 1.0
    assert payload["metrics"]["python_refute_kill"] == 1.0
    assert payload["metrics"]["tenant_refute_kill"] == 1.0
    assert payload["metrics"]["inline_refute_kill"] == 1.0
    assert payload["metrics"]["async_refute_kill"] == 1.0
    assert payload["metrics"]["multihop_refute_kill"] == 1.0
    assert payload["metrics"]["role_owner_and_refute_kill"] == 1.0
    assert payload["metrics"]["membership_refute_kill"] == 1.0
    assert payload["metrics"]["bool_helper_refute_kill"] == 1.0
    assert payload["metrics"]["workspace_refute_kill"] == 1.0
    assert payload["metrics"]["assert_refute_kill"] == 1.0
    assert payload["metrics"]["or_refute_kill"] == 1.0
    assert payload["metrics"]["gated_eq_refute_kill"] == 1.0
    assert payload["metrics"]["decorator_refute_kill"] == 1.0
    assert payload["metrics"]["query_filter_refute_kill"] == 1.0
    assert payload["metrics"]["depends_refute_kill"] == 1.0
    assert payload["metrics"]["ts_membership_refute_kill"] == 1.0
    assert payload["metrics"]["cross_file_py_refute_kill"] == 1.0
    assert payload["metrics"]["cross_file_bool_refute_kill"] == 1.0
    assert payload["metrics"]["class_method_refute_kill"] == 1.0
    assert payload["metrics"]["ts_cross_file_refute_kill"] == 1.0
    assert payload["metrics"]["assign_helper_refute_kill"] == 1.0
    assert payload["metrics"]["service_layer_refute_kill"] == 1.0
    assert payload["metrics"]["g_current_user_refute_kill"] == 1.0
    assert payload["metrics"]["or_admin_owner_refute_kill"] == 1.0
    assert payload["metrics"]["ts_middleware_refute_kill"] == 1.0
    assert payload["metrics"]["team_refute_kill"] == 1.0
    assert payload["metrics"]["ts_service_layer_refute_kill"] == 1.0
    assert payload["metrics"]["rust_refute_kill"] == 1.0
    assert payload["metrics"]["rust_role_only_retain_hit"] == 1.0
    assert payload["metrics"]["scala_refute_kill"] == 1.0
    assert payload["metrics"]["scala_role_only_retain_hit"] == 1.0
    assert payload["scenario_count"] == 90
    blob = out.read_text(encoding="utf-8")
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    captured = capsys.readouterr()
    assert "passed=True" in captured.out
