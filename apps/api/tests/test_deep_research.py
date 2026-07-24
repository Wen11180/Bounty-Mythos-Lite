from pathlib import Path

import pytest

from app.deep_research import (
    STATUS_EMPTY,
    STATUS_PACKAGE_MISSING,
    STATUS_READY,
    STATUS_WAITING,
    STATUS_WRITTEN,
    attach_deep_research_to_bridge_result,
    build_deep_research_plan,
    build_knowledge_artifact,
    run_deep_research,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_DEEP_RESEARCH,
    build_multi_engine_verdict,
    signal_from_deep_research,
)


def _safe_bridge(**extra):
    base = {
        "package_id": "demo-pkg",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "confirmed_vulnerability": False,
        "drafts": [
            {
                "candidate_id": "H-001",
                "root_cause_id": "RC-ssrf",
                "vuln_type": "ssrf",
                "submission_blocked": True,
                "confirmed_vulnerability": False,
                "summary": "SSRF candidate for local retain lab",
            }
        ],
        "human_residual_gates": [
            {
                "candidate_id": "H-001",
                "status": "ready_for_human_review",
                "vuln_type": "ssrf",
                "report_submission_allowed": False,
                "execution_allowed": False,
                "confirmed_vulnerability": False,
            }
        ],
        "crs_fuzzing": {
            "parser_candidates": [
                {"symbol_name": "decode_webhook", "source_path": "app/codec.py"}
            ]
        },
        "authorized_web_api": {
            "role_models": [
                {"account_label": "user_a", "role": "user"},
                {"account_label": "admin_a", "role": "admin"},
            ]
        },
        "multi_engine_deep": True,
    }
    base.update(extra)
    return base


def test_build_deep_research_plan_creates_chains_variants_and_long_horizon_queue():
    plan = build_deep_research_plan(
        {
            "source_hypotheses": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization",
                    "location": "GET /api/orders/{order_id}",
                    "risk": "high",
                    "reason": "Missing handler-level authorization check.",
                }
            ],
            "authorized_bug_bounty": {
                "role_models": [
                    {"account_label": "buyer_a", "role": "buyer"},
                    {"account_label": "admin_a", "role": "admin"},
                ],
                "business_logic_candidates": [
                    {
                        "candidate_id": "V2-001",
                        "vuln_type": "bola_idor",
                        "endpoint": "GET /api/orders/{order_id}",
                    }
                ],
            },
            "crs_fuzzing": {
                "parser_candidates": [
                    {"symbol_name": "decode_order_token", "source_path": "app/codec.py"}
                ]
            },
            "industrial_scheduler": {
                "risk_queue": [
                    {"finding_id": "H-001", "severity": "high", "priority": 1}
                ],
                "agent_memory": {"status": "advisory_update_planned"},
            },
        }
    )

    assert plan.stage == "v4_deep_vulnerability_research"
    assert plan.inspirations == ["Mythos", "Big Sleep"]
    assert plan.execution_mode == "deep_reasoning_plan_only"
    assert plan.permission_model.status == "modeled_from_test_roles"
    assert plan.permission_model.roles == ["admin", "buyer"]
    assert plan.cross_file_reasoning[0].focus == "authorization"
    assert plan.vulnerability_chains[0].stages == [
        "entrypoint",
        "authorization_boundary",
        "object_access",
        "impact_review",
    ]
    assert plan.vulnerability_chains[0].execution_allowed is False
    assert plan.refutation_matrix[0].chain_id == plan.vulnerability_chains[0].chain_id
    assert plan.refutation_matrix[0].status == "unresolved_requires_human_review"
    assert plan.refutation_matrix[0].execution_allowed is False
    assert plan.refutation_matrix[0].human_review_required is True
    assert plan.refutation_matrix[0].allowed_evidence == [
        "local_code_trace",
        "sanitized_fixture_diff",
        "human_review_decision",
    ]
    assert "missing_refutation_evidence" in plan.refutation_matrix[0].blockers
    assert plan.variant_analysis[0].source_hypothesis_id == "H-001"
    assert plan.protocol_aware_fuzzing[0].target_symbol == "decode_order_token"
    assert plan.patch_diff_learner.status == "waiting_for_patch_diff"
    assert plan.long_horizon_plan.iteration_strategy == "refute_then_branch"
    assert "try_variant_analysis" in plan.long_horizon_plan.fallback_paths
    assert plan.evidence_graph.nodes[0].node_id == "H-001"
    assert plan.evidence_graph.edges[0].relationship == "supports_chain"
    assert plan.evidence_graph.storage_policy == "metadata_only_no_raw_secret_or_user_data"
    assert plan.reflection_log[0].trigger == "initial_chain_planning"
    assert plan.reflection_log[0].next_path == "try_variant_analysis"
    assert plan.knowledge_consolidation_queue[0].source_ref == "H-001"
    assert plan.knowledge_consolidation_queue[0].human_review_required is True
    assert plan.knowledge_updates[0].status == "advisory_only"
    assert plan.knowledge_updates[0].source_ref == "H-001"
    assert plan.knowledge_updates[0].applicability_boundary == (
        "authorized_local_artifacts_only"
    )
    assert "no_exploit_generation" in plan.safety_invariants
    assert "human_review_required_before_validation" in plan.safety_invariants


@pytest.mark.parametrize(
    ("vuln_type", "expected_stages", "expected_invariant", "expected_refutation_steps"),
    [
        (
            "ssrf",
            ["entrypoint", "url_policy", "egress_sink", "impact_review"],
            (
                "Outbound requests to user-controlled URLs must validate the target "
                "against private networks, metadata endpoints, and unsafe schemes."
            ),
            [
                "trace local URL normalization and egress policy before the outbound sink",
                "confirm the policy rejects private, metadata, and unsafe scheme target classes",
                "require redacted evidence and human review before promotion",
            ],
        ),
        (
            "path_traversal",
            ["entrypoint", "path_canonicalization", "filesystem_sink", "impact_review"],
            "User-controlled file paths must be sanitized before reaching filesystem read sinks.",
            [
                "trace local path canonicalization or safe-join before the filesystem sink",
                "confirm the boundary remains inside the intended local root",
                "require redacted evidence and human review before promotion",
            ],
        ),
        (
            "mass_assignment",
            ["entrypoint", "field_allowlist", "state_update", "impact_review"],
            (
                "User-controlled update payloads must not set privilege or tenancy fields "
                "without an allowlist."
            ),
            [
                "trace the local schema or field allowlist before the update sink",
                "confirm privilege and tenancy fields remain outside the writable set",
                "require redacted evidence and human review before promotion",
            ],
        ),
        (
            "command_injection",
            ["entrypoint", "command_policy", "command_sink", "impact_review"],
            (
                "Command selection and arguments must be constrained by an explicit local "
                "allowlist or structured validation before command-execution sinks."
            ),
            [
                "trace command identifier and argument validation before the execution sink",
                "confirm an explicit local allowlist constrains the mapped command path",
                "require redacted evidence and human review before promotion",
            ],
        ),
        (
            "unsafe_deserialization",
            ["entrypoint", "loader_policy", "deserialization_sink", "impact_review"],
            (
                "Serialized input must pass an explicit type and loader policy before unsafe "
                "deserialization sinks."
            ),
            [
                "trace serialized-input validation and loader policy before deserialization",
                "confirm local type and format restrictions run before object construction",
                "require redacted evidence and human review before promotion",
            ],
        ),
        (
            "file_upload",
            ["entrypoint", "upload_policy", "storage_sink", "impact_review"],
            (
                "Uploaded files must pass explicit type, filename, and storage policy checks "
                "before upload-storage sinks."
            ),
            [
                "trace type, filename, and storage policy checks before upload storage",
                "confirm unsupported fixture metadata is rejected before storage",
                "require redacted evidence and human review before promotion",
            ],
        ),
        (
            "business_logic",
            [
                "entrypoint",
                "server_amount_derivation",
                "financial_action",
                "impact_review",
            ],
            (
                "Financial amounts, credits, and refunds must be derived from trusted "
                "server-side order or account state before financial action sinks."
            ),
            [
                "trace server-side amount or credit derivation before the financial action",
                "confirm trusted order or account state overrides client-supplied values",
                "require redacted evidence and human review before promotion",
            ],
        ),
        (
            "agent_tool_authz_gap",
            ["entrypoint", "agent_tool_policy", "tool_dispatch", "impact_review"],
            (
                "Agent tool dispatch must verify the current user, agent policy, and task "
                "context permit the selected tool before invocation."
            ),
            [
                "trace current-user, agent-policy, and task-context checks before tool dispatch",
                "confirm selected tool and resource scope are rechecked before invocation",
                "require redacted evidence and human review before promotion",
            ],
        ),
    ],
)
def test_build_deep_research_plan_preserves_static_family_reasoning(
    vuln_type: str,
    expected_stages: list[str],
    expected_invariant: str,
    expected_refutation_steps: list[str],
):
    plan = build_deep_research_plan(
        {
            "source_hypotheses": [
                {
                    "hypothesis_id": "H-static",
                    "vuln_type": vuln_type,
                    "location": "local_handler",
                    "risk": "high",
                    "reason": "static candidate",
                }
            ]
        }
    )

    assert plan.vulnerability_chains[0].stages == expected_stages
    assert plan.vulnerability_chains[0].execution_allowed is False
    assert plan.cross_file_reasoning[0].invariant == expected_invariant
    assert plan.cross_file_reasoning[0].refutation_steps == expected_refutation_steps
    assert plan.refutation_matrix[0].execution_allowed is False
    assert plan.refutation_matrix[0].human_review_required is True


def test_build_knowledge_artifact_exports_advisory_reviewable_memory_without_secrets():
    plan = build_deep_research_plan(
        {
            "source_hypotheses": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization",
                    "location": "GET /api/orders/{order_id}",
                    "risk": "high",
                    "reason": "Authorization: Bearer should-not-leak",
                }
            ]
        }
    )
    artifact = build_knowledge_artifact(plan)
    assert artifact.artifact_type == "v4_advisory_knowledge"
    assert artifact.status == "requires_human_review"
    assert artifact.storage_policy == "metadata_only_no_raw_secret_or_user_data"
    blob = str(artifact.to_dict())
    assert "should-not-leak" not in blob
    assert artifact.entries
    assert artifact.entries[0].review_required is True


def test_run_deep_research_from_bridge():
    result = run_deep_research(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.chain_count >= 1
    assert result.variant_count >= 1
    assert result.unresolved_refutation_count >= 1
    assert result.execution_allowed is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.ranking_permission_granted is False
    assert result.network_access is False
    assert result.live_validation is False
    assert result.plan
    assert result.plan.get("execution_mode") == "deep_reasoning_plan_only"


def test_run_deep_research_offline_artifact(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    payload = (
        '{"source_hypotheses":[{"hypothesis_id":"H-offline",'
        '"vuln_type":"injection","location":"POST /parse",'
        '"risk":"high","reason":"untrusted parser path"}]}'
    )
    (inputs / "deep_research.json").write_text(payload, encoding="utf-8")
    result = run_deep_research(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(drafts=[]),
    )
    assert result.status == STATUS_READY
    assert result.offline_artifact_count >= 1
    assert result.chain_count >= 1
    assert result.execution_allowed is False


def test_export_under_package(tmp_path: Path):
    result = run_deep_research(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count >= 1
    export_root = tmp_path / "_export" / "deep_research"
    assert export_root.is_dir()
    stamps = list(export_root.iterdir())
    assert stamps
    assert (stamps[0] / "index.json").is_file()
    assert (stamps[0] / "README.md").is_file()


def test_bridge_attach_forces_safety():
    bridge = _safe_bridge(
        execution_allowed=True,
        report_submission_allowed=True,
        confirmed_vulnerability=True,
        submission_blocked=False,
        validation_allowed=True,
    )
    out = attach_deep_research_to_bridge_result(bridge)
    assert out["deep_research_present"] is True
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["deep_research_execution_allowed"] is False
    assert out["deep_research"]["execution_allowed"] is False
    assert out["deep_research"]["ranking_permission_granted"] is False


def test_waiting_or_empty_without_hypotheses():
    result = run_deep_research(bridge_result={"package_id": "empty"})
    assert result.status in {STATUS_EMPTY, STATUS_WAITING, STATUS_READY, STATUS_PACKAGE_MISSING}
    assert result.execution_allowed is False


def test_mev_signal_and_engine():
    payload = run_deep_research(bridge_result=_safe_bridge()).to_dict()
    sig = signal_from_deep_research(payload)
    assert sig is not None
    assert sig["status"] == "ready"
    unsafe = signal_from_deep_research({**payload, "execution_allowed": True})
    assert unsafe["status"] == "blocked"
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-001"},
        deep_research_signal=sig,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_DEEP_RESEARCH in engines
    assert verdict.confirmed_vulnerability is False
    assert verdict.execution_allowed is False
    assert verdict.report_submission_allowed is False


def test_scheduler_includes_t013():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True, "reason": "authorized local repository"},
            "hypotheses": [],
            "crs_fuzzing": {"parser_candidates": [{"symbol_name": "decode_frame"}]},
            "authorized_bug_bounty": {"human_gate": {"status": "required"}},
        }
    )
    task_by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-013" in task_by_id
    assert task_by_id["T-013"].agent == "deep_research_agent"
    assert task_by_id["T-013"].execution_allowed is False
    assert task_by_id["T-013"].requires_human_review is True
    assert "T-012" in task_by_id["T-013"].depends_on
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-010") == ["T-013"]
    assert plan.deep_research.execution_allowed is False
    assert plan.deep_research.mode == "deep_reasoning_plan_only"


def test_patch_diff_learner_and_confirmed_seed_paths():
    plan = build_deep_research_plan(
        {
            "confirmed_findings": [
                {
                    "finding_id": "F-9",
                    "vuln_type": "ssrf",
                    "location": "fetch_url",
                    "risk": "high",
                    "reason": "confirmed seed for variants",
                }
            ],
            "patch_diff": {
                "source_ref": "commit-abc",
                "changed_files": ["app/fetch.py"],
                "root_cause": "missing allowlist",
                "fix_strategy": "host allowlist",
                "regression_test": "static sibling check",
            },
        }
    )
    assert plan.variant_analysis
    assert plan.patch_diff_learner.status == "advisory_pattern_ready"
    assert plan.patch_diff_learner.learned_patterns
    assert plan.patch_diff_learner.learned_patterns[0].root_cause_summary
    assert plan.execution_mode == "deep_reasoning_plan_only"
