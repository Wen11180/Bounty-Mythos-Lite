import json

from app.deep_research import build_deep_research_plan, build_knowledge_artifact
from app.knowledge_base import run_knowledge_base
from app.multi_engine_verifier import build_multi_engine_verdict, signal_from_knowledge_base
from app.source_audit import build_source_audit_pipeline_payload, run_source_audit


def test_confirmed_finding_generates_only_unverified_variant_candidate():
    plan = build_deep_research_plan(
        {
            "confirmed_findings": [
                {
                    "finding_id": "F-001",
                    "vuln_type": "ssrf",
                    "location": "app/fetch.py:fetch_url",
                }
            ]
        }
    )

    assert len(plan.variant_analysis) == 1
    variant = plan.variant_analysis[0]
    assert variant.source_hypothesis_id == "F-001"
    assert variant.status == "unverified_hypothesis_from_confirmed_finding"
    assert variant.search_pattern == "similar_ssrf_boundary_near_app/fetch.py:fetch_url"
    assert all(chain.execution_allowed is False for chain in plan.vulnerability_chains)


def test_knowledge_base_is_decision_neutral_for_candidate_verification():
    candidate = {"candidate_id": "C-001"}
    supporting_signals = {
        "hunter_signal": {"status": "ready", "supports_candidate": True},
        "report_bridge_signal": {"status": "ready", "supports_candidate": True},
    }
    baseline = build_multi_engine_verdict(candidate=candidate, **supporting_signals)

    knowledge_base = run_knowledge_base(
        bridge_result={"package_id": "phase7-acceptance"}
    ).to_dict()
    knowledge_signal = signal_from_knowledge_base(knowledge_base)
    with_knowledge = build_multi_engine_verdict(
        candidate=candidate,
        knowledge_base_signal=knowledge_signal,
        **supporting_signals,
    )

    assert knowledge_signal is not None
    assert knowledge_signal.get("supports_candidate") is None
    assert with_knowledge.status == baseline.status
    assert with_knowledge.agreement_score == baseline.agreement_score
    assert with_knowledge.execution_allowed is False
    assert with_knowledge.validation_allowed is False
    assert with_knowledge.report_submission_allowed is False
    assert with_knowledge.confirmed_vulnerability is False

    missing_signal = signal_from_knowledge_base(
        {"status": "knowledge_base_package_missing"}
    )
    missing_catalog = build_multi_engine_verdict(
        candidate=candidate,
        knowledge_base_signal=missing_signal,
        **supporting_signals,
    )
    assert missing_signal is not None
    assert missing_signal["status"] != "blocked"
    assert missing_catalog.status == baseline.status

    catalog_error = build_multi_engine_verdict(
        candidate=candidate,
        knowledge_base_signal={"status": "error", "notes": ["catalog_unavailable"]},
        **supporting_signals,
    )
    assert catalog_error.status == baseline.status

    direct_knowledge_support = build_multi_engine_verdict(
        candidate=candidate,
        knowledge_base_signal={"status": "ready", "supports_candidate": True},
    )
    assert direct_knowledge_support.status == "needs_verification"

    unsafe_signal = signal_from_knowledge_base(
        {**knowledge_base, "ranking_permission_granted": True}
    )
    blocked = build_multi_engine_verdict(
        candidate=candidate,
        knowledge_base_signal=unsafe_signal,
        **supporting_signals,
    )
    assert blocked.status == "blocked"


def test_knowledge_updates_keep_traceable_source_and_applicability_boundary():
    plans = [
        build_deep_research_plan({}),
        build_deep_research_plan(
            {
                "source_hypotheses": [{"vuln_type": "authorization"}],
            }
        ),
        build_deep_research_plan(
            {
                "source_hypotheses": [
                    {"hypothesis_id": "H-007", "vuln_type": "authorization"}
                ],
                "patch_diff": {
                    "source_ref": "commit-abc",
                    "linked_hypothesis_id": "H-007",
                    "changed_files": ["app/service.py"],
                    "root_cause": "missing ownership guard",
                    "fix_strategy": "add ownership guard",
                    "regression_test": "local regression test",
                },
            }
        ),
    ]

    updates = [update for plan in plans for update in plan.knowledge_updates]
    queue_items = [item for plan in plans for item in plan.knowledge_consolidation_queue]
    assert updates
    assert queue_items
    assert all(update.source_ref not in {"", "none", "unknown"} for update in updates)
    assert all(update.applicability_boundary for update in updates)
    assert all(item.source_ref not in {"", "none", "unknown"} for item in queue_items)
    assert any(
        update.source_ref == "patch_diff:H-007"
        and update.applicability_boundary == "reviewed_patch_diff_patterns_only"
        for update in updates
    )

    generated_plan = plans[1]
    generated_source = "generated:hypothesis-001"
    assert generated_plan.cross_file_reasoning[0].evidence_refs == [generated_source]
    assert generated_plan.vulnerability_chains[0].source_hypothesis_id == generated_source
    assert generated_plan.variant_analysis[0].source_hypothesis_id == generated_source
    assert generated_plan.evidence_graph.nodes[0].node_id == generated_source


def test_patch_diff_source_ref_is_redacted_before_any_research_payload(tmp_path):
    marker = "phase7-secret-marker"
    untrusted_refs = [
        f"token={marker}",
        "H-phase7opaquevalue",
        "a" * 40,
    ]
    for source_ref in untrusted_refs:
        patch_diff = {
            "source_ref": source_ref,
            "changed_files": ["app/service.py"],
            "root_cause": "missing ownership guard",
            "fix_strategy": "add ownership guard",
            "regression_test": "local regression test",
        }
        plan = build_deep_research_plan({"patch_diff": patch_diff})
        artifact = build_knowledge_artifact(plan)
        serialized = json.dumps({"plan": plan.to_dict(), "artifact": artifact.to_dict()})

        assert source_ref not in serialized
        assert plan.patch_diff_learner.learned_patterns[0].source_ref == "unattributed_patch_diff"

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "service.py").write_text("def read_item():\n    return 1\n", encoding="utf-8")
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    result = run_source_audit(
        repo,
        scope,
        patch_diff_metadata={
            "source_ref": untrusted_refs[1],
            "changed_files": ["app/service.py"],
            "root_cause": "missing ownership guard",
            "fix_strategy": "add ownership guard",
            "regression_test": "local regression test",
        },
    )
    payload = build_source_audit_pipeline_payload(result)

    serialized_payload = json.dumps(payload)
    assert marker not in serialized_payload
    assert untrusted_refs[1] not in serialized_payload
