from app.deep_research import build_deep_research_plan, build_knowledge_artifact


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
    serialized = str(artifact.to_dict())

    assert artifact.artifact_type == "v4_advisory_knowledge"
    assert artifact.status == "requires_human_review"
    assert artifact.storage_policy == "metadata_only_no_raw_secret_or_user_data"
    assert artifact.entries[0].source_ref == "H-001"
    assert artifact.entries[0].review_required is True
    assert artifact.entries[0].confidence == "low"
    assert "should-not-leak" not in serialized


def test_patch_diff_learner_extracts_advisory_pattern_without_raw_diff_or_execution():
    plan = build_deep_research_plan(
        {
            "source_hypotheses": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization",
                    "location": "GET /api/orders/{order_id}",
                    "risk": "high",
                    "reason": "Missing ownership check.",
                }
            ],
            "patch_diff": {
                "linked_hypothesis_id": "H-001",
                "changed_files": ["app/services/orders.py"],
                "root_cause": "missing_object_ownership_check",
                "fix_strategy": "service_layer_owner_guard",
                "regression_test": "test_user_cannot_read_peer_order",
                "raw_diff": "Authorization: Bearer should-not-leak",
            },
        }
    )

    serialized = str(plan.to_dict())

    assert plan.patch_diff_learner.status == "advisory_pattern_ready"
    assert plan.patch_diff_learner.learned_patterns[0].source_ref == "H-001"
    assert plan.patch_diff_learner.learned_patterns[0].changed_files == [
        "app/services/orders.py"
    ]
    assert plan.patch_diff_learner.learned_patterns[0].execution_allowed is False
    assert plan.patch_diff_learner.learned_patterns[0].human_review_required is True
    assert "patch_diff_pattern" in plan.knowledge_updates[-1].retained_fields
    assert "should-not-leak" not in serialized

    artifact = build_knowledge_artifact(plan)
    artifact_entries = {
        entry.source_ref: entry
        for entry in artifact.entries
    }
    assert "patch_diff:H-001" in artifact_entries
    assert artifact_entries["patch_diff:H-001"].review_required is True
    assert artifact_entries["patch_diff:H-001"].confidence == "medium"


def test_confirmed_finding_seeds_unverified_variant_candidates_only():
    plan = build_deep_research_plan(
        {
            "confirmed_findings": [
                {
                    "finding_id": "F-001",
                    "vuln_type": "authorization",
                    "location": "GET /api/orders/{order_id}",
                    "root_cause": "missing_object_ownership_check",
                }
            ]
        }
    )

    assert plan.vulnerability_chains[0].source_hypothesis_id == "F-001"
    assert plan.vulnerability_chains[0].execution_allowed is False
    assert plan.variant_analysis[0].source_hypothesis_id == "F-001"
    assert plan.variant_analysis[0].status == "unverified_hypothesis_from_confirmed_finding"
    assert plan.variant_analysis[0].safe_next_step == (
        "search authorized local code for comparable guards and sinks"
    )
    assert plan.knowledge_consolidation_queue[0].source_ref == "F-001"
    assert plan.knowledge_consolidation_queue[0].human_review_required is True
    assert plan.knowledge_updates[0].status == "advisory_only"
    assert plan.knowledge_updates[0].source_ref == "F-001"
    assert plan.knowledge_updates[0].applicability_boundary == (
        "authorized_local_artifacts_only"
    )
    assert "current_vulnerability_proof" not in plan.knowledge_updates[0].retained_fields
    assert "no_exploit_generation" in plan.safety_invariants
