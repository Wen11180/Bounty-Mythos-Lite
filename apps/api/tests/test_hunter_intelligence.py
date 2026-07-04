from app.hunter_intelligence import (
    assess_hunter_intelligence,
    recommend_hunter_operating_action,
)


def test_assess_hunter_intelligence_prioritizes_bola_file_export_with_human_review():
    intelligence = assess_hunter_intelligence(
        target_model={
            "objects": [{"name": "file_id"}],
            "sensitive_actions": [
                {"action": "export", "method": "GET", "path": "/files/{file_id}/export"}
            ],
        },
        hypotheses=[
            {
                "hypothesis": "Changing file_id may export another user's private file.",
                "vuln_type": "broken_access_control",
                "risk_level": "high",
                "policy_risk": "low",
                "validation_mode": "two_account_authorization_check",
                "evidence_needed": ["two low-privilege test accounts"],
            }
        ],
        refutation={"status": "blocked", "reasons": ["human_approval_required"]},
    )

    assessment = intelligence.assessments[0]
    assert intelligence.top_recommendation == "needs_human_review"
    assert assessment.playbook_id == "bola_idor"
    assert assessment.hunter_priority_score >= 55
    assert assessment.impact_score >= 80
    assert assessment.policy_risk_score < 30
    assert assessment.rejection_risk_score < 45
    assert assessment.next_action == "Prepare human-approved, test-account-only validation."
    assert "no_live_requests" in assessment.safety_notes


def test_assess_hunter_intelligence_uses_object_relationships_for_boundary_judgment():
    intelligence = assess_hunter_intelligence(
        target_model={
            "objects": [
                {"name": "org_id"},
                {"name": "team_id"},
                {"name": "file_id"},
            ],
            "sensitive_actions": [
                {
                    "action": "export",
                    "method": "GET",
                    "path": "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export",
                }
            ],
            "relationships": [
                {
                    "parent_object": "org_id",
                    "child_object": "team_id",
                    "relationship": "contains",
                },
                {
                    "parent_object": "team_id",
                    "child_object": "file_id",
                    "relationship": "contains",
                },
            ],
        },
        hypotheses=[
            {
                "hypothesis": "Changing file_id may export another user's private file.",
                "vuln_type": "broken_access_control",
                "risk_level": "high",
                "policy_risk": "low",
                "validation_mode": "two_account_authorization_check",
            }
        ],
        refutation={"status": "blocked", "reasons": ["human_approval_required"]},
    )

    assessment = intelligence.assessments[0]
    assert assessment.hunter_priority_score >= 65
    assert "target_relationship:org_id>team_id>file_id" in assessment.reasons
    assert "parent_child_authorization_matrix" in assessment.evidence_focus


def test_assess_hunter_intelligence_penalizes_money_flow_policy_risk():
    intelligence = assess_hunter_intelligence(
        target_model={
            "objects": [{"name": "invoice_id"}],
            "sensitive_actions": [
                {"action": "refund", "method": "POST", "path": "/invoices/{invoice_id}/refund"}
            ],
        },
        hypotheses=[
            {
                "hypothesis": "Client refund amount may be trusted by the server.",
                "vuln_type": "business_logic_authorization",
                "risk_level": "critical",
                "policy_risk": "medium",
                "validation_mode": "non_destructive_request_review",
                "evidence_needed": ["non-destructive request review"],
            }
        ],
        refutation={"status": "passed", "reasons": []},
    )

    assessment = intelligence.assessments[0]
    assert assessment.playbook_id == "money_flow_tampering"
    assert assessment.impact_score == 95
    assert assessment.policy_risk_score >= 40
    assert assessment.recommendation == "pursue_with_care"
    assert assessment.next_action == "Review requests locally before any human-approved validation."


def test_assess_hunter_intelligence_blocks_out_of_scope_candidates():
    intelligence = assess_hunter_intelligence(
        target_model={"objects": [{"name": "team_id"}], "sensitive_actions": []},
        hypotheses=[
            {
                "hypothesis": "Member may change team settings.",
                "vuln_type": "privilege_escalation",
                "risk_level": "high",
                "policy_risk": "low",
                "validation_mode": "role_based_authorization_check",
                "evidence_needed": ["role matrix"],
            }
        ],
        refutation={"status": "blocked", "reasons": ["out_of_scope"]},
    )

    assessment = intelligence.assessments[0]
    assert intelligence.top_recommendation == "blocked"
    assert assessment.recommendation == "blocked"
    assert assessment.hunter_priority_score == 0
    assert assessment.next_action == "Do not validate; resolve scope or policy blocker first."


def test_recommend_hunter_operating_action_promotes_high_quality_reviewed_claim():
    intelligence = assess_hunter_intelligence(
        target_model={
            "objects": [{"name": "file_id"}],
            "sensitive_actions": [
                {"action": "export", "method": "GET", "path": "/files/{file_id}/export"}
            ],
        },
        hypotheses=[
            {
                "hypothesis": "Changing file_id may export another user's private file.",
                "vuln_type": "broken_access_control",
                "risk_level": "high",
                "policy_risk": "low",
                "validation_mode": "two_account_authorization_check",
            }
        ],
        refutation={"status": "blocked", "reasons": ["human_approval_required"]},
    )

    signal = recommend_hunter_operating_action(
        intelligence.assessments[0],
        claim_quality_score=92,
        readiness_level="human_reviewed_gated",
    )

    assert signal.action == "promote_to_finding_candidate"
    assert signal.claim_quality_score == 92
    assert "claim_quality:high" in signal.reasons
    assert "human_gate:still_required" in signal.safety_notes


def test_recommend_hunter_operating_action_parks_duplicate_risk_before_promotion():
    intelligence = assess_hunter_intelligence(
        target_model={"objects": [{"name": "status"}], "sensitive_actions": []},
        hypotheses=[
            {
                "hypothesis": "Service status banner might expose generic metadata.",
                "vuln_type": "information_disclosure",
                "risk_level": "medium",
                "policy_risk": "low",
            }
        ],
        refutation={"status": "passed", "reasons": []},
    )

    signal = recommend_hunter_operating_action(
        intelligence.assessments[0],
        claim_quality_score=90,
        readiness_level="human_reviewed_gated",
    )

    assert signal.action == "park_duplicate_risk"
    assert "duplicate_risk:high" in signal.reasons
