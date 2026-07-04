from app.models import Program, ScopeStatus
from app.mythos_brain import (
    LearningSignal,
    build_learning_signal_from_outcome,
    build_program_intelligence,
)


def test_build_program_intelligence_extracts_high_value_surface_memory():
    program = Program(
        id="program_example",
        name="Example Program",
        platform="HackerOne",
        bounty_range="High $3000 / Critical $10000",
        scope_status=ScopeStatus.IN_SCOPE,
        automation="limited",
        testing_accounts="configured",
        api_docs="imported",
        public_code="available",
        duplicate_risk="medium",
        priority="A",
    )
    pipeline_runs = [
        {
            "asset": "api.example.com",
            "payload": {
                "target_model": {
                    "objects": [{"name": "file_id"}, {"name": "team_id"}],
                    "sensitive_actions": [
                        {
                            "action": "export",
                            "method": "GET",
                            "path": "/files/{file_id}/export",
                            "roles": ["member"],
                        },
                        {
                            "action": "share",
                            "method": "POST",
                            "path": "/teams/{team_id}/shares",
                            "roles": ["admin", "member"],
                        },
                    ],
                    "roles": ["admin", "member"],
                },
                "hunter_intelligence": {
                    "assessments": [
                        {
                            "playbook_id": "bola_idor",
                            "hunter_priority_score": 68,
                            "recommendation": "needs_human_review",
                        }
                    ]
                },
            },
        }
    ]
    learning_signals = [
        LearningSignal(
            program_id="program_example",
            playbook_id="bola_idor",
            outcome="accepted",
            surface_key="file_id:export",
            notes="Accepted BOLA report on file export.",
        )
    ]

    profile = build_program_intelligence(
        program=program,
        pipeline_runs=pipeline_runs,
        learning_signals=learning_signals,
    )

    assert profile.program_id == "program_example"
    assert profile.program_score >= 80
    assert profile.attack_surface_memory.objects == ["file_id", "team_id"]
    assert profile.attack_surface_memory.roles == ["admin", "member"]
    assert profile.high_value_surfaces[0].surface_key == "file_id:export"
    assert profile.high_value_surfaces[0].score > profile.high_value_surfaces[1].score
    assert "learning:accepted" in profile.high_value_surfaces[0].reasons
    assert profile.learning_summary.accepted_count == 1
    assert profile.learning_summary.boosted_playbooks == ["bola_idor"]
    assert "no_live_requests" in profile.safety_notes


def test_build_program_intelligence_prioritizes_relationship_leaf_surfaces():
    program = Program(
        id="program_example",
        name="Example Program",
        platform="HackerOne",
        bounty_range="High $3000 / Critical $10000",
        scope_status=ScopeStatus.IN_SCOPE,
        automation="limited",
        testing_accounts="configured",
        api_docs="imported",
        public_code="available",
        duplicate_risk="medium",
        priority="A",
    )
    path = "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export"
    pipeline_runs = [
        {
            "asset": "api.example.com",
            "payload": {
                "target_model": {
                    "objects": [
                        {"name": "org_id"},
                        {"name": "team_id"},
                        {"name": "file_id"},
                    ],
                    "sensitive_actions": [
                        {
                            "action": "export",
                            "method": "GET",
                            "path": path,
                            "roles": ["member"],
                        }
                    ],
                    "relationships": [
                        {
                            "parent_object": "org_id",
                            "child_object": "team_id",
                            "relationship": "contains",
                            "path": path,
                        },
                        {
                            "parent_object": "team_id",
                            "child_object": "file_id",
                            "relationship": "contains",
                            "path": path,
                        },
                    ],
                    "roles": ["member"],
                },
                "hunter_intelligence": {
                    "assessments": [
                        {
                            "playbook_id": "bola_idor",
                            "hunter_priority_score": 73,
                            "recommendation": "needs_human_review",
                        }
                    ]
                },
            },
        }
    ]

    profile = build_program_intelligence(
        program=program,
        pipeline_runs=pipeline_runs,
        learning_signals=[],
    )

    surfaces = {surface.surface_key: surface for surface in profile.high_value_surfaces}
    assert [
        relationship.model_dump(mode="json")
        for relationship in profile.attack_surface_memory.relationships
    ] == [
        {
            "parent_object": "org_id",
            "child_object": "team_id",
            "relationship": "contains",
            "paths": [path],
        },
        {
            "parent_object": "team_id",
            "child_object": "file_id",
            "relationship": "contains",
            "paths": [path],
        },
    ]
    assert profile.high_value_surfaces[0].surface_key == "file_id:export"
    assert surfaces["file_id:export"].score > surfaces["team_id:export"].score
    assert surfaces["team_id:export"].score > surfaces["org_id:export"].score
    assert "target_relationship:org_id>team_id>file_id" in surfaces["file_id:export"].reasons


def test_build_program_intelligence_turns_duplicate_and_na_into_rejection_risk():
    program = Program(
        id="program_example",
        name="Example Program",
        platform="Bugcrowd",
        bounty_range="Medium $500 / High $3000",
        scope_status=ScopeStatus.IN_SCOPE,
        automation="limited",
        testing_accounts="configured",
        api_docs="imported",
        public_code="available",
        duplicate_risk="high",
        priority="B",
    )
    pipeline_runs = [
        {
            "asset": "app.example.com",
            "payload": {
                "target_model": {
                    "objects": [{"name": "team_id"}],
                    "sensitive_actions": [
                        {
                            "action": "write",
                            "method": "PATCH",
                            "path": "/teams/{team_id}/settings",
                            "roles": ["member"],
                        }
                    ],
                    "roles": ["member"],
                },
                "hunter_intelligence": {
                    "assessments": [
                        {
                            "playbook_id": "role_boundary",
                            "hunter_priority_score": 61,
                            "recommendation": "needs_human_review",
                        }
                    ]
                },
            },
        }
    ]
    learning_signals = [
        LearningSignal(
            program_id="program_example",
            playbook_id="role_boundary",
            outcome="duplicate",
            surface_key="team_id:write",
            notes="Triager marked similar report duplicate.",
        ),
        LearningSignal(
            program_id="program_example",
            playbook_id="role_boundary",
            outcome="na",
            surface_key="team_id:write",
            notes="Prior report lacked practical impact.",
        ),
    ]

    profile = build_program_intelligence(
        program=program,
        pipeline_runs=pipeline_runs,
        learning_signals=learning_signals,
    )

    assert profile.learning_summary.duplicate_count == 1
    assert profile.learning_summary.na_count == 1
    assert profile.learning_summary.rejection_risk_delta >= 20
    assert profile.learning_summary.penalized_playbooks == ["role_boundary"]
    assert "learning:duplicate_or_na" in profile.high_value_surfaces[0].reasons
    assert profile.high_value_surfaces[0].score < 70


def test_build_program_intelligence_weights_evidence_aware_learning_signals():
    program = Program(
        id="program_example",
        name="Example Program",
        platform="HackerOne",
        bounty_range="Medium $500 / High $3000",
        scope_status=ScopeStatus.IN_SCOPE,
        automation="limited",
        testing_accounts="not_configured",
        api_docs="missing",
        public_code="unavailable",
        duplicate_risk="medium",
        priority="C",
    )
    pipeline_runs = [
        {
            "asset": "api.example.com",
            "payload": {
                "target_model": {
                    "objects": [{"name": "file_id"}],
                    "sensitive_actions": [
                        {
                            "action": "export",
                            "method": "GET",
                            "path": "/files/{file_id}/export",
                            "roles": ["member"],
                        }
                    ],
                    "roles": ["member"],
                },
                "hunter_intelligence": {
                    "assessments": [
                        {
                            "playbook_id": "bola_idor",
                            "hunter_priority_score": 68,
                            "recommendation": "needs_human_review",
                        }
                    ]
                },
            },
        }
    ]
    accepted_only = [
        LearningSignal(
            program_id="program_example",
            playbook_id="bola_idor",
            outcome="accepted",
            surface_key="file_id:export",
        )
    ]
    evidence_aware = [
        LearningSignal(
            program_id="program_example",
            playbook_id="bola_idor",
            outcome="accepted",
            surface_key="file_id:export",
            bounty_amount=3000,
            severity_delta="up",
            evidence_quality="strong",
            triager_feedback="Triager confirmed clear cross-account impact.",
        )
    ]

    accepted_only_profile = build_program_intelligence(
        program=program,
        pipeline_runs=pipeline_runs,
        learning_signals=accepted_only,
    )
    evidence_aware_profile = build_program_intelligence(
        program=program,
        pipeline_runs=pipeline_runs,
        learning_signals=evidence_aware,
    )

    surface = evidence_aware_profile.high_value_surfaces[0]

    assert evidence_aware_profile.program_score > accepted_only_profile.program_score
    assert "learning:bounty_paid" in surface.reasons
    assert "learning:strong_evidence" in surface.reasons
    assert "learning:severity_up" in surface.reasons
    assert evidence_aware_profile.learning_summary.bounty_total == 3000
    assert evidence_aware_profile.learning_summary.strong_evidence_count == 1
    assert evidence_aware_profile.learning_summary.severity_up_count == 1
    assert evidence_aware_profile.recent_learning_signals[0].triager_feedback.startswith("Triager")


def test_build_program_intelligence_does_not_boost_surfaces_for_weak_accepted_evidence():
    program = Program(
        id="program_example",
        name="Example Program",
        platform="HackerOne",
        bounty_range="Medium $500 / High $3000",
        scope_status=ScopeStatus.IN_SCOPE,
        automation="limited",
        testing_accounts="configured",
        api_docs="imported",
        public_code="available",
        duplicate_risk="medium",
        priority="A",
    )
    pipeline_runs = [
        {
            "asset": "api.example.com",
            "payload": {
                "target_model": {
                    "objects": [{"name": "file_id"}],
                    "sensitive_actions": [
                        {
                            "action": "export",
                            "method": "GET",
                            "path": "/files/{file_id}/export",
                            "roles": ["member"],
                        }
                    ],
                    "roles": ["member"],
                },
                "hunter_intelligence": {
                    "assessments": [
                        {
                            "playbook_id": "bola_idor",
                            "hunter_priority_score": 68,
                            "recommendation": "needs_human_review",
                        }
                    ]
                },
            },
        }
    ]
    no_learning_profile = build_program_intelligence(
        program=program,
        pipeline_runs=pipeline_runs,
        learning_signals=[],
    )
    weak_accepted_profile = build_program_intelligence(
        program=program,
        pipeline_runs=pipeline_runs,
        learning_signals=[
            LearningSignal(
                program_id="program_example",
                playbook_id="bola_idor",
                outcome="accepted",
                surface_key="file_id:export",
                evidence_quality="weak",
            )
        ],
    )

    weak_surface = weak_accepted_profile.high_value_surfaces[0]

    assert weak_surface.score <= no_learning_profile.high_value_surfaces[0].score
    assert "learning:accepted" not in weak_surface.reasons
    assert "learning:weak_accepted_evidence_not_boosted" in weak_surface.reasons
    assert "learning:weak_evidence" in weak_surface.reasons
    assert weak_accepted_profile.learning_summary.weak_evidence_count == 1
    assert weak_accepted_profile.learning_summary.boosted_playbooks == []


def test_build_learning_signal_from_outcome_derives_surface_and_playbook_from_run():
    signal = build_learning_signal_from_outcome(
        program_id="program_example",
        outcome="accepted",
        notes="Accepted after triager confirmed cross-account export impact.",
        pipeline_run={
            "payload": {
                "target_model": {
                    "objects": [{"name": "file_id"}],
                    "sensitive_actions": [
                        {
                            "action": "export",
                            "method": "GET",
                            "path": "/files/{file_id}/export",
                        }
                    ],
                },
                "hunter_intelligence": {
                    "assessments": [
                        {
                            "playbook_id": "bola_idor",
                            "hunter_priority_score": 68,
                        }
                    ]
                },
            }
        },
    )

    assert signal.program_id == "program_example"
    assert signal.outcome == "accepted"
    assert signal.playbook_id == "bola_idor"
    assert signal.surface_key == "file_id:export"
    assert "triager confirmed" in signal.notes


def test_build_learning_signal_from_outcome_prefers_relationship_leaf_surface():
    path = "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export"

    signal = build_learning_signal_from_outcome(
        program_id="program_example",
        outcome="accepted",
        pipeline_run={
            "payload": {
                "target_model": {
                    "objects": [
                        {"name": "org_id"},
                        {"name": "team_id"},
                        {"name": "file_id"},
                    ],
                    "sensitive_actions": [
                        {
                            "action": "export",
                            "method": "GET",
                            "path": path,
                        }
                    ],
                    "relationships": [
                        {
                            "parent_object": "org_id",
                            "child_object": "team_id",
                            "relationship": "contains",
                            "path": path,
                        },
                        {
                            "parent_object": "team_id",
                            "child_object": "file_id",
                            "relationship": "contains",
                            "path": path,
                        },
                    ],
                },
                "hunter_intelligence": {
                    "assessments": [
                        {
                            "playbook_id": "bola_idor",
                            "hunter_priority_score": 73,
                        }
                    ]
                },
            }
        },
    )

    assert signal.surface_key == "file_id:export"
