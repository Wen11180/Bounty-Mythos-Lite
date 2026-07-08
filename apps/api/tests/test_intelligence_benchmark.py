import json
from pathlib import Path

from app.cli import main as cli_main
from app.intelligence_benchmark import (
    build_studio_expectations_template,
    evaluate_studio_candidates,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "studio_benchmarks"


def test_evaluate_studio_candidates_passes_on_traceable_ab_candidate():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "required_artifacts": ["code", "api", "har"],
                }
            ],
            "forbidden_text": ["secret-token", "Authorization: Bearer"],
        },
    )

    assert result["status"] == "passed"
    assert result["matched"] == 1
    assert result["failures"] == []
    assert result["safety"]["forbidden_text_present"] == []


def test_ab_file_export_benchmark_fixture_passes_quality_gate():
    candidates_payload = json.loads(
        (FIXTURE_ROOT / "ab_file_export_candidates.json").read_text(encoding="utf-8")
    )
    expectations = json.loads(
        (FIXTURE_ROOT / "ab_file_export_expectations.json").read_text(encoding="utf-8")
    )

    result = evaluate_studio_candidates(candidates_payload, expectations)

    assert result["status"] == "passed"
    assert result["candidate_count"] == 1
    assert result["expected_count"] == 1
    assert result["matched"] == 1
    assert result["failures"] == []
    assert result["evidence_gaps"] == []
    assert result["safety"]["forbidden_text_present"] == []


def test_evaluate_studio_candidates_fails_without_expected_candidates():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "routes.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {"expected_candidates": []},
    )

    assert result["status"] == "failed"
    assert {"name": "benchmark", "reason": "no_expected_candidates"} in result["failures"]


def test_build_studio_expectations_template_uses_safe_candidate_metadata_only():
    template = build_studio_expectations_template(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization",
                    "location": "GET /files/{file_id}/export",
                    "reason": "send_file(file_id) should not be copied",
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "C:/target/routes.py",
                            "symbol_name": "export_file",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        }
    )

    assert template["draft_review_required"] is True
    assert template["max_candidates"] == 5
    assert template["expected_candidates"] == [
        {
            "name": "authorization at GET /files/{file_id}/export",
            "route_method": "GET",
            "route_path": "/files/{file_id}/export",
            "vuln_type": "authorization",
            "required_artifacts": ["code", "api", "har"],
            "require_code_path": True,
            "require_refutation_status": True,
            "require_security_invariant": True,
            "require_impact_rationale": True,
            "require_repair_guidance": True,
            "require_regression_test": True,
            "max_duplicate_risk_score": 49,
            "code_path": "routes.py:export_file",
        }
    ]
    assert "Authorization: Bearer" in template["forbidden_text"]
    assert "send_file(file_id)" not in str(template)


def test_build_studio_expectations_template_preserves_ab_required_artifacts():
    template = build_studio_expectations_template(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization",
                    "location": "GET /files/{file_id}/export",
                    "source_facts": [
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        }
    )

    assert template["expected_candidates"][0]["required_artifacts"] == [
        "code",
        "api",
        "har",
    ]
    assert template["expected_candidates"][0]["require_code_path"] is True
    assert template["expected_candidates"][0]["require_refutation_status"] is True
    assert template["expected_candidates"][0]["require_security_invariant"] is True
    assert template["expected_candidates"][0]["require_impact_rationale"] is True
    assert template["expected_candidates"][0]["require_repair_guidance"] is True
    assert template["expected_candidates"][0]["require_regression_test"] is True
    assert template["expected_candidates"][0]["max_duplicate_risk_score"] == 49


def test_evaluate_studio_candidates_requires_any_code_path_when_marked_required():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "required_artifacts": ["code", "api", "har"],
                    "require_code_path": True,
                }
            ]
        },
    )

    assert result["status"] == "failed"
    assert {
        "name": "file export authz gap",
        "reason": "missing_code_path",
    } in result["failures"]


def test_evaluate_studio_candidates_requires_refutation_and_low_duplicate_risk_when_expected():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "duplicate_risk_score": 75,
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "src/routes.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "required_artifacts": ["code", "api", "har"],
                    "require_refutation_status": True,
                    "max_duplicate_risk_score": 49,
                }
            ]
        },
    )

    assert result["status"] == "failed"
    assert {
        "name": "file export authz gap",
        "reason": "missing_refutation_status",
    } in result["failures"]
    assert {
        "name": "file export authz gap",
        "reason": "duplicate_risk_too_high:75",
    } in result["failures"]


def test_evaluate_studio_candidates_requires_duplicate_risk_score_when_expected():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "refutation_status": "unverified",
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "src/routes.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "required_artifacts": ["code", "api", "har"],
                    "max_duplicate_risk_score": 49,
                }
            ]
        },
    )

    assert result["status"] == "failed"
    assert {
        "name": "file export authz gap",
        "reason": "missing_duplicate_risk_score",
    } in result["failures"]


def test_evaluate_studio_candidates_requires_repair_guidance_and_regression_test_when_expected():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "broken_invariant": "Private files require ownership checks.",
                    "impact_rationale": "Cross-user file export can expose sensitive data.",
                    "refutation_status": "unverified",
                    "duplicate_risk_score": 10,
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "src/routes.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "required_artifacts": ["code", "api", "har"],
                    "require_repair_guidance": True,
                    "require_regression_test": True,
                }
            ]
        },
    )

    assert result["status"] == "failed"
    assert {
        "name": "file export authz gap",
        "reason": "missing_repair_guidance",
    } in result["failures"]
    assert {
        "name": "file export authz gap",
        "reason": "missing_regression_test",
    } in result["failures"]


def test_evaluate_studio_candidates_requires_invariant_and_impact_when_expected():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "src/routes.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "required_artifacts": ["code", "api", "har"],
                    "require_security_invariant": True,
                    "require_impact_rationale": True,
                }
            ]
        },
    )

    assert result["status"] == "failed"
    assert {
        "name": "file export authz gap",
        "reason": "missing_security_invariant",
    } in result["failures"]
    assert {
        "name": "file export authz gap",
        "reason": "missing_impact_rationale",
    } in result["failures"]


def test_evaluate_studio_candidates_accepts_invariant_and_impact_ranking_reason():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "broken_invariant": "Private files require ownership checks.",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "ranking_reasons": ["impact:sensitive_data_sink"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "src/routes.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "required_artifacts": ["code", "api", "har"],
                    "require_security_invariant": True,
                    "require_impact_rationale": True,
                }
            ]
        },
    )

    assert result["status"] == "passed"
    assert result["matched"] == 1


def test_evaluate_studio_candidates_reports_artifact_evidence_gaps():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "required_artifacts": ["code", "api", "har"],
                    "require_code_path": True,
                }
            ]
        },
    )

    assert result["status"] == "failed"
    assert result["evidence_gaps"] == [
        {
            "name": "file export authz gap",
            "artifact_kind": "har",
            "reason": "missing_required_artifact",
        },
        {
            "name": "file export authz gap",
            "artifact_kind": "code",
            "reason": "missing_code_path",
        },
    ]


def test_evaluate_studio_candidates_fails_closed_on_missing_quality_and_secret_leak():
    result = evaluate_studio_candidates(
        [
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization_gap",
                "location": "GET /files/{file_id}/export",
                "evidence_needed": [],
                "false_positive_checks": [],
                "safe_validation_plan": [],
                "safety_blockers": [],
                "report_readiness": {
                    "status": "ready",
                    "report_submission_allowed": True,
                },
                "source_facts": [
                    {
                        "artifact_kind": "api",
                        "route_method": "GET",
                        "route_path": "/files/{file_id}/export",
                    }
                ],
                "debug": "Authorization: Bearer secret-token",
            }
        ],
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "required_artifacts": ["code", "api", "har"],
                }
            ],
            "forbidden_text": ["secret-token", "Authorization: Bearer"],
        },
    )

    assert result["status"] == "failed"
    assert result["matched"] == 0
    assert {
        failure["reason"]
        for failure in result["failures"]
    } >= {
        "missing_evidence_needed",
        "missing_false_positive_checks",
        "missing_safe_validation_plan",
        "missing_required_artifacts:code,har",
        "report_not_submission_blocked",
        "report_submission_allowed",
        "missing_safety_blockers",
        "forbidden_text_present",
    }
    assert result["safety"]["forbidden_text_present"] == [
        "secret-token",
        "Authorization: Bearer",
    ]


def test_evaluate_studio_candidates_fails_when_candidate_set_is_noisy():
    good_candidate = {
        "hypothesis_id": "H-001",
        "vuln_type": "authorization_gap",
        "location": "GET /files/{file_id}/export",
        "evidence_needed": ["Two authorized test accounts"],
        "false_positive_checks": ["Does the service enforce ownership?"],
        "safe_validation_plan": ["Use local test accounts only"],
        "safety_blockers": [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
        ],
        "report_readiness": {
            "status": "submission_blocked",
            "report_submission_allowed": False,
        },
        "source_facts": [
            {
                "artifact_kind": "code",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
            },
            {
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": "/files/{id}/export",
            },
            {
                "artifact_kind": "har",
                "route_method": "GET",
                "route_path": "/files/123/export",
            },
        ],
    }
    noisy_candidates = [
        {**good_candidate, "hypothesis_id": f"H-{index:03d}"}
        for index in range(1, 7)
    ]

    result = evaluate_studio_candidates(
        {"candidates": noisy_candidates},
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "required_artifacts": ["code", "api", "har"],
                }
            ]
        },
    )

    assert result["status"] == "failed"
    assert {"name": "candidate_set", "reason": "too_many_candidates:6"} in result["failures"]
    assert result["failures"].count(
        {"name": "candidate_set", "reason": "too_many_candidates:6"}
    ) == 1


def test_evaluate_studio_candidates_fails_when_expectation_set_is_noisy():
    candidate = {
        "hypothesis_id": "H-001",
        "vuln_type": "authorization_gap",
        "location": "GET /files/{file_id}/export",
        "broken_invariant": "Private files require ownership checks.",
        "evidence_needed": ["Two authorized test accounts"],
        "false_positive_checks": ["Does the service enforce ownership?"],
        "ranking_reasons": ["impact:sensitive_data_sink"],
        "safe_validation_plan": ["Use local test accounts only"],
        "safety_blockers": [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
        ],
        "report_readiness": {
            "status": "submission_blocked",
            "report_submission_allowed": False,
            "next_allowed_action": "Review evidence and safety blockers before export.",
        },
        "source_facts": [
            {
                "artifact_kind": "code",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "routes.py",
            },
            {
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": "/files/{id}/export",
            },
            {
                "artifact_kind": "har",
                "route_method": "GET",
                "route_path": "/files/123/export",
            },
        ],
    }
    expected_candidates = [
        {
            "name": f"expected authz gap {index}",
            "route_method": "GET",
            "route_path": "/files/{file_id}/export",
            "vuln_type": "authorization_gap",
            "required_artifacts": ["code", "api", "har"],
        }
        for index in range(6)
    ]

    result = evaluate_studio_candidates(
        {"candidates": [candidate]},
        {"expected_candidates": expected_candidates},
    )

    assert result["status"] == "failed"
    assert {
        "name": "expected_candidate_set",
        "reason": "too_many_expected_candidates:6",
    } in result["failures"]


def test_evaluate_studio_candidates_applies_lower_expectation_max_candidates():
    expected_candidates = [
        {
            "name": f"expected authz gap {index}",
            "route_method": "GET",
            "route_path": f"/files/{index}/export",
            "vuln_type": "authorization_gap",
            "required_artifacts": ["code", "api", "har"],
        }
        for index in range(4)
    ]

    result = evaluate_studio_candidates(
        {"candidates": []},
        {"max_candidates": 3, "expected_candidates": expected_candidates},
    )

    assert {
        "name": "expected_candidate_set",
        "reason": "too_many_expected_candidates:4",
    } in result["failures"]


def test_evaluate_studio_candidates_requires_expected_code_path():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "views.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "code_path": "routes.py",
                    "required_artifacts": ["code", "api", "har"],
                }
            ]
        },
    )

    assert result["status"] == "failed"
    assert {"name": "file export authz gap", "reason": "missing_code_path:routes.py"} in result[
        "failures"
    ]


def test_evaluate_studio_candidates_accepts_expected_symbol_code_path():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "src/routes.py",
                            "symbol_name": "export_file",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "code_path": "routes.py:export_file",
                    "required_artifacts": ["code", "api", "har"],
                }
            ]
        },
    )

    assert result["status"] == "passed"
    assert result["matched"] == 1


def test_evaluate_studio_candidates_requires_scanner_artifacts_to_stay_advisory():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "src/routes.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                        {
                            "artifact_kind": "sarif",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "code_path": "routes.py",
                    "required_artifacts": ["code", "api", "har", "sarif"],
                }
            ]
        },
    )

    assert result["status"] == "failed"
    assert {
        "name": "file export authz gap",
        "reason": "missing_advisory_signal:sarif",
    } in result["failures"]


def test_evaluate_studio_candidates_accepts_advisory_scanner_and_dependency_signals():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                        "next_allowed_action": "Review evidence and safety blockers before export.",
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "src/routes.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                        {
                            "artifact_kind": "sarif",
                            "fact_type": "scanner_signal",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "advisory_only": "true",
                        },
                        {
                            "artifact_kind": "sbom",
                            "fact_type": "dependency_signal",
                            "package_name": "django",
                            "advisory_only": "true",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "code_path": "routes.py",
                    "required_artifacts": ["code", "api", "har", "sarif", "sbom"],
                }
            ]
        },
    )

    assert result["status"] == "passed"
    assert result["matched"] == 1


def test_evaluate_studio_candidates_detects_forbidden_text_case_insensitively():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "routes.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                    "debug": "authorization: bearer redacted-but-still-raw-header-shape",
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "code_path": "routes.py",
                    "required_artifacts": ["code", "api", "har"],
                }
            ],
            "forbidden_text": ["Authorization: Bearer"],
        },
    )

    assert result["status"] == "failed"
    assert {"name": "safety", "reason": "forbidden_text_present"} in result["failures"]
    assert result["safety"]["forbidden_text_present"] == ["Authorization: Bearer"]


def test_evaluate_studio_candidates_requires_report_review_next_action():
    result = evaluate_studio_candidates(
        {
            "candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Two authorized test accounts"],
                    "false_positive_checks": ["Does the service enforce ownership?"],
                    "safe_validation_plan": ["Use local test accounts only"],
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "report_readiness": {
                        "status": "submission_blocked",
                        "report_submission_allowed": False,
                    },
                    "source_facts": [
                        {
                            "artifact_kind": "code",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "source_path": "routes.py",
                        },
                        {
                            "artifact_kind": "api",
                            "route_method": "GET",
                            "route_path": "/files/{id}/export",
                        },
                        {
                            "artifact_kind": "har",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        },
                    ],
                }
            ]
        },
        {
            "expected_candidates": [
                {
                    "name": "file export authz gap",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                    "vuln_type": "authorization_gap",
                    "code_path": "routes.py",
                    "required_artifacts": ["code", "api", "har"],
                }
            ]
        },
    )

    assert result["status"] == "failed"
    assert {
        "name": "file export authz gap",
        "reason": "missing_report_next_allowed_action",
    } in result["failures"]


def test_cli_studio_eval_writes_benchmark_result(tmp_path, capsys):
    candidates_path = tmp_path / "candidates.json"
    expectations_path = tmp_path / "expectations.json"
    output_path = tmp_path / "result.json"
    candidates_path.write_text(
        json.dumps(
            {
                "candidates": [
                    {
                        "hypothesis_id": "H-001",
                        "vuln_type": "authorization_gap",
                        "location": "GET /files/{file_id}/export",
                        "evidence_needed": ["Two authorized test accounts"],
                        "false_positive_checks": ["Does the service enforce ownership?"],
                        "safe_validation_plan": ["Use local test accounts only"],
                        "safety_blockers": [
                            "execute_live_validation",
                            "touch_real_user_data",
                            "submit_report",
                        ],
                        "report_readiness": {
                            "status": "submission_blocked",
                            "report_submission_allowed": False,
                            "next_allowed_action": "Review evidence and safety blockers before export.",
                        },
                        "source_facts": [
                            {
                                "artifact_kind": "code",
                                "route_method": "GET",
                                "route_path": "/files/{file_id}/export",
                            },
                            {
                                "artifact_kind": "api",
                                "route_method": "GET",
                                "route_path": "/files/{id}/export",
                            },
                            {
                                "artifact_kind": "har",
                                "route_method": "GET",
                                "route_path": "/files/123/export",
                            },
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    expectations_path.write_text(
        json.dumps(
            {
                "expected_candidates": [
                    {
                        "name": "file export authz gap",
                        "route_method": "GET",
                        "route_path": "/files/{file_id}/export",
                        "vuln_type": "authorization_gap",
                        "required_artifacts": ["code", "api", "har"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    exit_code = cli_main(
        [
            "studio-eval",
            "--candidates",
            str(candidates_path),
            "--expectations",
            str(expectations_path),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["status"] == "passed"
    assert "Studio benchmark passed" in capsys.readouterr().out


def test_cli_studio_eval_template_writes_reviewable_expectations(tmp_path, capsys):
    candidates_path = tmp_path / "candidates.json"
    output_path = tmp_path / "expectations-template.json"
    candidates_path.write_text(
        json.dumps(
            {
                "candidates": [
                    {
                        "hypothesis_id": "H-001",
                        "vuln_type": "authorization_gap",
                        "location": "GET /files/{file_id}/export",
                        "source_facts": [
                            {
                                "artifact_kind": "code",
                                "route_method": "GET",
                                "route_path": "/files/{file_id}/export",
                                "source_path": "src/routes.py",
                                "symbol_name": "export_file",
                            },
                            {
                                "artifact_kind": "api",
                                "route_method": "GET",
                                "route_path": "/files/{id}/export",
                            },
                            {
                                "artifact_kind": "har",
                                "route_method": "GET",
                                "route_path": "/files/123/export",
                            },
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    exit_code = cli_main(
        [
            "studio-eval-template",
            "--candidates",
            str(candidates_path),
            "--output",
            str(output_path),
        ]
    )

    template = json.loads(output_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert template["draft_review_required"] is True
    assert template["expected_candidates"] == [
        {
            "name": "authorization_gap at GET /files/{file_id}/export",
            "route_method": "GET",
            "route_path": "/files/{file_id}/export",
            "vuln_type": "authorization_gap",
            "required_artifacts": ["code", "api", "har"],
            "require_code_path": True,
            "require_refutation_status": True,
            "require_security_invariant": True,
            "require_impact_rationale": True,
            "require_repair_guidance": True,
            "require_regression_test": True,
            "max_duplicate_risk_score": 49,
            "code_path": "routes.py:export_file",
        }
    ]
    assert "Authorization: Bearer" in template["forbidden_text"]
    assert "Studio benchmark template written" in capsys.readouterr().out
