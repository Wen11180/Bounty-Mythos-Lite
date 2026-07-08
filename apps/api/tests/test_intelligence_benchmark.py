import json

from app.cli import main as cli_main
from app.intelligence_benchmark import (
    build_studio_expectations_template,
    evaluate_studio_candidates,
)


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
            "code_path": "routes.py:export_file",
        }
    ]
    assert "Authorization: Bearer" in template["forbidden_text"]
    assert "Studio benchmark template written" in capsys.readouterr().out
