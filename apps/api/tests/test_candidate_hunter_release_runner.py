from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.intelligence_benchmark.release_fixtures import load_release_fixture_suite
from app.intelligence_benchmark.release_runner import (
    ReleaseRunnerError,
    normalize_studio_candidates_for_release_v1,
    run_candidate_hunter_release_fixture,
    run_candidate_hunter_release_suite,
)
import app.intelligence_benchmark.release_runner as release_runner_module


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "candidate_hunter_release"


def _session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()


def test_normalizer_preserves_observed_candidate_fields_without_inventing_decisions():
    normalized = normalize_studio_candidates_for_release_v1(
        [
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization_gap",
                "root_cause_id": "missing-object-ownership-check",
                "location": "GET /files/{file_id}/export",
                "source_facts": [
                    {
                        "artifact_kind": "code",
                        "source_path": "routes.py",
                        "symbol_name": "export_file",
                    }
                ],
                "evidence_trace_summary": {
                    "status": "traceable",
                    "execution_allowed": False,
                    "validation_allowed": False,
                    "report_submission_allowed": False,
                },
                "human_validation_readiness": "ready",
                "safe_validation_plan": ["Review only the local fixture."],
                "safety_blockers": [
                    "execute_live_validation",
                    "touch_real_user_data",
                    "submit_report",
                ],
                "report_readiness": {
                    "report_submission_allowed": False,
                    "next_allowed_action": "Review evidence before report export.",
                },
            }
        ]
    )

    assert normalized == {
        "final_candidates": [
            {
                "candidate_id": "H-001",
                "rank": 1,
                "vuln_type": "authorization_gap",
                "root_cause_id": "missing-object-ownership-check",
                "route": {"method": "GET", "path": "/files/{file_id}/export"},
                "source_fact_refs": ["code:routes.py:export_file"],
                "evidence_trace_status": "traceable",
                "human_validation_readiness": "ready",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
                "safe_validation_plan": ["Review only the local fixture."],
                "next_allowed_action": "Review evidence before report export.",
                "safety_blockers": [
                    "execute_live_validation",
                    "touch_real_user_data",
                    "submit_report",
                ],
            }
        ],
        "candidate_decisions": [],
    }


def test_normalizer_assigns_consecutive_ranks_after_skipping_invalid_records():
    normalized = normalize_studio_candidates_for_release_v1(
        [
            None,
            {
                "hypothesis_id": "H-002",
                "vuln_type": "authorization_gap",
                "location": "GET /files/{file_id}/export",
            },
        ]
    )

    assert normalized["final_candidates"] == [
        {
            "candidate_id": "H-002",
            "rank": 1,
            "vuln_type": "authorization_gap",
            "route": {"method": "GET", "path": "/files/{file_id}/export"},
        }
    ]


def test_normalizer_carries_observed_semantic_root_cause_from_source_facts():
    normalized = normalize_studio_candidates_for_release_v1(
        [
            {
                "hypothesis_id": "H-003",
                "vuln_type": "authorization",
                "location": "GET /files/{file_id}/export",
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "root_cause": "missing_object_ownership_check",
                        "source_path": "routes.py",
                    }
                ],
            }
        ]
    )

    assert normalized["final_candidates"][0]["root_cause_id"] == (
        "missing_object_ownership_check"
    )


def test_runner_stages_all_inputs_captures_candidates_then_reads_gold(tmp_path: Path):
    case = next(
        item
        for item in load_release_fixture_suite(FIXTURE_ROOT, "development")
        if item.case_id == "dev-001"
    )
    session = _session()
    try:
        result = run_candidate_hunter_release_fixture(
            case,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
        )
    finally:
        session.close()

    assert result["events"] == [
        "inputs_staged",
        "candidates_captured",
        "loop_projected",
        "gold_loaded",
    ]
    assert result["workspace_path"].is_relative_to(tmp_path / "studio-workspaces")
    assert case.case_id not in result["workspace_path"].name
    assert "release" not in result["workspace_path"].name
    assert result["run"]["submission_blocked"] is True
    assert result["captured_candidates"]
    assert result["loop_audit"]["round_count"] == 2
    assert len(result["loop_audit"]["stage_refs"]) == 8
    assert result["normalized_output"]["candidate_decisions"][0][
        "disposition"
    ] == "retained"
    assert all(
        candidate["execution_allowed"] is False
        and candidate["validation_allowed"] is False
        and candidate["report_submission_allowed"] is False
        for candidate in result["normalized_output"]["final_candidates"]
    )
    assert result["evaluation"]["status"] == "failed"
    assert result["normalized_output"]["final_candidates"][0]["root_cause_id"] == (
        "missing_object_ownership_check:read_record"
    )
    assert result["evaluation"]["safety_failures"] == []


@pytest.mark.parametrize("suite", ["development", "release"])
def test_suite_runner_aggregates_complete_suite_only_after_all_captures(
    suite: str,
    tmp_path: Path,
):
    cases = list(load_release_fixture_suite(FIXTURE_ROOT, suite))
    session = _session()
    try:
        result = run_candidate_hunter_release_suite(
            cases,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
        )
    finally:
        session.close()

    assert result["events"] == ["all_candidates_captured", "gold_loaded"]
    assert all(
        case_run["events"]
        == ["inputs_staged", "candidates_captured", "loop_projected"]
        for case_run in result["case_runs"]
    )
    assert result["evaluation"]["version"] == "candidate_hunter_release_suite_v1"
    assert result["evaluation"]["status"] == "passed"
    assert len(result["evaluation"]["case_diagnostics"]) == 12
    assert all(
        metric["passed"] is True
        for metric in result["evaluation"]["metrics"].values()
    )
    assert not any(
        failure["reason"] == "zero_denominator"
        for failure in result["evaluation"]["schema_failures"]
    )


def test_suite_runner_rejects_incomplete_release_suite(tmp_path: Path):
    cases = list(load_release_fixture_suite(FIXTURE_ROOT, "release"))[:4]
    session = _session()
    try:
        with pytest.raises(ReleaseRunnerError, match="release_suite_case_count"):
            run_candidate_hunter_release_suite(
                cases,
                workspace_root=tmp_path / "studio-workspaces",
                session=session,
            )
    finally:
        session.close()


def test_runner_fails_closed_when_persisted_stage_projection_is_invalid(
    tmp_path: Path,
    monkeypatch,
):
    case = load_release_fixture_suite(FIXTURE_ROOT, "development")[0]
    received = {}

    def invalid_projection(*, repository, pipeline_run_id):
        received["repository"] = repository
        received["pipeline_run_id"] = pipeline_run_id
        return {
            "status": "invalid_stage_sequence",
            "failures": ["unsafe_stage"],
            "final_candidates": [],
            "candidate_decisions": [],
        }

    monkeypatch.setattr(
        release_runner_module,
        "load_candidate_hunter_projection",
        invalid_projection,
    )
    monkeypatch.setattr(
        release_runner_module,
        "evaluate_candidate_hunter_release_v1",
        lambda normalized_output, gold_oracle: {
            "status": "passed",
            "schema_failures": [],
        },
    )
    session = _session()
    try:
        result = run_candidate_hunter_release_fixture(
            case,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
        )
    finally:
        session.close()

    assert set(received) == {"repository", "pipeline_run_id"}
    assert received["pipeline_run_id"] == result["run"]["run_id"]
    assert result["loop_audit"] == {
        "status": "invalid_stage_sequence",
        "failures": ["unsafe_stage"],
    }
    assert result["normalized_output"] == {
        "final_candidates": [],
        "candidate_decisions": [],
    }
    assert result["evaluation"]["status"] == "failed"
    assert result["evaluation"]["stage_audit_failures"] == [
        {
            "path": "loop_audit",
            "reason": "invalid_stage_sequence",
        }
    ]
