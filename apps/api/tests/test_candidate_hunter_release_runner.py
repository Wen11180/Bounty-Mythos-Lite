from __future__ import annotations

from pathlib import Path
import json
import shutil

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.cross_source_candidate_generator import ReplayCandidateReasoner
from app.intelligence_benchmark.release_fixtures import (
    load_release_fixture_replay,
    load_release_fixture_suite,
)
from app.intelligence_benchmark.release_runner import (
    ReleaseRunnerError,
    normalize_studio_candidates_for_release_v1,
    run_candidate_hunter_authorized_lab_package,
    run_candidate_hunter_release_fixture,
    run_candidate_hunter_release_suite,
)
import app.intelligence_benchmark.release_runner as release_runner_module
from app.llm.base import ProviderName
from app.repository import DatabaseRepository


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "candidate_hunter_release"
TYPESCRIPT_FIXTURE_ROOT = (
    Path(__file__).parent / "fixtures" / "candidate_hunter_typescript_release"
)


def _session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()


@pytest.mark.parametrize(
    ("language", "code_name", "route", "operation_id", "code"),
    [
        (
            "python",
            "code.py",
            "/local/python/records/{record_id}",
            "read_python_record",
            '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/local/python/records/{record_id}")
def read_python_record(record_id: str):
    return send_file(record_id)
''',
        ),
        (
            "go",
            "code.go",
            "/local/go/records/{record_id}",
            "read_go_record",
            '''
func mount(r Router) { r.GET("/local/go/records/{record_id}", read_go_record) }

func read_go_record() {
    sendFile(recordID)
}
''',
        ),
    ],
)
def test_runner_accepts_authorized_multilang_lab_package(
    tmp_path: Path,
    language: str,
    code_name: str,
    route: str,
    operation_id: str,
    code: str,
):
    package_root = tmp_path / f"{language}-lab-package"
    inputs = package_root / "inputs"
    inputs.mkdir(parents=True)
    for name, body in {
        "scope.json": json.dumps(
            {
                "fixture_id": f"lab-{language}-r4m2",
                "allowed_repos": ["${STAGED_CODE_ROOT}"],
                "allowed_routes": [route],
                "local_only": True,
            }
        ),
        "policy.md": "Authorized local static review only.",
        "api.json": json.dumps(
            {
                "openapi": "3.0.0",
                "paths": {route: {"get": {"operationId": operation_id}}},
            }
        ),
        "traffic.har.json": '{"log":{"version":"1.2","entries":[]}}',
        code_name: code,
    }.items():
        (inputs / name).write_text(body, encoding="utf-8")
    (package_root / "package.json").write_text(
        json.dumps(
            {
                "package_id": f"lab-{language}-unguarded-record",
                "risk_family": "authorization",
                "expected_disposition": "retain",
                "authorized_for_local_research": True,
                "contains_real_user_data": False,
                "contains_secrets": False,
                "inputs": [
                    {"kind": "scope", "path": "inputs/scope.json"},
                    {"kind": "policy", "path": "inputs/policy.md"},
                    {"kind": "api", "path": "inputs/api.json"},
                    {"kind": "har", "path": "inputs/traffic.har.json"},
                    {"kind": "code", "path": f"inputs/{code_name}"},
                ],
            }
        ),
        encoding="utf-8",
    )
    session = _session()
    try:
        result = run_candidate_hunter_authorized_lab_package(
            package_root,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
        )
    finally:
        session.close()

    assert result["loop_audit"]["status"] == "ready"
    assert result["evaluation"]["status"] == "skipped_no_gold"
    decision = result["normalized_output"]["candidate_decisions"][0]
    assert decision["candidate_id"] == "H-001"
    assert decision["root_cause_id"] == (
        f"missing_object_ownership_check:{operation_id}"
    )
    assert decision["disposition"] == "retained"
    assert f"code:{code_name}:{operation_id}" in decision["evidence_refs"]
    assert result["normalized_output"]["final_candidates"][0][
        "execution_allowed"
    ] is False
    assert result["normalized_output"]["final_candidates"][0][
        "report_submission_allowed"
    ] is False


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
                "candidate_promotion_allowed": False,
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
                "candidate_promotion_allowed": False,
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
    assert "candidate_promotion_allowed" not in normalized["final_candidates"][0]


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


def test_runner_executes_typescript_case_with_replay_runtime(tmp_path: Path):
    runtime_type = getattr(release_runner_module, "ReleaseCaseModelRuntime", None)
    assert callable(runtime_type)
    case = load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development")[0]
    replay_payload = load_release_fixture_replay(case)
    replay_reasoner = ReplayCandidateReasoner(replay_payload)
    received_fact_packs = []

    class RecordingReplayReasoner:
        async def generate(self, *, fact_pack, model_config, request_key):
            received_fact_packs.append(fact_pack)
            return await replay_reasoner.generate(
                fact_pack=fact_pack,
                model_config=model_config,
                request_key=request_key,
            )

    runtime = runtime_type(
        provider=ProviderName.OPENAI,
        model="fixture-replay-v1",
        reasoner=RecordingReplayReasoner(),
        audit_mode="replay",
    )
    session = _session()
    try:
        result = run_candidate_hunter_release_fixture(
            case,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
            model_runtime=runtime,
        )
        llm_runs = DatabaseRepository(session).list_llm_runs()
    finally:
        session.close()

    generation = result["run"]["candidate_generation"]
    assert generation["model_status"] == "completed"
    assert generation["accepted_count"] >= 1
    assert result["loop_audit"]["status"] == "ready"
    assert result["loop_audit"]["round_count"] == 2
    assert result["run"]["submission_blocked"] is True
    assert all(
        candidate[field] is False
        for candidate in result["normalized_output"]["final_candidates"]
        for field in (
            "execution_allowed",
            "validation_allowed",
            "candidate_promotion_allowed",
            "report_submission_allowed",
        )
    )
    assert len(llm_runs) == 1
    assert llm_runs[0].mode == "replay"
    assert "synthetic_replay_no_provider_call" in llm_runs[0].safety_notes
    assert len(received_fact_packs) == 1
    fact_pack_payload = received_fact_packs[0].model_dump(mode="json")
    serialized_fact_pack = str(fact_pack_payload).lower()
    assert case.case_id.lower() not in serialized_fact_pack
    assert case.suite not in serialized_fact_pack
    assert (
        replay_payload["proposals"][0]["impact_rationale"].lower()
        not in serialized_fact_pack
    )
    forbidden_control_keys = {
        "caseid",
        "suite",
        "authorizationpattern",
        "profile",
        "manifest",
        "expecteddisposition",
        "goldid",
        "duplicateof",
    }

    def normalized_keys(value: object) -> set[str]:
        if isinstance(value, list):
            return set().union(*(normalized_keys(item) for item in value), set())
        if not isinstance(value, dict):
            return set()
        current = {
            "".join(character for character in str(key).lower() if character.isalnum())
            for key in value
        }
        return current | set().union(
            *(normalized_keys(item) for item in value.values()),
            set(),
        )

    assert normalized_keys(fact_pack_payload).isdisjoint(forbidden_control_keys)


def test_runner_keeps_invalid_replay_safe_and_marks_model_review(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    response_path = case.root / "replay" / "response.json"
    payload = json.loads(response_path.read_text(encoding="utf-8"))
    payload["schema_version"] = "cross_source_candidate_model_unknown"
    response_path.write_text(json.dumps(payload), encoding="utf-8")
    runtime = release_runner_module.ReleaseCaseModelRuntime(
        provider=ProviderName.OPENAI,
        model="fixture-replay-v1",
        reasoner=ReplayCandidateReasoner(load_release_fixture_replay(case)),
        audit_mode="replay",
    )
    session = _session()
    try:
        result = run_candidate_hunter_release_fixture(
            case,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
            model_runtime=runtime,
        )
        llm_runs = DatabaseRepository(session).list_llm_runs()
    finally:
        session.close()

    generation = result["run"]["candidate_generation"]
    assert generation["model_status"] == "needs_model_review"
    assert generation["model_failure_reason"] == "invalid_schema"
    assert generation["accepted_count"] == 0
    assert result["run"]["submission_blocked"] is True
    assert result["normalized_output"]["final_candidates"]
    assert len(llm_runs) == 1
    assert llm_runs[0].mode == "replay"
    assert llm_runs[0].error == "invalid_schema"


def test_runner_records_current_semantics_for_legacy_role_only_gold(tmp_path: Path):
    case = next(
        case
        for case in load_release_fixture_suite(FIXTURE_ROOT, "development")
        if case.case_id == "dev-006"
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

    assert result["normalized_output"]["candidate_decisions"][0]["disposition"] == (
        "retained"
    )
    assert result["evaluation"]["legacy_gold_adjustments"] == [
        {
            "gold_id": "observed-primary-root",
            "original_disposition": "refute",
            "effective_disposition": "retain",
            "reason": "role_only_does_not_close_object_ownership_gap",
        }
    ]
    assert result["evaluation"]["invalid_refutations"] == []
    assert result["evaluation"]["false_positives"] == []


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


def test_suite_runner_threads_runtime_and_loads_gold_after_all_captures(
    tmp_path: Path,
    monkeypatch,
):
    cases = list(load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development"))
    events = []
    runtimes = {}

    def runtime_factory(case):
        runtime = release_runner_module.ReleaseCaseModelRuntime(
            provider=ProviderName.OPENAI,
            model="fixture-replay-v1",
            reasoner=ReplayCandidateReasoner(load_release_fixture_replay(case)),
            audit_mode="replay",
        )
        runtimes[case.case_id] = runtime
        return runtime

    def capture(case, *, workspace_root, session, model_runtime=None):
        assert workspace_root == tmp_path / "studio-workspaces"
        assert model_runtime is runtimes[case.case_id]
        events.append(f"capture:{case.case_id}")
        return {
            "case_id": case.case_id,
            "normalized_output": {},
            "loop_audit": {"status": "ready"},
            "events": [],
        }

    def load_gold_suite(received_cases):
        assert received_cases == tuple(cases)
        assert len(events) == 12
        events.append("gold_suite")
        return tuple({"expected_roots": []} for _ in received_cases)

    monkeypatch.setattr(
        release_runner_module,
        "_capture_candidate_hunter_release_fixture",
        capture,
    )
    monkeypatch.setattr(
        release_runner_module,
        "load_release_fixture_gold_suite",
        load_gold_suite,
        raising=False,
    )
    monkeypatch.setattr(
        release_runner_module,
        "evaluate_candidate_hunter_release_suite_v1",
        lambda values: {
            "status": "passed",
            "case_diagnostics": [],
            "schema_failures": [],
        },
    )
    session = _session()
    try:
        result = run_candidate_hunter_release_suite(
            cases,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
            model_runtime_factory=runtime_factory,
        )
    finally:
        session.close()

    assert events == [
        *(f"capture:{case.case_id}" for case in cases),
        "gold_suite",
    ]
    assert result["events"] == ["all_candidates_captured", "gold_loaded"]


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

def test_normalizer_empty_decisions_are_not_a_completed_loop_projection():
    normalized = normalize_studio_candidates_for_release_v1(
        [
            {
                "hypothesis_id": "H-ready",
                "vuln_type": "authorization",
                "root_cause_id": "missing_object_ownership_check:read_record",
                "location": "GET /records/{record_id}",
                "source_facts": [
                    {
                        "artifact_kind": "code",
                        "source_path": "code.ts",
                        "symbol_name": "read_record",
                    }
                ],
                "evidence_trace_summary": {"status": "traceable"},
                "human_validation_readiness": "ready",
                "safe_validation_plan": ["Review local evidence only."],
                "safety_blockers": [
                    "execute_live_validation",
                    "touch_real_user_data",
                    "submit_report",
                ],
                "report_readiness": {
                    "report_submission_allowed": False,
                    "next_allowed_action": "Human review",
                },
            }
        ]
    )

    assert normalized["final_candidates"]
    assert normalized["candidate_decisions"] == []
    # Capture helper must not invent terminal retained decisions.
    assert all(
        decision.get("disposition") != "retained"
        for decision in normalized["candidate_decisions"]
    )


def test_runner_ready_projection_requires_decisions_for_retained_candidates(
    tmp_path: Path,
    monkeypatch,
):
    case = load_release_fixture_suite(FIXTURE_ROOT, "development")[0]
    session = _session()

    def ready_projection_without_decisions(*, repository, pipeline_run_id):
        return {
            "status": "ready",
            "failures": [],
            "final_candidates": [
                {
                    "candidate_id": "H-001",
                    "rank": 1,
                    "vuln_type": "authorization",
                    "root_cause_id": "missing_object_ownership_check:read_record",
                    "route": {"method": "GET", "path": "/local/records/q7m4/{record_id}"},
                    "source_fact_refs": [
                        "code:code.ts:read_record",
                        "api:GET:/local/records/q7m4/{record_id}",
                    ],
                    "evidence_trace_status": "traceable",
                    "human_validation_readiness": "ready",
                    "execution_allowed": False,
                    "validation_allowed": False,
                    "report_submission_allowed": False,
                    "safe_validation_plan": ["Review local evidence only."],
                    "next_allowed_action": "Human review",
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                }
            ],
            "candidate_decisions": [],
            "audit": {
                "round_count": 1,
                "stage_refs": ["snapshot", "evidence", "decision", "rerank"],
            },
        }

    monkeypatch.setattr(
        release_runner_module,
        "load_candidate_hunter_projection",
        ready_projection_without_decisions,
    )
    try:
        result = run_candidate_hunter_release_fixture(
            case,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
        )
    finally:
        session.close()

    assert result["loop_audit"]["status"] == "ready"
    assert result["normalized_output"]["final_candidates"]
    assert result["normalized_output"]["candidate_decisions"] == []
    assert result["evaluation"]["status"] == "failed"
    assert {
        "path": "final_candidates[0].candidate_id",
        "reason": "missing_retained_decision",
    } in result["evaluation"]["schema_failures"]
