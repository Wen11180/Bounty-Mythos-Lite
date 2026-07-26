from __future__ import annotations

from copy import deepcopy
import importlib
import importlib.util
import json
from pathlib import Path
import shutil

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.intelligence_benchmark.release_fixtures import load_release_fixture_suite
from app.llm.base import ProviderName
from app.repository import DatabaseRepository
import app.main as main_module


FIXTURE_ROOT = (
    Path(__file__).parent / "fixtures" / "candidate_hunter_typescript_release_v2"
)


def _session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()


def _gate_function():
    module_name = "app.intelligence_benchmark.typescript_release_gate"
    assert importlib.util.find_spec(module_name) is not None
    module = importlib.import_module(module_name)
    return module.run_candidate_hunter_typescript_release_gate


def _passing_case_run(case_id: str) -> dict:
    false_permissions = {
        "execution_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    return {
        "case_id": case_id,
        "run": {
            "candidate_generation": {
                "model_requested": True,
                "model_status": "completed",
                "model_replay_binding": "bound",
                "accepted_count": 1,
                **false_permissions,
            }
        },
        "loop_audit": {"status": "ready"},
        "normalized_output": {
            "final_candidates": [{"candidate_id": "candidate", **false_permissions}],
            "candidate_decisions": [],
        },
    }


def _passing_suite_run(cases) -> dict:
    return {
        "evaluation": {
            "version": "candidate_hunter_release_suite_v1",
            "status": "passed",
            "metrics": {"root_cause_precision_at_5": {"passed": True}},
            "case_diagnostics": [],
            "schema_failures": [],
            "safety_failures": [],
            "stage_audit_failures": [],
        },
        "case_runs": [_passing_case_run(case.case_id) for case in cases],
        "events": ["all_candidates_captured", "gold_loaded"],
    }


@pytest.mark.parametrize(
    ("mode", "provider", "model", "reason"),
    (
        (
            "replay",
            ProviderName.OPENAI,
            None,
            "replay_rejects_provider_model",
        ),
        ("replay", None, "fixture-replay-v1", "replay_rejects_provider_model"),
        ("live", None, "test-model", "live_requires_provider_model"),
        ("live", ProviderName.OPENAI, None, "live_requires_provider_model"),
        ("live", ProviderName.OPENAI, "   ", "live_requires_provider_model"),
        ("unknown", None, None, "mode_unsupported"),
    ),
)
def test_typescript_release_gate_rejects_invalid_mode_configuration(
    mode: str,
    provider: ProviderName | None,
    model: str | None,
    reason: str,
    tmp_path: Path,
):
    gate = _gate_function()
    session = _session()
    try:
        with pytest.raises(ValueError, match=reason):
            gate(
                fixture_root=FIXTURE_ROOT,
                workspace_root=tmp_path / "studio-workspaces",
                session=session,
                mode=mode,
                provider=provider,
                model=model,
            )
    finally:
        session.close()


def test_typescript_release_gate_stops_before_release_when_development_fails(
    tmp_path: Path,
    monkeypatch,
):
    gate_module = importlib.import_module(
        "app.intelligence_benchmark.typescript_release_gate"
    )
    events = []

    def load_suite(fixture_root: Path, suite: str):
        events.append(f"load:{suite}")
        if suite == "release":
            raise AssertionError("release fixtures must remain untouched")
        return load_release_fixture_suite(fixture_root, suite)

    def preflight(cases):
        events.append(f"preflight:{cases[0].suite}")

    def run_suite(
        cases,
        *,
        workspace_root,
        session,
        model_runtime_factory,
    ):
        del workspace_root, session, model_runtime_factory
        events.append(f"run:{cases[0].suite}")
        return {
            "evaluation": {
                "version": "candidate_hunter_release_suite_v1",
                "status": "failed",
                "metrics": {},
                "case_diagnostics": [],
                "schema_failures": [
                    {"path": "cases", "reason": "forced_development_failure"}
                ],
                "safety_failures": [],
                "stage_audit_failures": [],
            },
            "case_runs": [],
            "events": ["all_candidates_captured", "gold_loaded"],
        }

    monkeypatch.setattr(gate_module, "load_release_fixture_suite", load_suite, raising=False)
    monkeypatch.setattr(
        gate_module,
        "preflight_release_fixture_suite",
        preflight,
        raising=False,
    )
    monkeypatch.setattr(
        gate_module,
        "run_candidate_hunter_release_suite",
        run_suite,
        raising=False,
    )
    session = _session()
    try:
        result = gate_module.run_candidate_hunter_typescript_release_gate(
            fixture_root=FIXTURE_ROOT,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
            mode="replay",
        )
    finally:
        session.close()

    assert events == [
        "load:development",
        "preflight:development",
        "run:development",
    ]
    assert result["status"] == "failed"
    assert result["development"]["attempted"] is True
    assert result["development"]["status"] == "failed"
    assert result["release"] == {
        "attempted": False,
        "status": "not_attempted",
    }
    assert result["release_qualified"] is False


@pytest.mark.parametrize(
    ("failure_kind", "failure_key"),
    (
        ("model_not_requested", "model_failures"),
        ("model_review", "model_failures"),
        ("unbound_replay", "model_failures"),
        ("zero_accepted", "model_failures"),
        ("invalid_stage", "stage_failures"),
        ("permission_true", "permission_failures"),
    ),
)
def test_typescript_release_gate_blocks_release_on_development_runtime_failure(
    failure_kind: str,
    failure_key: str,
    tmp_path: Path,
    monkeypatch,
):
    gate_module = importlib.import_module(
        "app.intelligence_benchmark.typescript_release_gate"
    )
    events = []

    def load_suite(fixture_root: Path, suite: str):
        events.append(f"load:{suite}")
        if suite == "release":
            raise AssertionError("release fixtures must remain untouched")
        return load_release_fixture_suite(fixture_root, suite)

    def run_suite(cases, **kwargs):
        del kwargs
        run = deepcopy(_passing_suite_run(cases))
        first = run["case_runs"][0]
        generation = first["run"]["candidate_generation"]
        if failure_kind == "model_not_requested":
            generation["model_requested"] = False
        elif failure_kind == "model_review":
            generation["model_status"] = "needs_model_review"
        elif failure_kind == "unbound_replay":
            generation["model_replay_binding"] = "legacy_unbound"
        elif failure_kind == "zero_accepted":
            generation["accepted_count"] = 0
        elif failure_kind == "invalid_stage":
            first["loop_audit"]["status"] = "invalid_stage_sequence"
        else:
            generation["candidate_promotion_allowed"] = True
        events.append("run:development")
        return run

    monkeypatch.setattr(gate_module, "load_release_fixture_suite", load_suite)
    monkeypatch.setattr(
        gate_module,
        "preflight_release_fixture_suite",
        lambda cases: events.append(f"preflight:{cases[0].suite}"),
    )
    monkeypatch.setattr(gate_module, "run_candidate_hunter_release_suite", run_suite)
    session = _session()
    try:
        result = gate_module.run_candidate_hunter_typescript_release_gate(
            fixture_root=FIXTURE_ROOT,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
            mode="replay",
        )
    finally:
        session.close()

    assert events == [
        "load:development",
        "preflight:development",
        "run:development",
    ]
    assert result["status"] == "failed"
    assert result["development"]["status"] == "failed"
    assert result["development"][failure_key]
    assert result["release"]["attempted"] is False


@pytest.mark.parametrize(
    ("mode", "provider", "model", "qualified"),
    (
        ("replay", None, None, False),
        ("live", ProviderName.OPENAI, "test-model", True),
    ),
)
def test_typescript_release_gate_runs_development_before_release(
    mode: str,
    provider: ProviderName | None,
    model: str | None,
    qualified: bool,
    tmp_path: Path,
    monkeypatch,
):
    gate_module = importlib.import_module(
        "app.intelligence_benchmark.typescript_release_gate"
    )
    events = []

    def load_suite(fixture_root: Path, suite: str):
        events.append(f"load:{suite}")
        return load_release_fixture_suite(fixture_root, suite)

    def preflight(cases):
        events.append(f"preflight:{cases[0].suite}")

    def run_suite(cases, *, model_runtime_factory, **kwargs):
        del kwargs
        events.append(f"run:{cases[0].suite}")
        runtimes = [model_runtime_factory(case) for case in cases]
        if mode == "replay":
            assert all(runtime.audit_mode == "replay" for runtime in runtimes)
            assert all(runtime.reasoner is not None for runtime in runtimes)
            assert all(runtime.model == "fixture-replay-v1" for runtime in runtimes)
        else:
            assert all(runtime.audit_mode == "live" for runtime in runtimes)
            assert all(runtime.reasoner is None for runtime in runtimes)
            assert all(runtime.provider == provider for runtime in runtimes)
            assert all(runtime.model == model for runtime in runtimes)
        return _passing_suite_run(cases)

    monkeypatch.setattr(gate_module, "load_release_fixture_suite", load_suite)
    monkeypatch.setattr(gate_module, "preflight_release_fixture_suite", preflight)
    monkeypatch.setattr(gate_module, "run_candidate_hunter_release_suite", run_suite)
    session = _session()
    try:
        result = gate_module.run_candidate_hunter_typescript_release_gate(
            fixture_root=FIXTURE_ROOT,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
            mode=mode,
            provider=provider,
            model=model,
        )
    finally:
        session.close()

    assert events == [
        "load:development",
        "preflight:development",
        "run:development",
        "load:release",
        "preflight:release",
        "run:release",
    ]
    assert result["status"] == "passed"
    assert result["development"]["status"] == "passed"
    assert result["release"]["status"] == "passed"
    assert result["release_qualified"] is qualified
    if mode == "replay":
        assert "provider" not in result
        assert "model" not in result
    else:
        assert result["provider"] == "openai"
        assert result["model"] == "test-model"


def test_actual_typescript_replay_gate_passes_without_registry_or_network(
    tmp_path: Path,
    monkeypatch,
):
    def fail_if_registry_is_built():
        raise AssertionError("replay gate must not construct a provider registry")

    monkeypatch.setattr(main_module, "build_default_registry", fail_if_registry_is_built)
    gate = _gate_function()
    session = _session()
    try:
        result = gate(
            fixture_root=FIXTURE_ROOT,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
            mode="replay",
        )
        llm_runs = DatabaseRepository(session).list_llm_runs()
    finally:
        session.close()

    assert result["gate_version"] == "candidate_hunter_typescript_release_gate_v2"
    assert result["profile"] == "candidate_hunter_typescript_express_v2"
    assert result["fixture_version"] == "candidate_hunter_typescript_express_fixture_v2"
    assert result["status"] == "passed", {
        "development_status": result["development"]["status"],
        "evaluation_status": result["development"]["evaluation"].get("status"),
        "model_failures": result["development"].get("model_failures"),
        "stage_failures": result["development"].get("stage_failures"),
        "permission_failures": result["development"].get("permission_failures"),
        "oracle_order_failures": result["development"].get(
            "oracle_order_failures"
        ),
        "metrics": result["development"]["evaluation"].get("metrics"),
        "schema_failures": result["development"]["evaluation"].get(
            "schema_failures"
        ),
        "safety_failures": result["development"]["evaluation"].get(
            "safety_failures"
        ),
    }
    assert result["development"]["status"] == "passed"
    assert result["release"]["status"] == "passed"
    assert result["release_qualified"] is False
    assert "provider" not in result
    assert "model" not in result
    for suite in ("development", "release"):
        summary = result[suite]
        assert len(summary["evaluation"]["metrics"]) == 6
        assert all(
            metric["passed"] is True
            and metric["denominator"] > 0
            for metric in summary["evaluation"]["metrics"].values()
        )
        assert summary["model_failures"] == []
        assert summary["stage_failures"] == []
        assert summary["permission_failures"] == []
        assert summary["oracle_order_failures"] == []
    assert len(llm_runs) == 24
    assert {llm_run.mode for llm_run in llm_runs} == {"replay"}
    assert all(
        "synthetic_replay_no_provider_call" in llm_run.safety_notes
        for llm_run in llm_runs
    )
    serialized = json.dumps(result).lower()
    for forbidden in (
        "workspace_path",
        "case_runs",
        "raw_response",
        "source_body",
        "authorization: bearer",
        "cookie:",
        "api_key",
        "gold_oracle",
    ):
        assert forbidden not in serialized


def test_typescript_replay_gate_rejects_changed_fixture_fact_pack(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(FIXTURE_ROOT, fixture_root)
    code_path = fixture_root / "cases" / "case-001" / "inputs" / "code.ts"
    code_path.write_text(
        code_path.read_text(encoding="utf-8") + "\n// fixture binding mutation\n",
        encoding="utf-8",
    )

    session = _session()
    try:
        result = _gate_function()(
            fixture_root=fixture_root,
            workspace_root=tmp_path / "studio-workspaces",
            session=session,
            mode="replay",
        )
    finally:
        session.close()

    assert result["status"] == "failed"
    assert result["development"]["status"] == "failed"
    assert {
        failure["reason"] for failure in result["development"]["model_failures"]
    } >= {"model_status:needs_model_review", "model_replay_binding:mismatch"}
    assert result["release"] == {
        "attempted": False,
        "status": "not_attempted",
    }
