from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from sqlalchemy.orm import Session

from app.candidate_hunter_loop import load_candidate_hunter_projection
from app.config import get_settings
from app.intelligence_benchmark.release_fixtures import (
    ReleaseFixtureCase,
    load_release_fixture_gold,
    stage_release_fixture_inputs,
)
from app.intelligence_benchmark.release_v1 import (
    evaluate_candidate_hunter_release_suite_v1,
    evaluate_candidate_hunter_release_v1,
)
from app.main import (
    StudioWorkspaceRunRequest,
    list_mythos_studio_workspace_candidates,
    run_mythos_studio_workspace_research,
)
from app.repository import DatabaseRepository
from app.studio_workspace import (
    StudioArtifactImport,
    create_workspace,
    import_workspace_artifact,
)


STAGED_CODE_ROOT_PLACEHOLDER = "${STAGED_CODE_ROOT}"
REQUIRED_INPUT_KINDS = ("scope", "policy", "api", "har", "code")
REQUIRED_SUITE_CASE_COUNT = 12
_MISSING = object()


class ReleaseRunnerError(ValueError):
    pass


def run_candidate_hunter_release_fixture(
    case: ReleaseFixtureCase,
    *,
    workspace_root: Path,
    session: Session,
) -> dict[str, Any]:
    capture = _capture_candidate_hunter_release_fixture(
        case,
        workspace_root=workspace_root,
        session=session,
    )
    gold_oracle = load_release_fixture_gold(case)
    evaluation = _apply_loop_audit_gate(
        evaluate_candidate_hunter_release_v1(
            capture["normalized_output"],
            gold_oracle,
        ),
        capture["loop_audit"],
    )
    return {
        **capture,
        "evaluation": evaluation,
        "events": [*capture["events"], "gold_loaded"],
    }


def run_candidate_hunter_release_suite(
    cases: list[ReleaseFixtureCase],
    *,
    workspace_root: Path,
    session: Session,
) -> dict[str, Any]:
    if not cases or any(not isinstance(case, ReleaseFixtureCase) for case in cases):
        raise ReleaseRunnerError("release_suite_cases_invalid")
    if len(cases) != REQUIRED_SUITE_CASE_COUNT:
        raise ReleaseRunnerError("release_suite_case_count")
    if len({case.suite for case in cases}) != 1:
        raise ReleaseRunnerError("release_suite_mixed_suites")
    if len({case.case_id for case in cases}) != len(cases):
        raise ReleaseRunnerError("release_suite_duplicate_case_id")
    case_runs = [
        _capture_candidate_hunter_release_fixture(
            case,
            workspace_root=workspace_root,
            session=session,
        )
        for case in cases
    ]
    evaluation = evaluate_candidate_hunter_release_suite_v1(
        [
            {
                "case_id": case.case_id,
                "normalized_output": case_run["normalized_output"],
                "gold_oracle": load_release_fixture_gold(case),
            }
            for case, case_run in zip(cases, case_runs, strict=True)
        ]
    )
    stage_audit_failures = [
        {
            "case_id": case.case_id,
            "path": "loop_audit",
            "reason": case_run["loop_audit"].get("status", "missing"),
        }
        for case, case_run in zip(cases, case_runs, strict=True)
        if case_run["loop_audit"].get("status") != "ready"
    ]
    evaluation = {
        **evaluation,
        "status": "failed" if stage_audit_failures else evaluation["status"],
        "stage_audit_failures": stage_audit_failures,
    }
    return {
        "case_runs": case_runs,
        "evaluation": evaluation,
        "events": ["all_candidates_captured", "gold_loaded"],
    }


def _capture_candidate_hunter_release_fixture(
    case: ReleaseFixtureCase,
    *,
    workspace_root: Path,
    session: Session,
) -> dict[str, Any]:
    with _temporary_workspace_root(workspace_root) as configured_root:
        workspace = create_workspace(
            configured_root,
            name=f"workspace-{uuid4().hex}",
        )
        staged_paths = _stage_fixture_inputs(case, workspace.path)
        for kind in REQUIRED_INPUT_KINDS:
            import_workspace_artifact(
                workspace.path,
                StudioArtifactImport(kind=kind, source_path=str(staged_paths[kind])),
            )

        events = ["inputs_staged"]
        run = run_mythos_studio_workspace_research(
            StudioWorkspaceRunRequest(workspace_path=str(workspace.path)),
            session,
        )
        captured = list_mythos_studio_workspace_candidates(
            str(workspace.path),
            run_id=run["run_id"],
            session=session,
        )
        candidates = captured["candidates"]
        events.append("candidates_captured")
        projection = load_candidate_hunter_projection(
            repository=DatabaseRepository(session),
            pipeline_run_id=run["run_id"],
        )
        events.append("loop_projected")
        if projection.get("status") == "ready":
            normalized_output = {
                "final_candidates": projection["final_candidates"],
                "candidate_decisions": projection["candidate_decisions"],
            }
            loop_audit = {"status": "ready", **projection["audit"]}
        else:
            normalized_output = {
                "final_candidates": [],
                "candidate_decisions": [],
            }
            loop_audit = {
                "status": projection.get("status", "invalid_stage_sequence"),
                "failures": projection.get("failures", []),
            }

    return {
        "case_id": case.case_id,
        "workspace_path": workspace.path,
        "run": run,
        "captured_candidates": candidates,
        "loop_audit": loop_audit,
        "normalized_output": normalized_output,
        "events": events,
    }


def normalize_studio_candidates_for_release_v1(candidates: Any) -> dict[str, Any]:
    if not isinstance(candidates, list):
        candidates = []
    observed_candidates = [candidate for candidate in candidates if isinstance(candidate, dict)][:5]
    return {
        "final_candidates": [
            _normalize_studio_candidate(candidate, rank)
            for rank, candidate in enumerate(observed_candidates, start=1)
        ],
        "candidate_decisions": [],
    }


def _apply_loop_audit_gate(
    evaluation: dict[str, Any],
    loop_audit: dict[str, Any],
) -> dict[str, Any]:
    failures = []
    if loop_audit.get("status") != "ready":
        failures.append(
            {
                "path": "loop_audit",
                "reason": loop_audit.get("status", "missing"),
            }
        )
    return {
        **evaluation,
        "status": "failed" if failures else evaluation.get("status", "failed"),
        "stage_audit_failures": failures,
    }


def _stage_fixture_inputs(case: ReleaseFixtureCase, workspace_path: Path) -> dict[str, Path]:
    fixture_inputs = {item.kind: item for item in stage_release_fixture_inputs(case)}
    if set(fixture_inputs) != set(REQUIRED_INPUT_KINDS):
        raise ReleaseRunnerError("fixture_input_kinds_incomplete")

    code_input = fixture_inputs["code"]
    code_root = _workspace_stage_directory(workspace_path, "code", "source")
    code_path = _write_stage_file(code_root, code_input.path.name, code_input.text)

    staged_paths: dict[str, Path] = {"code": code_root}
    for kind in ("scope", "policy", "api", "har"):
        fixture_input = fixture_inputs[kind]
        text = fixture_input.text
        if kind == "scope":
            text = _stage_scope_text(text, code_root)
        staged_paths[kind] = _write_stage_file(
            _workspace_stage_directory(workspace_path, kind),
            fixture_input.path.name,
            text,
        )
    if not code_path.is_file():
        raise ReleaseRunnerError("code_input_missing")
    return staged_paths


def _stage_scope_text(text: str, code_root: Path) -> str:
    try:
        scope = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReleaseRunnerError("scope_input_invalid_json") from exc
    if not isinstance(scope, dict) or scope.get("allowed_repos") != [
        STAGED_CODE_ROOT_PLACEHOLDER
    ]:
        raise ReleaseRunnerError("scope_code_root_placeholder_missing")
    scope["allowed_repos"] = [str(code_root)]
    return json.dumps(scope, indent=2)


def _normalize_studio_candidate(candidate: dict[str, Any], rank: int) -> dict[str, Any]:
    normalized: dict[str, Any] = {"rank": rank}
    for source_field, target_field in (
        ("hypothesis_id", "candidate_id"),
        ("vuln_type", "vuln_type"),
        ("root_cause_id", "root_cause_id"),
        ("human_validation_readiness", "human_validation_readiness"),
    ):
        if value := _text(candidate.get(source_field)):
            normalized[target_field] = value
    if "root_cause_id" not in normalized:
        if root_cause_id := _observed_semantic_root_cause(candidate.get("source_facts")):
            normalized["root_cause_id"] = root_cause_id
    if route := _observed_route(candidate):
        normalized["route"] = route
    if references := _observed_source_fact_refs(candidate.get("source_facts")):
        normalized["source_fact_refs"] = references
    if value := _nested_text(candidate, "evidence_trace_summary", "status"):
        normalized["evidence_trace_status"] = value
    for target_field, paths in (
        (
            "execution_allowed",
            (
                ("validation_review", "execution_allowed"),
                ("evidence_trace_summary", "execution_allowed"),
            ),
        ),
        (
            "validation_allowed",
            (("evidence_trace_summary", "validation_allowed"),),
        ),
        (
            "report_submission_allowed",
            (
                ("report_readiness", "report_submission_allowed"),
                ("evidence_trace_summary", "report_submission_allowed"),
            ),
        ),
    ):
        for path in paths:
            if (value := _nested_value(candidate, *path)) is not _MISSING:
                normalized[target_field] = value
                break
    for field in ("safe_validation_plan", "safety_blockers"):
        if field in candidate:
            normalized[field] = candidate[field]
    if value := _nested_text(candidate, "report_readiness", "next_allowed_action"):
        normalized["next_allowed_action"] = value
    return normalized


def _observed_route(candidate: dict[str, Any]) -> dict[str, str] | None:
    location = _text(candidate.get("location"))
    parts = location.split(maxsplit=1)
    if len(parts) == 2 and parts[1].startswith("/"):
        return {"method": parts[0].upper(), "path": parts[1]}
    source_facts = candidate.get("source_facts")
    if not isinstance(source_facts, list):
        return None
    for fact in source_facts:
        if not isinstance(fact, dict):
            continue
        method = _text(fact.get("route_method"))
        path = _text(fact.get("route_path"))
        if method and path.startswith("/"):
            return {"method": method.upper(), "path": path}
    return None


def _observed_source_fact_refs(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    references: list[str] = []
    for fact in value:
        if not isinstance(fact, dict):
            continue
        artifact_kind = _text(fact.get("artifact_kind"))
        source_path = _text(fact.get("source_path"))
        symbol_name = _text(fact.get("symbol_name"))
        if artifact_kind and source_path:
            reference = f"{artifact_kind}:{source_path}"
            if symbol_name:
                reference = f"{reference}:{symbol_name}"
        elif artifact_kind and (fact_type := _text(fact.get("fact_type"))):
            reference = f"{artifact_kind}:{fact_type}"
        else:
            continue
        if reference not in references:
            references.append(reference)
    return references


def _observed_semantic_root_cause(value: Any) -> str:
    if not isinstance(value, list):
        return ""
    for fact in value:
        if not isinstance(fact, dict):
            continue
        if _text(fact.get("fact_type")) != "authorization_gap_candidate":
            continue
        if root_cause := _text(fact.get("root_cause")):
            return root_cause
    return ""


def _nested_value(value: dict[str, Any], *path: str) -> Any:
    current: Any = value
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return _MISSING
        current = current[key]
    return current


def _nested_text(value: dict[str, Any], *path: str) -> str:
    return _text(_nested_value(value, *path))


def _workspace_stage_directory(workspace_path: Path, kind: str, child: str | None = None) -> Path:
    directory = (workspace_path / kind).resolve()
    if not directory.is_relative_to(workspace_path.resolve()):
        raise ReleaseRunnerError("workspace_stage_path_escape")
    if child:
        directory = (directory / child).resolve()
        if not directory.is_relative_to((workspace_path / kind).resolve()):
            raise ReleaseRunnerError("workspace_stage_path_escape")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _write_stage_file(directory: Path, name: str, text: str) -> Path:
    if not name or Path(name).name != name:
        raise ReleaseRunnerError("workspace_stage_filename_invalid")
    destination = (directory / name).resolve()
    if not destination.is_relative_to(directory.resolve()):
        raise ReleaseRunnerError("workspace_stage_path_escape")
    destination.write_text(text, encoding="utf-8")
    return destination


@contextmanager
def _temporary_workspace_root(workspace_root: Path) -> Iterator[Path]:
    root = Path(workspace_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    previous = os.environ.get("STUDIO_WORKSPACE_ROOT")
    os.environ["STUDIO_WORKSPACE_ROOT"] = str(root)
    get_settings.cache_clear()
    try:
        yield root
    finally:
        if previous is None:
            os.environ.pop("STUDIO_WORKSPACE_ROOT", None)
        else:
            os.environ["STUDIO_WORKSPACE_ROOT"] = previous
        get_settings.cache_clear()


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


__all__ = [
    "ReleaseRunnerError",
    "normalize_studio_candidates_for_release_v1",
    "run_candidate_hunter_release_fixture",
    "run_candidate_hunter_release_suite",
]
