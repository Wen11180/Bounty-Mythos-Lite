from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.cross_source_candidate_generator import ReplayCandidateReasoner
from app.intelligence_benchmark.release_fixtures import (
    ReleaseFixtureCase,
    TYPESCRIPT_V2_PROFILE,
    TYPESCRIPT_V2_VERSION,
    load_release_fixture_replay,
    load_release_fixture_suite,
    preflight_release_fixture_suite,
)
from app.intelligence_benchmark.release_runner import (
    ReleaseCaseModelRuntime,
    run_candidate_hunter_release_suite,
)
from app.llm.base import ProviderName


TYPESCRIPT_RELEASE_GATE_VERSION = "candidate_hunter_typescript_release_gate_v2"
TYPESCRIPT_RELEASE_PROFILE = TYPESCRIPT_V2_PROFILE
TYPESCRIPT_RELEASE_FIXTURE_VERSION = TYPESCRIPT_V2_VERSION
EXPECTED_SUITE_CASE_COUNT = 12
HARD_PERMISSION_FIELDS = (
    "execution_allowed",
    "validation_allowed",
    "candidate_promotion_allowed",
    "report_submission_allowed",
)


def run_candidate_hunter_typescript_release_gate(
    *,
    fixture_root: Path,
    workspace_root: Path,
    session: Session,
    mode: Literal["replay", "live"],
    provider: ProviderName | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    if mode not in {"replay", "live"}:
        raise ValueError("mode_unsupported")
    if mode == "replay":
        if provider is not None or model is not None:
            raise ValueError("replay_rejects_provider_model")
    elif provider is None or not isinstance(model, str) or not model.strip():
        raise ValueError("live_requires_provider_model")
    runtime_factory = _runtime_factory(
        mode=mode,
        provider=provider,
        model=model.strip() if isinstance(model, str) else None,
    )
    result: dict[str, Any] = {
        "gate_version": TYPESCRIPT_RELEASE_GATE_VERSION,
        "profile": TYPESCRIPT_RELEASE_PROFILE,
        "fixture_version": TYPESCRIPT_RELEASE_FIXTURE_VERSION,
        "mode": mode,
        "status": "failed",
        "development": {"attempted": False, "status": "not_attempted"},
        "release": {"attempted": False, "status": "not_attempted"},
        "release_qualified": False,
    }
    if mode == "live":
        assert provider is not None
        assert model is not None
        result["provider"] = provider.value
        result["model"] = model.strip()

    development_cases = load_release_fixture_suite(fixture_root, "development")
    preflight_release_fixture_suite(development_cases)
    development_run = run_candidate_hunter_release_suite(
        list(development_cases),
        workspace_root=workspace_root,
        session=session,
        model_runtime_factory=runtime_factory,
    )
    development = _suite_result(
        development_run,
        require_bound_replay=mode == "replay",
    )
    result["development"] = development
    if development["status"] != "passed":
        return result

    release_cases = load_release_fixture_suite(fixture_root, "release")
    preflight_release_fixture_suite(release_cases)
    release_run = run_candidate_hunter_release_suite(
        list(release_cases),
        workspace_root=workspace_root,
        session=session,
        model_runtime_factory=runtime_factory,
    )
    release = _suite_result(
        release_run,
        require_bound_replay=mode == "replay",
    )
    result["release"] = release
    if release["status"] == "passed":
        result["status"] = "passed"
        result["release_qualified"] = mode == "live"
    return result


def _runtime_factory(
    *,
    mode: Literal["replay", "live"],
    provider: ProviderName | None,
    model: str | None,
):
    if mode == "replay":
        def replay_runtime(case: ReleaseFixtureCase) -> ReleaseCaseModelRuntime:
            return ReleaseCaseModelRuntime(
                provider=ProviderName.OPENAI,
                model="fixture-replay-v1",
                reasoner=ReplayCandidateReasoner(load_release_fixture_replay(case)),
                audit_mode="replay",
            )

        return replay_runtime

    assert provider is not None
    assert model is not None

    def live_runtime(case: ReleaseFixtureCase) -> ReleaseCaseModelRuntime:
        del case
        return ReleaseCaseModelRuntime(
            provider=provider,
            model=model,
            reasoner=None,
            audit_mode="live",
        )

    return live_runtime


def _suite_result(
    run: dict[str, Any],
    *,
    require_bound_replay: bool,
) -> dict[str, Any]:
    evaluation = run.get("evaluation")
    if not isinstance(evaluation, dict):
        evaluation = {}
    case_runs = run.get("case_runs")
    if not isinstance(case_runs, list):
        case_runs = []
    model_failures: list[dict[str, str]] = []
    stage_failures: list[dict[str, str]] = []
    permission_failures: list[dict[str, str]] = []
    if len(case_runs) != EXPECTED_SUITE_CASE_COUNT:
        model_failures.append(
            {"case_id": "suite", "reason": "case_run_count"}
        )
    for case_run in case_runs:
        if not isinstance(case_run, dict):
            model_failures.append(
                {"case_id": "unknown", "reason": "case_run_invalid"}
            )
            continue
        case_id = _safe_text(case_run.get("case_id")) or "unknown"
        run_result = case_run.get("run")
        generation = (
            run_result.get("candidate_generation")
            if isinstance(run_result, dict)
            else None
        )
        if not isinstance(generation, dict):
            model_failures.append(
                {"case_id": case_id, "reason": "candidate_generation_missing"}
            )
        else:
            if generation.get("model_requested") is not True:
                model_failures.append(
                    {"case_id": case_id, "reason": "model_not_requested"}
                )
            if generation.get("model_status") != "completed":
                model_failures.append(
                    {
                        "case_id": case_id,
                        "reason": (
                            "model_status:"
                            f"{_safe_text(generation.get('model_status')) or 'missing'}"
                        ),
                    }
                )
            if (
                require_bound_replay
                and generation.get("model_replay_binding") != "bound"
            ):
                model_failures.append(
                    {
                        "case_id": case_id,
                        "reason": (
                            "model_replay_binding:"
                            f"{_safe_text(generation.get('model_replay_binding')) or 'missing'}"
                        ),
                    }
                )
            accepted_count = generation.get("accepted_count")
            if (
                not isinstance(accepted_count, int)
                or isinstance(accepted_count, bool)
                or accepted_count < 1
            ):
                model_failures.append(
                    {"case_id": case_id, "reason": "accepted_proposals_missing"}
                )
            permission_failures.extend(
                _permission_failures(case_id, "candidate_generation", generation)
            )
        loop_audit = case_run.get("loop_audit")
        if not isinstance(loop_audit, dict) or loop_audit.get("status") != "ready":
            stage_failures.append(
                {
                    "case_id": case_id,
                    "reason": (
                        _safe_text(loop_audit.get("status"))
                        if isinstance(loop_audit, dict)
                        else "missing"
                    )
                    or "missing",
                }
            )
        normalized_output = case_run.get("normalized_output")
        final_candidates = (
            normalized_output.get("final_candidates")
            if isinstance(normalized_output, dict)
            else []
        )
        if isinstance(final_candidates, list):
            for index, candidate in enumerate(final_candidates):
                if isinstance(candidate, dict):
                    permission_failures.extend(
                        _permission_failures(
                            case_id,
                            f"final_candidates[{index}]",
                            candidate,
                        )
                    )
    oracle_order_failures = []
    if run.get("events") != ["all_candidates_captured", "gold_loaded"]:
        oracle_order_failures.append(
            {"case_id": "suite", "reason": "oracle_event_order_invalid"}
        )
    status = (
        "passed"
        if evaluation.get("status") == "passed"
        and not model_failures
        and not stage_failures
        and not permission_failures
        and not oracle_order_failures
        else "failed"
    )
    safe_evaluation = {
        key: evaluation[key]
        for key in (
            "version",
            "status",
            "metrics",
            "case_diagnostics",
            "schema_failures",
            "safety_failures",
            "stage_audit_failures",
            "false_positives",
            "missed_retained_roots",
            "invalid_refutations",
            "invalid_deduplications",
        )
        if key in evaluation
    }
    return {
        "attempted": True,
        "status": status,
        "evaluation": safe_evaluation,
        "model_failures": model_failures,
        "stage_failures": stage_failures,
        "permission_failures": permission_failures,
        "oracle_order_failures": oracle_order_failures,
    }


def _permission_failures(
    case_id: str,
    path: str,
    value: dict[str, Any],
) -> list[dict[str, str]]:
    return [
        {
            "case_id": case_id,
            "reason": f"{path}.{field}_not_false",
        }
        for field in HARD_PERMISSION_FIELDS
        if value.get(field) is not False
    ]


def _safe_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


__all__ = ["run_candidate_hunter_typescript_release_gate"]
