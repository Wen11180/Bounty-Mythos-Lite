"""Black-box dual-role HAR golden package runner and quality gate.

Loads fixture packages under tests/fixtures/black_box_har_golden, runs the
existing HAR -> local-lab observe pipeline, ranks Top-N candidates, and
evaluates retain/refute expectations. Remote observation is unsupported.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.black_box_hunter.browser_demo_intake import (
    build_observed_workflow_model_from_browser_demo,
)
from app.black_box_hunter.har_intake import build_observed_workflow_model_from_role_hars
from app.black_box_hunter.local_lab_pipeline import run_har_local_lab_pipeline

DEFAULT_FIXTURE_ROOT = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "fixtures"
    / "black_box_har_golden"
)

REQUIRED_MANIFEST_KEYS = {
    "package_id",
    "scenario_class",
    "expected_status",
    "expected_trial_class",
    "lab_mode",
    "role_a_file",
    "role_b_file",
}

SECRET_MARKERS = (
    "SECRET",
    "Bearer",
    "leak-me",
    "password",
    "session=",
    "Cookie",
    "Set-Cookie",
)

ALLOWED_EXPECTED_STATUS = {
    "retained",
    "refuted",
    "suppressed",
    "needs_evidence",
}


class BlackBoxHarGoldenError(ValueError):
    """Raised when a golden package or gate evaluation is invalid."""


def default_fixture_root() -> Path:
    return DEFAULT_FIXTURE_ROOT


def list_golden_packages(root: Path | None = None) -> list[Path]:
    base = root or DEFAULT_FIXTURE_ROOT
    if not base.is_dir():
        raise BlackBoxHarGoldenError("golden_fixture_root_missing")
    packages = sorted(
        path.parent
        for path in base.glob("*/manifest.json")
        if path.is_file()
    )
    if not packages:
        raise BlackBoxHarGoldenError("no_golden_packages_found")
    return packages


def load_manifest(package_dir: Path) -> dict[str, Any]:
    manifest_path = package_dir / "manifest.json"
    if not manifest_path.is_file():
        raise BlackBoxHarGoldenError("manifest_json_required")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise BlackBoxHarGoldenError("manifest_json_invalid") from error
    if not isinstance(manifest, dict):
        raise BlackBoxHarGoldenError("manifest_object_required")
    missing = REQUIRED_MANIFEST_KEYS - set(manifest)
    if missing:
        raise BlackBoxHarGoldenError(
            f"manifest_missing_keys:{','.join(sorted(missing))}"
        )
    if manifest["expected_status"] not in ALLOWED_EXPECTED_STATUS:
        raise BlackBoxHarGoldenError("manifest_expected_status_unsupported")
    if manifest["scenario_class"] not in {"retain", "refute"}:
        raise BlackBoxHarGoldenError("manifest_scenario_class_unsupported")
    return manifest


def load_role_hars(package_dir: Path, manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    role_a_path = package_dir / str(manifest["role_a_file"])
    role_b_path = package_dir / str(manifest["role_b_file"])
    return {
        "role_a": _load_json_object(role_a_path, label="role_a"),
        "role_b": _load_json_object(role_b_path, label="role_b"),
    }


def run_har_golden_package(
    package_dir: Path | str,
    *,
    local_lab: bool = True,
) -> dict[str, Any]:
    """Run one golden package and return pipeline result + gate evaluation."""
    if not local_lab:
        raise BlackBoxHarGoldenError("local_lab_flag_required")

    root = Path(package_dir)
    if not root.is_dir():
        raise BlackBoxHarGoldenError("package_dir_required")

    manifest = load_manifest(root)
    role_hars = load_role_hars(root, manifest)
    account_aliases = dict(manifest.get("account_aliases") or {
        "role_a": "account_a",
        "role_b": "account_b",
    })
    role_aliases = dict(manifest.get("role_aliases") or {
        "role_a": "member",
        "role_b": "viewer",
    })
    role_ranks = {
        key: int(value)
        for key, value in dict(manifest.get("role_ranks") or {
            "role_a": 10,
            "role_b": 1,
        }).items()
    }
    trial_classes = set(manifest.get("trial_classes") or [manifest["expected_trial_class"]])
    top_n = int(manifest.get("top_n") or 5)

    pipeline = run_har_local_lab_pipeline(
        role_hars,
        mode=str(manifest["lab_mode"]),
        local_lab=True,
        trial_classes=trial_classes,
        account_aliases=account_aliases,
        role_aliases=role_aliases,
        role_ranks=role_ranks,
    )
    candidates = list(pipeline.get("candidates") or [])
    top_candidates = candidates[:top_n]
    gate = evaluate_har_golden(
        pipeline,
        manifest,
        top_candidates=top_candidates,
    )
    safety = assert_safe_pipeline_result(pipeline)

    return {
        "schema_version": "black_box_har_golden_result_v1",
        "package_id": manifest["package_id"],
        "package_dir": str(root.resolve()),
        "manifest": {
            "package_id": manifest["package_id"],
            "scenario_class": manifest["scenario_class"],
            "expected_status": manifest["expected_status"],
            "expected_trial_class": manifest["expected_trial_class"],
            "lab_mode": manifest["lab_mode"],
            "top_n": top_n,
            "expected_retained_trial_classes": list(
                manifest.get("expected_retained_trial_classes") or []
            ),
        },
        "mode": pipeline.get("mode"),
        "lab_mode": pipeline.get("lab_mode"),
        "local_lab": True,
        "plan_classes": pipeline.get("plan_classes"),
        "observations": pipeline.get("observations"),
        "candidates": candidates,
        "top_candidates": top_candidates,
        "retained_candidates": pipeline.get("retained_candidates"),
        "gate": gate,
        "safety": safety,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "raw_secrets_persisted": False,
        "workflow_model": pipeline.get("workflow_model"),
    }


def evaluate_har_golden(
    pipeline: dict[str, Any],
    manifest: dict[str, Any],
    *,
    top_candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate retain/refute expectations against Top-N candidates."""
    failures: list[str] = []
    expected_status = str(manifest["expected_status"])
    expected_trial = str(manifest["expected_trial_class"])
    top_n = int(manifest.get("top_n") or 5)
    candidates = list(top_candidates if top_candidates is not None else (pipeline.get("candidates") or [])[:top_n])

    if pipeline.get("execution_allowed") is not False:
        failures.append("execution_allowed_must_be_false")
    if pipeline.get("report_submission_allowed") is not False:
        failures.append("report_submission_allowed_must_be_false")
    if pipeline.get("raw_secrets_persisted") is not False:
        failures.append("raw_secrets_persisted_must_be_false")

    matching = [
        card
        for card in candidates
        if card.get("plan_trial_class") == expected_trial
        or card.get("family") == expected_trial
    ]
    if not matching:
        failures.append(f"expected_trial_class_missing_in_top_n:{expected_trial}")
        return {
            "passed": False,
            "package_id": manifest.get("package_id"),
            "expected_status": expected_status,
            "expected_trial_class": expected_trial,
            "observed_statuses": [],
            "failures": failures,
        }

    observed_statuses = [str(card.get("decision") or "") for card in matching]
    retained_for_class = [
        card for card in matching if card.get("decision") == "retained"
    ]

    expected_retained_classes = [
        str(item)
        for item in list(manifest.get("expected_retained_trial_classes") or [])
        if str(item).strip()
    ]
    if expected_retained_classes:
        retained_classes = {
            str(card.get("plan_trial_class") or card.get("family") or "")
            for card in candidates
            if card.get("decision") == "retained"
        }
        missing_retained = [
            trial_class
            for trial_class in expected_retained_classes
            if trial_class not in retained_classes
        ]
        if missing_retained:
            failures.append(
                "expected_retained_classes_missing:" + ",".join(missing_retained)
            )

    if expected_status == "retained":
        if not retained_for_class:
            failures.append(
                f"expected_retained_missing:{expected_trial}:{','.join(observed_statuses)}"
            )
    else:
        # refute packages: target class must not be retained in Top-N
        if retained_for_class:
            failures.append(
                f"unexpected_retained:{expected_trial}"
            )
        if expected_status not in observed_statuses:
            # allow stronger kill than expected (refuted when suppressed expected)
            if expected_status == "suppressed" and "refuted" in observed_statuses:
                pass
            elif expected_status == "refuted" and "suppressed" in observed_statuses:
                # suppressed is weaker; still fail if we required explicit refute
                failures.append(
                    f"expected_status_not_observed:{expected_status}:{','.join(observed_statuses)}"
                )
            else:
                failures.append(
                    f"expected_status_not_observed:{expected_status}:{','.join(observed_statuses)}"
                )

    for card in matching:
        if not card.get("falsify_attempts"):
            failures.append(f"falsify_attempts_required:{card.get('candidate_id')}")

    return {
        "passed": not failures,
        "package_id": manifest.get("package_id"),
        "expected_status": expected_status,
        "expected_trial_class": expected_trial,
        "observed_statuses": observed_statuses,
        "top_n": top_n,
        "matching_candidate_ids": [card.get("candidate_id") for card in matching],
        "failures": failures,
    }


def assert_safe_pipeline_result(pipeline: dict[str, Any]) -> dict[str, Any]:
    """Return a secret-safe summary. Never echo marker strings into the result."""
    blob = json.dumps(pipeline, default=str)
    high_risk_count = sum(
        1
        for marker in ("SECRET", "Bearer", "leak-me", "session=SECRET")
        if marker in blob
    )
    return {
        "safe": high_risk_count == 0,
        "high_risk_marker_count": high_risk_count,
        "execution_allowed": pipeline.get("execution_allowed") is False,
        "report_submission_allowed": pipeline.get("report_submission_allowed") is False,
        "raw_secrets_persisted": pipeline.get("raw_secrets_persisted") is False,
    }


def run_all_har_golden_packages(
    root: Path | None = None,
) -> dict[str, Any]:
    packages = list_golden_packages(root)
    results: list[dict[str, Any]] = []
    for package_dir in packages:
        result = run_har_golden_package(package_dir)
        results.append(result)

    failed = [
        item["package_id"]
        for item in results
        if not item.get("gate", {}).get("passed")
        or not item.get("safety", {}).get("safe")
    ]
    return {
        "schema_version": "black_box_har_golden_gate_v1",
        "fixture_root": str((root or DEFAULT_FIXTURE_ROOT).resolve()),
        "package_count": len(results),
        "passed": not failed,
        "failed_packages": failed,
        "results": results,
        "execution_allowed": False,
        "report_submission_allowed": False,
    }


def build_demo_packages_from_har_golden(
    package_dir: Path | str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Build browser-demo packages with the same dual-role traffic as a golden HAR package."""
    root = Path(package_dir)
    manifest = load_manifest(root)
    role_hars = load_role_hars(root, manifest)
    account_aliases = dict(manifest.get("account_aliases") or {
        "role_a": "account_a",
        "role_b": "account_b",
    })
    role_aliases = dict(manifest.get("role_aliases") or {
        "role_a": "member",
        "role_b": "viewer",
    })
    role_ranks = {
        key: int(value)
        for key, value in dict(manifest.get("role_ranks") or {
            "role_a": 10,
            "role_b": 1,
        }).items()
    }

    demo_a = _har_to_demo_package(
        role_hars["role_a"],
        account_alias=account_aliases["role_a"],
        role_alias=role_aliases["role_a"],
        role_rank=role_ranks["role_a"],
    )
    demo_b = _har_to_demo_package(
        role_hars["role_b"],
        account_alias=account_aliases["role_b"],
        role_alias=role_aliases["role_b"],
        role_rank=role_ranks["role_b"],
    )
    return demo_a, demo_b, manifest


def assert_intake_isomorphism(
    package_dir: Path | str,
) -> dict[str, Any]:
    """HAR and browser-demo intakes must yield the same plan classes for a golden package."""
    root = Path(package_dir)
    manifest = load_manifest(root)
    role_hars = load_role_hars(root, manifest)
    account_aliases = dict(manifest.get("account_aliases") or {
        "role_a": "account_a",
        "role_b": "account_b",
    })
    role_aliases = dict(manifest.get("role_aliases") or {
        "role_a": "member",
        "role_b": "viewer",
    })
    role_ranks = {
        key: int(value)
        for key, value in dict(manifest.get("role_ranks") or {
            "role_a": 10,
            "role_b": 1,
        }).items()
    }

    har_model = build_observed_workflow_model_from_role_hars(
        role_hars,
        account_aliases=account_aliases,
        role_aliases=role_aliases,
        role_ranks=role_ranks,
    )
    demo_a, demo_b, _ = build_demo_packages_from_har_golden(root)
    demo_model = build_observed_workflow_model_from_browser_demo(demo_a, demo_b)

    from app.black_box_hunter import plan_differential_trials

    har_plans = {
        plan.trial_class
        for plan in plan_differential_trials(har_model, require_all_classes=False)
    }
    demo_plans = {
        plan.trial_class
        for plan in plan_differential_trials(demo_model, require_all_classes=False)
    }
    har_routes = {
        step.route_template
        for workflow in har_model.workflows
        for step in workflow.steps
    }
    demo_routes = {
        step.route_template
        for workflow in demo_model.workflows
        for step in workflow.steps
    }
    har_accounts = {workflow.session.account_alias for workflow in har_model.workflows}
    demo_accounts = {workflow.session.account_alias for workflow in demo_model.workflows}

    failures: list[str] = []
    if har_plans != demo_plans:
        failures.append(
            f"plan_classes_mismatch:har={sorted(har_plans)}:demo={sorted(demo_plans)}"
        )
    if har_routes != demo_routes:
        failures.append(
            f"route_templates_mismatch:har={sorted(har_routes)}:demo={sorted(demo_routes)}"
        )
    if har_accounts != demo_accounts:
        failures.append(
            f"accounts_mismatch:har={sorted(har_accounts)}:demo={sorted(demo_accounts)}"
        )

    return {
        "passed": not failures,
        "package_id": manifest["package_id"],
        "har_plan_classes": sorted(har_plans),
        "demo_plan_classes": sorted(demo_plans),
        "har_routes": sorted(har_routes),
        "demo_routes": sorted(demo_routes),
        "failures": failures,
    }


def _har_to_demo_package(
    har: dict[str, Any],
    *,
    account_alias: str,
    role_alias: str,
    role_rank: int,
) -> dict[str, Any]:
    entries = har.get("log", {}).get("entries", [])
    events: list[dict[str, Any]] = []
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            request = entry.get("request")
            if not isinstance(request, dict):
                continue
            method = str(request.get("method") or "")
            url = str(request.get("url") or "")
            if not method or not url:
                continue
            response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
            status = int(response.get("status") or 200)
            events.append({"method": method, "url": url, "status": status})
    if not events:
        raise BlackBoxHarGoldenError("demo_events_required")
    return {
        "account_alias": account_alias,
        "role_alias": role_alias,
        "role_rank": role_rank,
        "events": events,
        # Secrets accepted only into ephemeral session path; never exported.
        "auth_headers": {
            "Cookie": "session=SECRET_COOKIE",
            "Authorization": "Bearer SECRET_TOKEN",
        },
    }


def _load_json_object(path: Path, *, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise BlackBoxHarGoldenError(f"{label}_file_missing")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise BlackBoxHarGoldenError(f"{label}_json_invalid") from error
    if not isinstance(payload, dict):
        raise BlackBoxHarGoldenError(f"{label}_object_required")
    return payload
