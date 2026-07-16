"""Black-box leadership gate: golden corpus + dual-intake iso + quality metrics.

Proves lab-quality leadership claims for the authorized black-box slice:
every golden package gates, stays secret-safe, dual-intake isomorphic,
and retains/refutes with falsify audit coverage. Remote live observe is
out of scope.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.intelligence_benchmark.black_box_har_golden import (
    assert_intake_isomorphism,
    default_fixture_root,
    list_golden_packages,
    run_har_golden_package,
)

REQUIRED_METRICS = (
    "golden_pass_rate",
    "safety_rate",
    "iso_pass_rate",
    "falsify_coverage",
    "retain_hit",
    "refute_kill",
    "family_retain_coverage",
    "family_refute_coverage",
)

# Leadership requires these differential families on the lab corpus.
REQUIRED_FAMILIES = (
    "cross_account_object_swap",
    "lower_role_replay",
    "unauthenticated_read_only_replay",
    "owned_parent_child_swap",
    "reversible_out_of_order_state_transition",
)


class BlackBoxLeadershipGateError(ValueError):
    """Raised when leadership gate inputs are invalid."""


def run_black_box_leadership_gate(
    root: Path | None = None,
    *,
    require_perfect: bool = True,
) -> dict[str, Any]:
    """Run all HAR goldens + dual-intake iso and compute leadership metrics."""
    fixture_root = Path(root) if root is not None else default_fixture_root()
    if not fixture_root.is_dir():
        raise BlackBoxLeadershipGateError("leadership_fixture_root_missing")

    packages = list_golden_packages(fixture_root)

    package_rows: list[dict[str, Any]] = []
    iso_results: list[dict[str, Any]] = []
    failed_packages: list[str] = []

    golden_pass = 0
    safety_pass = 0
    iso_pass = 0
    falsify_pass = 0
    retain_hit = 0
    retain_expected = 0
    refute_kill = 0
    refute_expected = 0

    families_with_retain: set[str] = set()
    families_with_refute: set[str] = set()

    for package_dir in packages:
        result = run_har_golden_package(package_dir)
        iso = assert_intake_isomorphism(package_dir)
        iso_results.append(iso)

        gate_ok = bool(result.get("gate", {}).get("passed"))
        safety_ok = bool(result.get("safety", {}).get("safe"))
        iso_ok = bool(iso.get("passed"))
        if gate_ok:
            golden_pass += 1
        if safety_ok:
            safety_pass += 1
        if iso_ok:
            iso_pass += 1
        if not gate_ok or not safety_ok:
            failed_packages.append(str(result.get("package_id")))

        expected_status = str(result.get("manifest", {}).get("expected_status") or "")
        expected_trial = str(
            result.get("manifest", {}).get("expected_trial_class") or ""
        )
        matching = [
            card
            for card in (result.get("top_candidates") or [])
            if card.get("plan_trial_class") == expected_trial
            or card.get("family") == expected_trial
        ]
        falsify_ok = bool(matching) and all(
            bool(card.get("falsify_attempts")) for card in matching
        )
        if falsify_ok:
            falsify_pass += 1

        if expected_status == "retained":
            retain_expected += 1
            if any(card.get("decision") == "retained" for card in matching):
                retain_hit += 1
                if expected_trial:
                    families_with_retain.add(expected_trial)
            retained_classes = {
                str(card.get("plan_trial_class") or card.get("family") or "")
                for card in (result.get("top_candidates") or [])
                if card.get("decision") == "retained"
            }
            for trial_class in list(
                result.get("manifest", {}).get("expected_retained_trial_classes") or []
            ):
                if str(trial_class) in retained_classes:
                    families_with_retain.add(str(trial_class))
        elif expected_status in {"refuted", "suppressed"}:
            refute_expected += 1
            if matching and all(
                card.get("decision") != "retained"
                and any(
                    attempt.get("outcome") == "kill"
                    for attempt in (card.get("falsify_attempts") or [])
                )
                for card in matching
            ):
                refute_kill += 1
                if expected_trial:
                    families_with_refute.add(expected_trial)

        package_rows.append(
            {
                "package_id": result.get("package_id"),
                "expected_status": expected_status,
                "expected_trial_class": expected_trial,
                "gate_passed": gate_ok,
                "safety_ok": safety_ok,
                "iso_ok": iso_ok,
                "falsify_ok": falsify_ok,
                "observed_statuses": list(
                    result.get("gate", {}).get("observed_statuses") or []
                ),
            }
        )

    total = len(packages) or 1
    required_family_count = len(REQUIRED_FAMILIES) or 1
    metrics = {
        "golden_pass_rate": golden_pass / total,
        "safety_rate": safety_pass / total,
        "iso_pass_rate": iso_pass / total,
        "falsify_coverage": falsify_pass / total,
        "retain_hit": (retain_hit / retain_expected) if retain_expected else 1.0,
        "refute_kill": (refute_kill / refute_expected) if refute_expected else 1.0,
        "family_retain_coverage": len(
            families_with_retain.intersection(REQUIRED_FAMILIES)
        )
        / required_family_count,
        "family_refute_coverage": len(
            families_with_refute.intersection(REQUIRED_FAMILIES)
        )
        / required_family_count,
    }

    failures: list[str] = []
    if failed_packages:
        failures.append("golden_packages_failed:" + ",".join(failed_packages))
    for row in package_rows:
        if not row["iso_ok"]:
            failures.append(f"iso_failed:{row['package_id']}")
        if not row["falsify_ok"]:
            failures.append(f"falsify_missing:{row['package_id']}")
    if require_perfect:
        for name in REQUIRED_METRICS:
            if metrics[name] < 1.0:
                failures.append(f"metric_below_threshold:{name}={metrics[name]:.3f}")

    passed = not failures
    return {
        "schema_version": "black_box_leadership_gate_v1",
        "fixture_root": str(fixture_root.resolve()),
        "package_count": len(packages),
        "passed": passed,
        "require_perfect": require_perfect,
        "metrics": metrics,
        "thresholds": {name: 1.0 for name in REQUIRED_METRICS},
        "required_families": list(REQUIRED_FAMILIES),
        "families_with_retain": sorted(families_with_retain),
        "families_with_refute": sorted(families_with_refute),
        "failures": failures,
        "packages": package_rows,
        "golden_summary": {
            "passed": not failed_packages,
            "package_count": len(packages),
            "failed_packages": failed_packages,
        },
        "iso_results": [
            {
                "package_id": item.get("package_id"),
                "passed": item.get("passed"),
                "failures": item.get("failures"),
            }
            for item in iso_results
        ],
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "raw_secrets_persisted": False,
        "claim_scope": "lab_quality_leadership",
        "claim_note": (
            "Metrics prove synthetic dual-role HAR local-lab quality only; "
            "not XBOW live-target proof."
        ),
    }
