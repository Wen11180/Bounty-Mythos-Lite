from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


AUDIT_VERSION = "candidate_hunter_corpus_audit_v1"
VERIFIER_VERSION = "1.0.0"
CAPABILITY_LEVELS = ("lab", "benchmark", "field_proven")
LEVEL_RANK = {level: index for index, level in enumerate(CAPABILITY_LEVELS)}
MIN_BENCHMARK_CASES = 30
MIN_BENCHMARK_CASES_PER_SUITE = 15
MIN_BENCHMARK_REPOSITORIES_PER_SUITE = 3
MIN_HISTORICAL_PILOT_CASES = 5
MIN_HISTORICAL_PILOT_REPOSITORIES = 5
MIN_HISTORICAL_PILOT_RISK_FAMILIES = 4
SUITES = ("development", "release")
SUPPORTED_MANIFEST_VERSIONS = {
    "candidate_hunter_release_fixture_v1",
    "candidate_hunter_typescript_express_fixture_v1",
    "candidate_hunter_typescript_express_fixture_v2",
    "candidate_hunter_repository_history_fixture_v1",
}
HUNTER_ARTIFACT_KINDS = {
    "vulnerable_snapshot",
    "scope",
    "policy",
    "api",
    "har",
}
REQUIRED_HUNTER_ARTIFACT_KINDS = {
    "vulnerable_snapshot",
    "scope",
    "policy",
}
ORACLE_ARTIFACT_KINDS = {
    "fixed_snapshot",
    "patch",
    "advisory",
    "expected_root_cause",
    "evaluation",
    "leak_canary",
}
CONSTRUCTION_FIELDS = {
    "origin",
    "manually_injected",
    "template_generated",
    "mutated_from_another_case",
    "minimized_or_rewritten",
    "teaching_fixture",
}
CONSTRUCTION_FALSE_FIELDS = CONSTRUCTION_FIELDS - {"origin"}
DIRECTORY_ARTIFACT_KINDS = {"vulnerable_snapshot", "fixed_snapshot"}
REVISION_PATTERN = re.compile(r"^[0-9a-fA-F]{40,64}$")
TREE_PATTERN = re.compile(r"^[0-9a-fA-F]{40,64}$")
OPAQUE_HISTORICAL_CASE_ID_PATTERN = re.compile(r"^rhp-[a-z0-9]{3,16}$")
SECRET_MATERIAL_PATTERNS = (
    re.compile(rb"-----BEGIN(?: [A-Z]+){0,3} PRIVATE KEY-----"),
    re.compile(rb"(?<![A-Za-z0-9_-])(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(rb"(?i)(?<![A-Za-z0-9_-])gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(rb"(?i)(?<![A-Za-z0-9_-])github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(rb"(?i)(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(
        rb"(?<![A-Za-z0-9_-])"
        rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    ),
)


def audit_candidate_hunter_corpus(fixture_root: str | Path) -> dict[str, Any]:
    root = Path(fixture_root).resolve()
    schema_failures: list[dict[str, str]] = []
    safety_failures: list[dict[str, str]] = []
    provenance_failures: list[dict[str, str]] = []
    benchmark_blockers: list[dict[str, str]] = []
    claim_failures: list[dict[str, str]] = []
    case_results: list[dict[str, Any]] = []
    manifest = _read_json_object(
        root / "suite-manifest.json",
        "suite_manifest",
        schema_failures,
    )

    if manifest.get("version") not in SUPPORTED_MANIFEST_VERSIONS:
        schema_failures.append(
            _issue("suite_manifest.version", "unsupported_manifest_version")
        )
    claimed_level = _text(manifest.get("capability_level"))
    if claimed_level not in CAPABILITY_LEVELS:
        schema_failures.append(
            _issue("suite_manifest.capability_level", "unsupported_capability_level")
        )

    entries = manifest.get("cases")
    if not isinstance(entries, list):
        schema_failures.append(_issue("suite_manifest.cases", "must_be_list"))
        entries = []

    counts = {
        "total": 0,
        "development": 0,
        "release": 0,
        "synthetic": 0,
        "historical_patch": 0,
    }
    lineage_sets = {suite: set() for suite in SUITES}
    vulnerable_tree_sets = {suite: set() for suite in SUITES}
    patch_sets = {suite: set() for suite in SUITES}
    advisory_event_sets = {suite: set() for suite in SUITES}
    advisory_event_counts: dict[str, int] = {}
    verified_risk_families: set[str] = set()
    seen_case_ids: set[str] = set()
    seen_paths: set[str] = set()
    bundle_cache: dict[tuple[str, str, str], tuple[dict[str, str] | None, str]] = {}

    for index, entry in enumerate(entries):
        path = f"suite_manifest.cases[{index}]"
        if not isinstance(entry, dict):
            schema_failures.append(_issue(path, "must_be_object"))
            continue
        case_id = _text(entry.get("case_id"))
        suite = _text(entry.get("suite"))
        relative_case_path = _text(entry.get("path"))
        if not case_id:
            schema_failures.append(_issue(f"{path}.case_id", "required"))
        elif case_id in seen_case_ids:
            schema_failures.append(_issue(f"{path}.case_id", "must_be_unique"))
        else:
            seen_case_ids.add(case_id)
        if suite not in SUITES:
            schema_failures.append(_issue(f"{path}.suite", "unsupported_suite"))
        if not relative_case_path:
            schema_failures.append(_issue(f"{path}.path", "required"))
        elif relative_case_path in seen_paths:
            schema_failures.append(_issue(f"{path}.path", "must_be_unique"))
        else:
            seen_paths.add(relative_case_path)
        if not case_id or suite not in SUITES or not relative_case_path:
            continue

        case_root = _resolve_under(
            root,
            relative_case_path,
            f"{case_id}.path",
            schema_failures,
            require_directory=True,
        )
        if case_root is None:
            continue
        metadata = _read_json_object(
            case_root / "case.json",
            f"{case_id}.case_metadata",
            schema_failures,
        )
        counts["total"] += 1
        counts[suite] += 1
        case_schema_failures: list[dict[str, str]] = []
        if metadata.get("case_id") != case_id:
            failure = _issue(
                f"{case_id}.case_metadata.case_id",
                "case_id_mismatch",
            )
            schema_failures.append(failure)
            case_schema_failures.append(failure)
        case_safety_failures: list[dict[str, str]] = []
        _audit_safety_flags(metadata, case_id, case_safety_failures)
        safety_failures.extend(case_safety_failures)

        synthetic = metadata.get("synthetic") is True
        if synthetic:
            counts["synthetic"] += 1
        provenance = metadata.get("provenance")
        source_kind = (
            _text(provenance.get("source_kind"))
            if isinstance(provenance, dict)
            else ""
        )
        historical_declared = source_kind == "historical_patch"
        if historical_declared:
            counts["historical_patch"] += 1

        must_verify_history = (
            historical_declared
            or metadata.get("synthetic") is False
            or claimed_level in {"benchmark", "field_proven"}
        )
        case_provenance_failures: list[dict[str, str]] = []
        verified_facts: dict[str, str] | None = None
        if must_verify_history:
            verified_facts = _audit_historical_case(
                case_root=case_root,
                case_id=case_id,
                entry_lineage_id=_text(entry.get("repository_lineage_id")),
                metadata=metadata,
                failures=case_provenance_failures,
                bundle_cache=bundle_cache,
            )
            provenance_failures.extend(case_provenance_failures)

        historical_evidence_verified = bool(
            must_verify_history
            and verified_facts is not None
            and not case_provenance_failures
        )
        provenance_classification = (
            "historical_evidence_verified"
            if (
                historical_evidence_verified
                and not case_schema_failures
                and not case_safety_failures
            )
            else "lab"
        )
        failure_reasons = sorted(
            {
                failure["reason"]
                for failure in (
                    case_schema_failures
                    + case_safety_failures
                    + case_provenance_failures
                )
            }
        )
        case_results.append(
            {
                "case_id": case_id,
                "suite": suite,
                "provenance_classification": provenance_classification,
                "historical_evidence_verified": historical_evidence_verified,
                "source_repository_binding": (
                    "operator_attested"
                    if historical_evidence_verified
                    else (
                        "unverified"
                        if must_verify_history
                        else "not_applicable"
                    )
                ),
                "runtime_isolation_verified": False,
                "benchmark_evaluation_allowed": False,
                "failure_reasons": failure_reasons,
            }
        )
        if verified_facts is not None and not case_provenance_failures:
            lineage_sets[suite].add(verified_facts["repository_lineage_id"])
            verified_risk_families.add(_text(metadata.get("risk_family")))
            vulnerable_tree_sets[suite].add(
                verified_facts["vulnerable_tree_digest"]
            )
            patch_sets[suite].add(verified_facts["patch_digest"])
            advisory_event_id = verified_facts["advisory_event_id"]
            advisory_event_sets[suite].add(advisory_event_id)
            advisory_event_counts[advisory_event_id] = (
                advisory_event_counts.get(advisory_event_id, 0) + 1
            )

    verified_historical_cases = sum(
        result["provenance_classification"] == "historical_evidence_verified"
        for result in case_results
    )
    _audit_benchmark_shape(
        counts=counts,
        verified_historical_cases=verified_historical_cases,
        lineage_sets=lineage_sets,
        blockers=benchmark_blockers,
    )
    lineage_overlap = sorted(
        lineage_sets["development"].intersection(lineage_sets["release"])
    )
    vulnerable_tree_overlap = sorted(
        vulnerable_tree_sets["development"].intersection(
            vulnerable_tree_sets["release"]
        )
    )
    patch_overlap = sorted(
        patch_sets["development"].intersection(patch_sets["release"])
    )
    advisory_event_overlap = sorted(
        advisory_event_sets["development"].intersection(
            advisory_event_sets["release"]
        )
    )
    if lineage_overlap:
        benchmark_blockers.append(
            _issue("repository_split", "repository_lineage_split_overlap")
        )
    if vulnerable_tree_overlap:
        benchmark_blockers.append(
            _issue("repository_split", "vulnerable_tree_split_overlap")
        )
    if patch_overlap:
        benchmark_blockers.append(
            _issue("repository_split", "patch_split_overlap")
        )
    if advisory_event_overlap:
        benchmark_blockers.append(
            _issue("repository_split", "advisory_event_split_overlap")
        )
    if any(count > 1 for count in advisory_event_counts.values()):
        benchmark_blockers.append(
            _issue("corpus.advisory_events", "advisory_event_must_be_unique")
        )

    verified_lineages = set().union(*lineage_sets.values())
    historical_pilot_corpus_ready = not (
        schema_failures or safety_failures or provenance_failures
    ) and (
        verified_historical_cases >= MIN_HISTORICAL_PILOT_CASES
        and len(verified_lineages) >= MIN_HISTORICAL_PILOT_REPOSITORIES
        and len(verified_risk_families) >= MIN_HISTORICAL_PILOT_RISK_FAMILIES
        and len(advisory_event_counts) == verified_historical_cases
    )
    historical_corpus_evidence_complete = not (
        schema_failures
        or safety_failures
        or provenance_failures
        or benchmark_blockers
    )
    proven_level = "lab"
    provenance_level = (
        "historical_corpus_evidence_complete"
        if historical_corpus_evidence_complete
        else "lab"
    )
    if claimed_level == "field_proven":
        claim_failures.append(
            _issue(
                "suite_manifest.capability_level",
                "field_proven_requires_external_outcomes",
            )
        )
    if (
        claimed_level in LEVEL_RANK
        and LEVEL_RANK[claimed_level] > LEVEL_RANK[proven_level]
    ):
        claim_failures.append(
            _issue(
                "suite_manifest.capability_level",
                "claimed_level_exceeds_proven_level",
            )
        )

    historical_results = [
        result
        for result in case_results
        if result["historical_evidence_verified"]
    ]
    if counts["historical_patch"] == 0:
        external_source_verification = "not_applicable_lab_synthetic"
    elif len(historical_results) == counts["historical_patch"]:
        external_source_verification = (
            "offline_git_evidence_verified_repository_binding_operator_attested"
        )
    else:
        external_source_verification = "failed"

    report = {
        "version": AUDIT_VERSION,
        "verifier_version": VERIFIER_VERSION,
        "status": (
            "failed"
            if (
                schema_failures
                or safety_failures
                or provenance_failures
                or claim_failures
            )
            else "passed"
        ),
        "fixture_root": str(root),
        "claimed_level": claimed_level or "unknown",
        "proven_level": proven_level,
        "provenance_level": provenance_level,
        "source_repository_binding_verified": False,
        "runtime_isolation_verified": False,
        "benchmark_evaluation_allowed": False,
        "case_counts": counts,
        "case_results": case_results,
        "historical_pilot": {
            "corpus_ready": historical_pilot_corpus_ready,
            "evidence_scope": "offline_historical_corpus_only",
            "minimum_verified_cases": MIN_HISTORICAL_PILOT_CASES,
            "minimum_repository_lineages": MIN_HISTORICAL_PILOT_REPOSITORIES,
            "minimum_risk_families": MIN_HISTORICAL_PILOT_RISK_FAMILIES,
            "verified_cases": verified_historical_cases,
            "repository_lineages": len(verified_lineages),
            "risk_families": len(verified_risk_families),
            "blind_model_evaluation_completed": False,
        },
        "repository_split": {
            "development": sorted(lineage_sets["development"]),
            "release": sorted(lineage_sets["release"]),
            "overlap": lineage_overlap,
            "vulnerable_tree_overlap": vulnerable_tree_overlap,
            "patch_overlap": patch_overlap,
            "advisory_event_overlap": advisory_event_overlap,
        },
        "schema_failures": _unique_issues(schema_failures),
        "safety_failures": _unique_issues(safety_failures),
        "provenance_failures": _unique_issues(provenance_failures),
        "benchmark_blockers": _unique_issues(benchmark_blockers),
        "claim_failures": _unique_issues(claim_failures),
        "field_proven_assessed": False,
        "external_source_verification": external_source_verification,
    }
    report["audit_digest"] = _audit_digest(report)
    return report


def capability_level_meets(proven_level: str, required_level: str) -> bool:
    if required_level != "lab":
        return False
    return (
        proven_level in LEVEL_RANK
        and required_level in LEVEL_RANK
        and LEVEL_RANK[proven_level] >= LEVEL_RANK[required_level]
    )


def _audit_safety_flags(
    metadata: dict[str, Any],
    case_id: str,
    failures: list[dict[str, str]],
) -> None:
    required = {
        "authorized_for_local_benchmark": True,
        "contains_real_user_data": False,
        "contains_secrets": False,
    }
    for field, expected in required.items():
        if metadata.get(field) is not expected:
            failures.append(
                _issue(
                    f"{case_id}.case_metadata.{field}",
                    f"must_be_{str(expected).lower()}",
                )
            )
    if not isinstance(metadata.get("synthetic"), bool):
        failures.append(
            _issue(f"{case_id}.case_metadata.synthetic", "must_be_boolean")
        )


def _audit_benchmark_shape(
    *,
    counts: dict[str, int],
    verified_historical_cases: int,
    lineage_sets: dict[str, set[str]],
    blockers: list[dict[str, str]],
) -> None:
    if (
        counts["total"] < MIN_BENCHMARK_CASES
        or counts["historical_patch"] < MIN_BENCHMARK_CASES
    ):
        blockers.append(
            _issue("corpus.case_counts", "benchmark_requires_30_historical_cases")
        )
    if verified_historical_cases < MIN_BENCHMARK_CASES:
        blockers.append(
            _issue(
                "corpus.case_counts",
                "benchmark_requires_30_verified_historical_cases",
            )
        )
    if counts["synthetic"]:
        blockers.append(
            _issue("corpus.synthetic_cases", "benchmark_requires_non_synthetic_cases")
        )
    for suite in SUITES:
        if counts[suite] < MIN_BENCHMARK_CASES_PER_SUITE:
            blockers.append(
                _issue(
                    f"corpus.case_counts.{suite}",
                    "benchmark_requires_15_cases_per_suite",
                )
            )
        if len(lineage_sets[suite]) < MIN_BENCHMARK_REPOSITORIES_PER_SUITE:
            blockers.append(
                _issue(
                    f"repository_split.{suite}",
                    "benchmark_requires_3_repository_lineages_per_suite",
                )
            )


def _audit_historical_case(
    *,
    case_root: Path,
    case_id: str,
    entry_lineage_id: str,
    metadata: dict[str, Any],
    failures: list[dict[str, str]],
    bundle_cache: dict[
        tuple[str, str, str],
        tuple[dict[str, str] | None, str],
    ],
) -> dict[str, str] | None:
    if not OPAQUE_HISTORICAL_CASE_ID_PATTERN.fullmatch(case_id):
        failures.append(_issue(f"{case_id}.case_id", "opaque_case_id_required"))
    if case_root.name != case_id:
        failures.append(
            _issue(f"{case_id}.path", "case_directory_must_match_opaque_case_id")
        )
    if metadata.get("synthetic") is not False:
        failures.append(
            _issue(
                f"{case_id}.case_metadata.synthetic",
                "benchmark_requires_non_synthetic_cases",
            )
        )
    if not _text(metadata.get("risk_family")):
        failures.append(
            _issue(f"{case_id}.case_metadata.risk_family", "required")
        )
    _audit_construction(metadata.get("construction"), case_id, failures)
    provenance = metadata.get("provenance")
    if not isinstance(provenance, dict):
        failures.append(_issue(f"{case_id}.provenance", "must_be_object"))
        return None
    if provenance.get("source_kind") != "historical_patch":
        failures.append(
            _issue(
                f"{case_id}.provenance.source_kind",
                "historical_patch_required",
            )
        )

    repository = provenance.get("repository")
    repository_lineage_id = ""
    source_reference_digest = ""
    if not isinstance(repository, dict):
        failures.append(_issue(f"{case_id}.provenance.repository", "must_be_object"))
    else:
        canonical_url = _text(repository.get("canonical_url"))
        repository_lineage_id = _text(repository.get("lineage_id"))
        if not _is_safe_https_url(canonical_url):
            failures.append(
                _issue(
                    f"{case_id}.provenance.repository.canonical_url",
                    "safe_https_url_required",
                )
            )
        source_reference = repository.get("source_reference")
        source_path, source_reference_digest = _audit_file_reference(
            case_root=case_root,
            value=source_reference,
            label=f"{case_id}.provenance.repository.source_reference",
            required_parent="provenance",
            failures=failures,
        )
        if source_path is not None:
            source = _read_json_object(
                source_path,
                f"{case_id}.repository_source",
                failures,
            )
            if source.get("version") != "github_repository_source_v1":
                failures.append(
                    _issue(
                        f"{case_id}.repository_source.version",
                        "unsupported_repository_source_version",
                    )
                )
            if source.get("canonical_url") != canonical_url:
                failures.append(
                    _issue(
                        f"{case_id}.repository_source.canonical_url",
                        "repository_source_url_mismatch",
                    )
                )
            source_lineage_id = _text(source.get("root_repository_node_id"))
            if not source_lineage_id:
                failures.append(
                    _issue(
                        f"{case_id}.repository_source.root_repository_node_id",
                        "required",
                    )
                )
            if source_lineage_id != repository_lineage_id:
                failures.append(
                    _issue(
                        f"{case_id}.provenance.repository.lineage_id",
                        "repository_lineage_source_mismatch",
                    )
                )
            if _text(source.get("node_id")) == "":
                failures.append(
                    _issue(f"{case_id}.repository_source.node_id", "required")
                )
            if not _timezone_aware_timestamp(_text(source.get("captured_at"))):
                failures.append(
                    _issue(
                        f"{case_id}.repository_source.captured_at",
                        "timezone_aware_timestamp_required",
                    )
                )
        if not entry_lineage_id or entry_lineage_id != repository_lineage_id:
            failures.append(
                _issue(
                    f"{case_id}.provenance.repository.lineage_id",
                    "repository_lineage_manifest_mismatch",
                )
            )

    advisory_url = _text(provenance.get("advisory_url"))
    if not _is_safe_https_url(advisory_url):
        failures.append(
            _issue(f"{case_id}.provenance.advisory_url", "safe_https_url_required")
        )
    for field in ("advisory_id", "license_spdx"):
        if not _text(provenance.get(field)):
            failures.append(_issue(f"{case_id}.provenance.{field}", "required"))
    advisory_event_id = _canonical_advisory_event_id(
        advisory_url,
        _text(provenance.get("advisory_id")),
    )
    if not advisory_event_id:
        failures.append(
            _issue(
                f"{case_id}.provenance.advisory_id",
                "advisory_url_identity_mismatch",
            )
        )

    vulnerable_revision = _text(provenance.get("vulnerable_revision")).lower()
    fixed_revision = _text(provenance.get("fixed_revision")).lower()
    for field, value in (
        ("vulnerable_revision", vulnerable_revision),
        ("fixed_revision", fixed_revision),
    ):
        if not REVISION_PATTERN.fullmatch(value):
            failures.append(
                _issue(f"{case_id}.provenance.{field}", "full_revision_required")
            )
    if vulnerable_revision and vulnerable_revision == fixed_revision:
        failures.append(
            _issue(
                f"{case_id}.provenance.fixed_revision",
                "fixed_revision_must_differ",
            )
        )
    vulnerable_tree_oid = _text(provenance.get("vulnerable_tree_oid")).lower()
    fixed_tree_oid = _text(provenance.get("fixed_tree_oid")).lower()
    for field, value in (
        ("vulnerable_tree_oid", vulnerable_tree_oid),
        ("fixed_tree_oid", fixed_tree_oid),
    ):
        if not TREE_PATTERN.fullmatch(value):
            failures.append(
                _issue(f"{case_id}.provenance.{field}", "full_tree_oid_required")
            )
    if not _timezone_aware_timestamp(_text(provenance.get("retrieved_at"))):
        failures.append(
            _issue(
                f"{case_id}.provenance.retrieved_at",
                "timezone_aware_timestamp_required",
            )
        )

    hunter_artifacts = _audit_artifact_group(
        case_root=case_root,
        case_id=case_id,
        group_name="hunter_input",
        value=metadata.get("hunter_input"),
        allowed_kinds=HUNTER_ARTIFACT_KINDS,
        required_kinds=REQUIRED_HUNTER_ARTIFACT_KINDS,
        required_parent="input",
        failures=failures,
    )
    oracle_artifacts = _audit_artifact_group(
        case_root=case_root,
        case_id=case_id,
        group_name="oracle",
        value=metadata.get("oracle"),
        allowed_kinds=ORACLE_ARTIFACT_KINDS,
        required_kinds=ORACLE_ARTIFACT_KINDS,
        required_parent="oracle",
        failures=failures,
    )
    _audit_advisory_artifact(
        case_id=case_id,
        advisory_id=_text(provenance.get("advisory_id")),
        advisory_url=advisory_url,
        advisory_artifact=oracle_artifacts.get("advisory"),
        failures=failures,
    )
    _audit_artifact_separation(
        case_id=case_id,
        hunter_artifacts=hunter_artifacts,
        oracle_artifacts=oracle_artifacts,
        failures=failures,
    )

    bundle_path, bundle_digest = _audit_file_reference(
        case_root=case_root,
        value=provenance.get("history_bundle"),
        label=f"{case_id}.provenance.history_bundle",
        required_parent="provenance",
        failures=failures,
    )
    _audit_review(
        provenance=provenance,
        case_id=case_id,
        advisory_url=advisory_url,
        patch_digest=_artifact_digest(oracle_artifacts, "patch"),
        bundle_digest=bundle_digest,
        source_reference_digest=source_reference_digest,
        failures=failures,
    )

    git_facts: dict[str, str] | None = None
    if (
        bundle_path is not None
        and REVISION_PATTERN.fullmatch(vulnerable_revision)
        and REVISION_PATTERN.fullmatch(fixed_revision)
    ):
        cache_key = (bundle_digest, vulnerable_revision, fixed_revision)
        if cache_key not in bundle_cache:
            bundle_cache[cache_key] = _verify_git_bundle(
                bundle_path,
                vulnerable_revision,
                fixed_revision,
            )
        git_facts, git_failure = bundle_cache[cache_key]
        if git_facts is None:
            failures.append(
                _issue(
                    f"{case_id}.provenance.history_bundle",
                    git_failure,
                )
            )

    if git_facts is not None:
        expected_pairs = (
            (
                "vulnerable_tree_oid",
                vulnerable_tree_oid,
                git_facts["vulnerable_tree_oid"],
            ),
            ("fixed_tree_oid", fixed_tree_oid, git_facts["fixed_tree_oid"]),
        )
        for field, declared, actual in expected_pairs:
            if declared != actual:
                failures.append(
                    _issue(
                        f"{case_id}.provenance.{field}",
                        f"{field}_mismatch",
                    )
                )
        vulnerable_digest = _artifact_digest(
            hunter_artifacts,
            "vulnerable_snapshot",
        )
        fixed_digest = _artifact_digest(oracle_artifacts, "fixed_snapshot")
        patch_digest = _artifact_digest(oracle_artifacts, "patch")
        if vulnerable_digest != git_facts["vulnerable_tree_digest"]:
            failures.append(
                _issue(
                    f"{case_id}.hunter_input.vulnerable_snapshot",
                    "vulnerable_snapshot_git_tree_mismatch",
                )
            )
        if fixed_digest != git_facts["fixed_tree_digest"]:
            failures.append(
                _issue(
                    f"{case_id}.oracle.fixed_snapshot",
                    "fixed_snapshot_git_tree_mismatch",
                )
            )
        if patch_digest != git_facts["patch_digest"]:
            failures.append(
                _issue(
                    f"{case_id}.oracle.patch",
                    "patch_git_diff_mismatch",
                )
            )

    if failures or git_facts is None:
        return None
    return {
        "repository_lineage_id": repository_lineage_id,
        "vulnerable_tree_digest": git_facts["vulnerable_tree_digest"],
        "patch_digest": git_facts["patch_digest"],
        "advisory_event_id": advisory_event_id,
    }


def _audit_construction(
    value: Any,
    case_id: str,
    failures: list[dict[str, str]],
) -> None:
    label = f"{case_id}.construction"
    if not isinstance(value, dict):
        failures.append(_issue(label, "must_be_object"))
        return
    if set(value) != CONSTRUCTION_FIELDS:
        failures.append(_issue(label, "unexpected_keys"))
    if value.get("origin") != "upstream_historical_snapshot":
        failures.append(
            _issue(f"{label}.origin", "upstream_historical_snapshot_required")
        )
    for field in CONSTRUCTION_FALSE_FIELDS:
        if value.get(field) is not False:
            failures.append(_issue(f"{label}.{field}", "must_be_false"))


def _audit_artifact_group(
    *,
    case_root: Path,
    case_id: str,
    group_name: str,
    value: Any,
    allowed_kinds: set[str],
    required_kinds: set[str],
    required_parent: str,
    failures: list[dict[str, str]],
) -> dict[str, tuple[Path, str]]:
    label = f"{case_id}.{group_name}"
    if not isinstance(value, dict) or set(value) != {"artifacts"}:
        failures.append(_issue(label, "artifacts_object_required"))
        return {}
    specs = value.get("artifacts")
    if not isinstance(specs, list):
        failures.append(_issue(f"{label}.artifacts", "must_be_list"))
        return {}
    artifacts: dict[str, tuple[Path, str]] = {}
    for index, spec in enumerate(specs):
        spec_label = f"{label}.artifacts[{index}]"
        if not isinstance(spec, dict) or set(spec) != {"kind", "path", "sha256"}:
            failures.append(_issue(spec_label, "unexpected_keys"))
            continue
        kind = _text(spec.get("kind"))
        if kind not in allowed_kinds:
            failures.append(_issue(f"{spec_label}.kind", "unsupported_artifact_kind"))
            continue
        if kind in artifacts:
            failures.append(_issue(f"{spec_label}.kind", "must_be_unique"))
            continue
        relative_path = _text(spec.get("path"))
        if not relative_path or Path(relative_path).parts[:1] != (required_parent,):
            reason = (
                "oracle_path_exposed_to_hunter"
                if required_parent == "oracle"
                else f"{required_parent}_path_required"
            )
            failures.append(
                _issue(f"{spec_label}.path", reason)
            )
            continue
        resolved = _resolve_under(
            case_root,
            relative_path,
            f"{spec_label}.path",
            failures,
            require_directory=kind in DIRECTORY_ARTIFACT_KINDS,
        )
        if resolved is None:
            continue
        try:
            actual_digest = (
                _tree_digest(resolved) if resolved.is_dir() else _file_digest(resolved)
            )
        except (OSError, ValueError):
            failures.append(_issue(f"{spec_label}.path", "artifact_unreadable"))
            continue
        declared_digest = _text(spec.get("sha256")).lower()
        if declared_digest != actual_digest:
            failures.append(_issue(f"{spec_label}.sha256", f"{kind}_digest_mismatch"))
        try:
            contains_secret_material = _artifact_contains_secret_material(resolved)
        except OSError:
            failures.append(_issue(f"{spec_label}.path", "artifact_unreadable"))
            continue
        if contains_secret_material:
            failures.append(
                _issue(
                    f"{spec_label}.path",
                    "secret_shaped_material_not_allowed",
                )
            )
        artifacts[kind] = (resolved, actual_digest)
    for kind in sorted(required_kinds - set(artifacts)):
        failures.append(_issue(f"{label}.artifacts", f"missing_artifact:{kind}"))
    return artifacts


def _audit_advisory_artifact(
    *,
    case_id: str,
    advisory_id: str,
    advisory_url: str,
    advisory_artifact: tuple[Path, str] | None,
    failures: list[dict[str, str]],
) -> None:
    if advisory_artifact is None:
        return
    advisory = _read_json_object(
        advisory_artifact[0],
        f"{case_id}.oracle.advisory",
        failures,
    )
    if advisory.get("id") != advisory_id:
        failures.append(
            _issue(
                f"{case_id}.oracle.advisory.id",
                "advisory_id_mismatch",
            )
        )
    artifact_url = _text(advisory.get("source_url") or advisory.get("url"))
    if artifact_url != advisory_url:
        failures.append(
            _issue(
                f"{case_id}.oracle.advisory.source_url",
                "advisory_url_mismatch",
            )
        )


def _audit_artifact_separation(
    *,
    case_id: str,
    hunter_artifacts: dict[str, tuple[Path, str]],
    oracle_artifacts: dict[str, tuple[Path, str]],
    failures: list[dict[str, str]],
) -> None:
    for hunter_kind, (hunter_path, _) in hunter_artifacts.items():
        for oracle_kind, (oracle_path, _) in oracle_artifacts.items():
            if _paths_overlap(hunter_path, oracle_path):
                failures.append(
                    _issue(
                        f"{case_id}.hunter_input.{hunter_kind}",
                        f"oracle_artifact_overlap:{oracle_kind}",
                    )
                )
    canary = oracle_artifacts.get("leak_canary")
    if canary is None:
        return
    try:
        canary_bytes = canary[0].read_bytes()
    except OSError:
        failures.append(_issue(f"{case_id}.oracle.leak_canary", "canary_unreadable"))
        return
    if len(canary_bytes) < 16:
        failures.append(_issue(f"{case_id}.oracle.leak_canary", "canary_too_short"))
        return
    for kind, (path, _) in hunter_artifacts.items():
        if _artifact_contains(path, canary_bytes):
            failures.append(
                _issue(
                    f"{case_id}.hunter_input.{kind}",
                    "oracle_canary_exposed_to_hunter",
                )
            )


def _audit_file_reference(
    *,
    case_root: Path,
    value: Any,
    label: str,
    required_parent: str,
    failures: list[dict[str, str]],
) -> tuple[Path | None, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        failures.append(_issue(label, "file_reference_required"))
        return None, ""
    relative_path = _text(value.get("path"))
    if not relative_path or Path(relative_path).parts[:1] != (required_parent,):
        failures.append(_issue(f"{label}.path", f"{required_parent}_path_required"))
        return None, ""
    path = _resolve_under(
        case_root,
        relative_path,
        f"{label}.path",
        failures,
        require_directory=False,
    )
    if path is None:
        return None, ""
    actual_digest = _file_digest(path)
    if _text(value.get("sha256")).lower() != actual_digest:
        failures.append(_issue(f"{label}.sha256", "file_digest_mismatch"))
    return path, actual_digest


def _audit_review(
    *,
    provenance: dict[str, Any],
    case_id: str,
    advisory_url: str,
    patch_digest: str,
    bundle_digest: str,
    source_reference_digest: str,
    failures: list[dict[str, str]],
) -> None:
    review = provenance.get("review")
    if not isinstance(review, dict):
        failures.append(_issue(f"{case_id}.provenance.review", "must_be_object"))
        return
    if review.get("status") != "approved":
        failures.append(
            _issue(f"{case_id}.provenance.review.status", "approved_required")
        )
    if not _text(review.get("reviewer")):
        failures.append(
            _issue(f"{case_id}.provenance.review.reviewer", "required")
        )
    if not _timezone_aware_timestamp(_text(review.get("reviewed_at"))):
        failures.append(
            _issue(
                f"{case_id}.provenance.review.reviewed_at",
                "timezone_aware_timestamp_required",
            )
        )
    evidence_refs = review.get("evidence_refs")
    if (
        not isinstance(evidence_refs, list)
        or not evidence_refs
        or any(not _text(item) for item in evidence_refs)
    ):
        failures.append(
            _issue(
                f"{case_id}.provenance.review.evidence_refs",
                "nonempty_string_list_required",
            )
        )
        return
    required_refs = {
        advisory_url,
        f"patch:{patch_digest}",
        f"bundle:{bundle_digest}",
        f"repository-source:{source_reference_digest}",
    }
    if not required_refs.issubset(set(evidence_refs)):
        failures.append(
            _issue(
                f"{case_id}.provenance.review.evidence_refs",
                "source_patch_bundle_refs_required",
            )
        )


def _verify_git_bundle(
    bundle_path: Path,
    vulnerable_revision: str,
    fixed_revision: str,
) -> tuple[dict[str, str] | None, str]:
    try:
        with tempfile.TemporaryDirectory(prefix="mythos-corpus-git-") as temp_dir:
            git_dir = Path(temp_dir) / "history.git"
            if _git(["init", "--bare", "--quiet", str(git_dir)]).returncode != 0:
                return None, "git_verifier_initialization_failed"
            git_prefix = [f"--git-dir={git_dir}"]
            if (
                _git([*git_prefix, "bundle", "verify", str(bundle_path)]).returncode
                != 0
            ):
                return None, "git_bundle_verification_failed"
            fetch = _git(
                [
                    *git_prefix,
                    "fetch",
                    "--quiet",
                    str(bundle_path),
                    "refs/corpus/vulnerable:refs/corpus/vulnerable",
                    "refs/corpus/fixed:refs/corpus/fixed",
                ]
            )
            if fetch.returncode != 0:
                return None, "git_bundle_refs_missing"
            actual_vulnerable = _git_text(
                [
                    *git_prefix,
                    "rev-parse",
                    "refs/corpus/vulnerable^{commit}",
                ]
            )
            actual_fixed = _git_text(
                [*git_prefix, "rev-parse", "refs/corpus/fixed^{commit}"]
            )
            if (
                actual_vulnerable != vulnerable_revision
                or actual_fixed != fixed_revision
            ):
                return None, "git_bundle_revision_mismatch"
            if (
                _git(
                    [
                        *git_prefix,
                        "merge-base",
                        "--is-ancestor",
                        vulnerable_revision,
                        fixed_revision,
                    ]
                ).returncode
                != 0
            ):
                return None, "fixed_revision_not_descendant"
            vulnerable_tree_oid = _git_text(
                [*git_prefix, "rev-parse", f"{vulnerable_revision}^{{tree}}"]
            )
            fixed_tree_oid = _git_text(
                [*git_prefix, "rev-parse", f"{fixed_revision}^{{tree}}"]
            )
            vulnerable_tree_digest = _git_tree_digest(
                git_prefix,
                vulnerable_revision,
            )
            fixed_tree_digest = _git_tree_digest(git_prefix, fixed_revision)
            diff = _git(
                [
                    *git_prefix,
                    "diff",
                    "--binary",
                    "--full-index",
                    "--no-ext-diff",
                    vulnerable_revision,
                    fixed_revision,
                    "--",
                ]
            )
            if diff.returncode != 0:
                return None, "git_diff_reproduction_failed"
            return (
                {
                    "vulnerable_tree_oid": vulnerable_tree_oid,
                    "fixed_tree_oid": fixed_tree_oid,
                    "vulnerable_tree_digest": vulnerable_tree_digest,
                    "fixed_tree_digest": fixed_tree_digest,
                    "patch_digest": _bytes_digest(diff.stdout),
                },
                "",
            )
    except (OSError, UnicodeDecodeError, ValueError):
        return None, "git_bundle_verification_failed"


def _git_tree_digest(git_prefix: list[str], revision: str) -> str:
    listing = _git(
        [*git_prefix, "ls-tree", "-r", "-z", "--full-tree", revision]
    )
    if listing.returncode != 0:
        raise ValueError("git_tree_listing_failed")
    entries: list[dict[str, str]] = []
    for raw_entry in listing.stdout.split(b"\0"):
        if not raw_entry:
            continue
        metadata, raw_path = raw_entry.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        if object_type != "blob" or mode == "120000":
            raise ValueError("unsupported_git_tree_entry")
        blob = _git([*git_prefix, "cat-file", "blob", object_id])
        if blob.returncode != 0:
            raise ValueError("git_blob_read_failed")
        entries.append(
            {
                "path": raw_path.decode("utf-8"),
                "sha256": _bytes_digest(blob.stdout),
            }
        )
    entries.sort(key=lambda entry: entry["path"])
    return _json_digest(entries)


def _git(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _git_text(args: list[str]) -> str:
    result = _git(args)
    if result.returncode != 0:
        raise ValueError("git_command_failed")
    return result.stdout.decode("ascii").strip().lower()


def _read_json_object(
    path: Path,
    label: str,
    failures: list[dict[str, str]],
) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        failures.append(_issue(label, "unreadable_json"))
        return {}
    if not isinstance(value, dict):
        failures.append(_issue(label, "must_be_object"))
        return {}
    return value


def _resolve_under(
    root: Path,
    relative_path: str,
    label: str,
    failures: list[dict[str, str]],
    *,
    require_directory: bool,
) -> Path | None:
    try:
        resolved_root = root.resolve(strict=True)
        requested_path = Path(relative_path)
        if requested_path.is_absolute() or ".." in requested_path.parts:
            raise ValueError
        candidate = resolved_root
        for part in requested_path.parts:
            candidate /= part
            if _is_path_link(candidate):
                failures.append(_issue(label, "symlink_not_allowed"))
                return None
        candidate = candidate.resolve(strict=True)
        candidate.relative_to(resolved_root)
    except (OSError, ValueError):
        failures.append(_issue(label, "path_missing_or_outside_case"))
        return None
    if require_directory and not candidate.is_dir():
        failures.append(_issue(label, "directory_required"))
        return None
    if not require_directory and not candidate.is_file():
        failures.append(_issue(label, "file_required"))
        return None
    return candidate


def _tree_digest(root: Path) -> str:
    entries = []
    for path in root.rglob("*"):
        if _is_path_link(path):
            raise ValueError("symlink_not_allowed")
        if path.is_file():
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": _file_digest(path),
                }
            )
    entries.sort(key=lambda entry: entry["path"])
    return _json_digest(entries)


def _is_path_link(path: Path) -> bool:
    return path.is_symlink() or (
        hasattr(path, "is_junction") and path.is_junction()
    )


def _artifact_contains(path: Path, needle: bytes) -> bool:
    if path.is_file():
        return needle in path.read_bytes()
    return any(
        needle in candidate.read_bytes()
        for candidate in path.rglob("*")
        if candidate.is_file()
    )


def _artifact_contains_secret_material(path: Path) -> bool:
    candidates = (
        (path,)
        if path.is_file()
        else tuple(candidate for candidate in path.rglob("*") if candidate.is_file())
    )
    for candidate in candidates:
        content = candidate.read_bytes()
        if any(pattern.search(content) is not None for pattern in SECRET_MATERIAL_PATTERNS):
            return True
    return False


def _paths_overlap(first: Path, second: Path) -> bool:
    return (
        first == second
        or first in second.parents
        or second in first.parents
    )


def _artifact_digest(
    artifacts: dict[str, tuple[Path, str]],
    kind: str,
) -> str:
    artifact = artifacts.get(kind)
    return artifact[1] if artifact is not None else ""


def _file_digest(path: Path) -> str:
    return _bytes_digest(path.read_bytes())


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _bytes_digest(payload)


def _audit_digest(report: dict[str, Any]) -> str:
    stable_report = {
        key: value
        for key, value in report.items()
        if key not in {"fixture_root", "audit_digest"}
    }
    return _json_digest(stable_report)


def _is_safe_https_url(value: str) -> bool:
    parsed = urlsplit(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


def _canonical_advisory_event_id(advisory_url: str, advisory_id: str) -> str:
    if not _is_safe_https_url(advisory_url) or not advisory_id:
        return ""
    parsed = urlsplit(advisory_url)
    path = parsed.path.rstrip("/")
    if path.rsplit("/", 1)[-1].lower() != advisory_id.lower():
        return ""
    return f"{parsed.hostname.lower()}{path.lower()}"


def _timezone_aware_timestamp(value: str) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _issue(path: str, reason: str) -> dict[str, str]:
    return {"path": path, "reason": reason}


def _unique_issues(issues: list[dict[str, str]]) -> list[dict[str, str]]:
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for issue in issues:
        key = (issue["path"], issue["reason"])
        if key not in seen:
            unique.append(issue)
            seen.add(key)
    return unique


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


__all__ = [
    "AUDIT_VERSION",
    "CAPABILITY_LEVELS",
    "VERIFIER_VERSION",
    "audit_candidate_hunter_corpus",
    "capability_level_meets",
]
