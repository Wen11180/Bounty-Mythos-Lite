from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from app.cli import main as cli_main
from app.intelligence_benchmark.corpus_provenance import (
    audit_candidate_hunter_corpus,
    capability_level_meets,
)
from app.intelligence_benchmark.release_v1 import (
    evaluate_candidate_hunter_release_suite_v1,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
LAB_CORPORA = (
    FIXTURE_ROOT / "candidate_hunter_release",
    FIXTURE_ROOT / "candidate_hunter_typescript_release",
    FIXTURE_ROOT / "candidate_hunter_typescript_release_v2",
)
PILOT_CORPUS = FIXTURE_ROOT / "candidate_hunter_repository_history_pilot"


@pytest.fixture(scope="module")
def historical_corpus_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _write_historical_corpus(
        tmp_path_factory.mktemp("candidate-hunter-history-template")
    )


def _copied_historical_corpus(
    template: Path,
    destination: Path,
) -> Path:
    return Path(shutil.copytree(template, destination))


@pytest.mark.parametrize("fixture_root", LAB_CORPORA)
def test_committed_synthetic_corpora_are_explicitly_lab_only(
    fixture_root: Path,
):
    report = audit_candidate_hunter_corpus(fixture_root)

    assert report["status"] == "passed"
    assert report["claimed_level"] == "lab"
    assert report["proven_level"] == "lab"
    assert report["case_counts"] == {
        "total": 24,
        "development": 12,
        "release": 12,
        "synthetic": 24,
        "historical_patch": 0,
    }
    assert "benchmark_requires_30_historical_cases" in _reasons(report)
    assert report["repository_split"]["overlap"] == []


def test_unknown_manifest_version_fails_closed(tmp_path: Path):
    corpus_root = tmp_path / "unknown-corpus"
    _write_json(
        corpus_root / "suite-manifest.json",
        {
            "version": "candidate_hunter_repository_history_fixture_v999",
            "capability_level": "lab",
            "cases": [],
        },
    )

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert "unsupported_manifest_version" in _reasons(report)


def test_flipping_a_lab_case_to_non_synthetic_cannot_self_upgrade(
    tmp_path: Path,
):
    corpus_root = tmp_path / "candidate_hunter_release"
    shutil.copytree(LAB_CORPORA[0], corpus_root)
    case_path = corpus_root / "cases" / "case-001" / "case.json"
    metadata = _read_json(case_path)
    metadata["synthetic"] = False
    _write_json(case_path, metadata)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert report["proven_level"] == "lab"
    assert "must_be_object" in _reasons(report)


def test_committed_historical_pilot_is_cross_repository_but_remains_lab():
    report = audit_candidate_hunter_corpus(PILOT_CORPUS)

    assert report["status"] == "passed"
    assert report["claimed_level"] == "lab"
    assert report["proven_level"] == "lab"
    assert report["case_counts"]["historical_patch"] == 5
    assert {
        result["case_id"] for result in report["case_results"]
    } == {
        "rhp-0c8a4",
        "rhp-3f6d2",
        "rhp-a7c9",
        "rhp-b94e1",
        "rhp-e27b5",
    }
    assert all(
        result["historical_evidence_verified"]
        and result["provenance_classification"]
        == "historical_evidence_verified"
        and result["failure_reasons"] == []
        for result in report["case_results"]
    )
    for result in report["case_results"]:
        gold = _read_json(
            PILOT_CORPUS
            / "cases"
            / result["case_id"]
            / "oracle"
            / "expected_root_cause.json"
        )
        assert gold["version"] == "candidate_hunter_historical_gold_v2"
        assert gold["case_id"] == result["case_id"]
        assert gold["security_invariant"]
        assert gold["attacker_controlled_source"]
        assert gold["missing_or_incorrect_control"]
        assert gold["sensitive_operation"]
        assert gold["fixed_behavior"]
        assert gold["refutation_checks"]
    assert report["historical_pilot"] == {
        "corpus_ready": True,
        "evidence_scope": "offline_historical_corpus_only",
        "minimum_verified_cases": 5,
        "minimum_repository_lineages": 5,
        "minimum_risk_families": 4,
        "verified_cases": 5,
        "repository_lineages": 5,
        "risk_families": 5,
        "blind_model_evaluation_completed": False,
    }
    assert report["source_repository_binding_verified"] is False
    assert report["benchmark_evaluation_allowed"] is False
    assert report["external_source_verification"] == (
        "offline_git_evidence_verified_repository_binding_operator_attested"
    )
    assert "benchmark_requires_30_historical_cases" in _reasons(report)


def test_historical_case_identity_must_be_opaque(tmp_path: Path):
    corpus_root = Path(shutil.copytree(PILOT_CORPUS, tmp_path / "pilot"))
    manifest_path = corpus_root / "suite-manifest.json"
    manifest = _read_json(manifest_path)
    manifest["cases"][0]["case_id"] = "fast-uri-path-traversal"
    _write_json(manifest_path, manifest)
    case_path = corpus_root / manifest["cases"][0]["path"] / "case.json"
    metadata = _read_json(case_path)
    metadata["case_id"] = "fast-uri-path-traversal"
    _write_json(case_path, metadata)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert "opaque_case_id_required" in _reasons(report)
    assert "case_directory_must_match_opaque_case_id" in _reasons(report)


def test_audit_digest_is_stable_across_checkout_locations(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    first_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "first",
    )
    second_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "second",
    )

    first = audit_candidate_hunter_corpus(first_root)
    second = audit_candidate_hunter_corpus(second_root)

    assert first["fixture_root"] != second["fixture_root"]
    assert first["audit_digest"] == second["audit_digest"]
    assert first["verifier_version"] == second["verifier_version"]


def test_release_metrics_are_explicitly_scoped_to_lab():
    result = evaluate_candidate_hunter_release_suite_v1([])

    assert result["metric_scope"] == "lab"
    assert result["capability_level"] == "lab"
    assert result["benchmark_claim_allowed"] is False


def test_provenance_gate_cannot_authorize_benchmark_evaluation():
    assert capability_level_meets("lab", "lab") is True
    assert capability_level_meets("benchmark", "benchmark") is False
    assert capability_level_meets("field_proven", "field_proven") is False


def test_historical_corpus_completes_provenance_but_cannot_authorize_benchmark(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    corpus_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "corpus",
    )

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "passed"
    assert report["claimed_level"] == "lab"
    assert report["proven_level"] == "lab"
    assert report["provenance_level"] == "historical_corpus_evidence_complete"
    assert report["source_repository_binding_verified"] is False
    assert report["runtime_isolation_verified"] is False
    assert report["benchmark_evaluation_allowed"] is False
    assert report["benchmark_blockers"] == []
    assert report["case_counts"] == {
        "total": 30,
        "development": 15,
        "release": 15,
        "synthetic": 0,
        "historical_patch": 30,
    }
    assert len(report["repository_split"]["development"]) == 3
    assert len(report["repository_split"]["release"]) == 3
    assert report["repository_split"]["overlap"] == []


def test_benchmark_claim_fails_when_one_case_is_synthetic(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    corpus_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "corpus",
    )
    case_path = corpus_root / "cases" / "rhp-001" / "case.json"
    metadata = _read_json(case_path)
    metadata["synthetic"] = True
    _write_json(case_path, metadata)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert report["proven_level"] == "lab"
    assert "benchmark_requires_non_synthetic_cases" in _reasons(report)


def test_benchmark_claim_fails_when_repository_split_overlaps(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    corpus_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "corpus",
    )
    manifest_path = corpus_root / "suite-manifest.json"
    manifest = _read_json(manifest_path)
    development_entry = next(
        entry for entry in manifest["cases"] if entry["suite"] == "development"
    )
    release_entry = next(
        entry for entry in manifest["cases"] if entry["suite"] == "release"
    )
    shared_lineage_id = development_entry["repository_lineage_id"]
    release_entry["repository_lineage_id"] = shared_lineage_id
    _write_json(manifest_path, manifest)

    case_path = corpus_root / release_entry["path"] / "case.json"
    metadata = _read_json(case_path)
    metadata["provenance"]["repository"]["lineage_id"] = shared_lineage_id
    source_reference = metadata["provenance"]["repository"]["source_reference"]
    source_path = case_path.parent / source_reference["path"]
    source = _read_json(source_path)
    source["root_repository_node_id"] = shared_lineage_id
    _write_json(source_path, source)
    old_source_digest = source_reference["sha256"]
    new_source_digest = _file_digest(source_path)
    source_reference["sha256"] = new_source_digest
    metadata["provenance"]["review"]["evidence_refs"] = [
        (
            f"repository-source:{new_source_digest}"
            if item == f"repository-source:{old_source_digest}"
            else item
        )
        for item in metadata["provenance"]["review"]["evidence_refs"]
    ]
    _write_json(case_path, metadata)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "passed"
    assert report["provenance_level"] == "lab"
    assert report["repository_split"]["overlap"] == [shared_lineage_id]
    assert "repository_lineage_split_overlap" in _reasons(report)


def test_benchmark_claim_fails_when_oracle_is_exposed_to_runner(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    corpus_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "corpus",
    )
    case_root = corpus_root / "cases" / "rhp-001"
    case_path = case_root / "case.json"
    metadata = _read_json(case_path)
    exposed_patch = case_root / "input" / "patch.diff"
    exposed_patch.write_text(
        (case_root / "oracle" / "patch.diff").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    patch_spec = next(
        spec
        for spec in metadata["oracle"]["artifacts"]
        if spec["kind"] == "patch"
    )
    patch_spec["path"] = "input/patch.diff"
    patch_spec["sha256"] = _file_digest(exposed_patch)
    _write_json(case_path, metadata)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert "oracle_path_exposed_to_hunter" in _reasons(report)


def test_historical_case_rejects_symlinked_artifact(tmp_path: Path):
    corpus_root = Path(shutil.copytree(PILOT_CORPUS, tmp_path / "pilot"))
    case_root = corpus_root / "cases" / "rhp-a7c9"
    case_path = case_root / "case.json"
    metadata = _read_json(case_path)
    scope_path = case_root / "input" / "scope.yaml"
    linked_scope = case_root / "input" / "scope-link.yaml"
    try:
        linked_scope.symlink_to(scope_path.name)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    scope_spec = next(
        spec
        for spec in metadata["hunter_input"]["artifacts"]
        if spec["kind"] == "scope"
    )
    scope_spec["path"] = "input/scope-link.yaml"
    _write_json(case_path, metadata)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert "symlink_not_allowed" in _reasons(report)


def test_historical_case_rejects_secret_shaped_artifact_material(
    tmp_path: Path,
):
    corpus_root = Path(shutil.copytree(PILOT_CORPUS, tmp_path / "pilot"))
    case_root = corpus_root / "cases" / "rhp-a7c9"
    case_path = case_root / "case.json"
    metadata = _read_json(case_path)
    policy_path = case_root / "input" / "policy.md"
    policy_path.write_text(
        policy_path.read_text(encoding="utf-8")
        + "\n-----BEGIN PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    policy_spec = next(
        spec
        for spec in metadata["hunter_input"]["artifacts"]
        if spec["kind"] == "policy"
    )
    policy_spec["sha256"] = _file_digest(policy_path)
    _write_json(case_path, metadata)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert "secret_shaped_material_not_allowed" in _reasons(report)


def test_benchmark_claim_fails_when_declared_patch_digest_is_stale(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    corpus_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "corpus",
    )
    patch_path = corpus_root / "cases" / "rhp-001" / "oracle" / "patch.diff"
    patch_path.write_text("tampered after review", encoding="utf-8")

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert "patch_digest_mismatch" in _reasons(report)


def test_benchmark_claim_fails_when_construction_facts_show_injection(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    corpus_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "corpus",
    )
    case_path = corpus_root / "cases" / "rhp-001" / "case.json"
    metadata = _read_json(case_path)
    metadata["construction"]["manually_injected"] = True
    _write_json(case_path, metadata)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert "must_be_false" in _reasons(report)


def test_benchmark_claim_fails_when_oracle_canary_reaches_hunter_input(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    corpus_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "corpus",
    )
    case_root = corpus_root / "cases" / "rhp-001"
    case_path = case_root / "case.json"
    metadata = _read_json(case_path)
    canary = (case_root / "oracle" / "leak-canary.txt").read_bytes()
    scope_path = case_root / "input" / "scope.yaml"
    scope_path.write_bytes(scope_path.read_bytes() + b"\n" + canary)
    scope_spec = next(
        spec
        for spec in metadata["hunter_input"]["artifacts"]
        if spec["kind"] == "scope"
    )
    scope_spec["sha256"] = _file_digest(scope_path)
    _write_json(case_path, metadata)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert "oracle_canary_exposed_to_hunter" in _reasons(report)


def test_repository_rename_cannot_hide_tree_and_patch_split_overlap(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    corpus_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "corpus",
    )
    source_root = corpus_root / "cases" / "rhp-001"
    target_root = corpus_root / "cases" / "rhp-016"
    source = _read_json(source_root / "case.json")
    target_path = target_root / "case.json"
    target = _read_json(target_path)

    for relative_path in (
        "input/vulnerable_snapshot/handler.ts",
        "oracle/fixed_snapshot/handler.ts",
        "oracle/patch.diff",
        "provenance/history.bundle",
    ):
        shutil.copy2(source_root / relative_path, target_root / relative_path)

    for field in (
        "vulnerable_revision",
        "fixed_revision",
        "vulnerable_tree_oid",
        "fixed_tree_oid",
    ):
        target["provenance"][field] = source["provenance"][field]
    target_bundle = target_root / "provenance" / "history.bundle"
    target["provenance"]["history_bundle"]["sha256"] = _file_digest(target_bundle)
    for kind, relative_path in (
        ("vulnerable_snapshot", "input/vulnerable_snapshot"),
        ("fixed_snapshot", "oracle/fixed_snapshot"),
        ("patch", "oracle/patch.diff"),
    ):
        group = "hunter_input" if kind == "vulnerable_snapshot" else "oracle"
        spec = next(
            item
            for item in target[group]["artifacts"]
            if item["kind"] == kind
        )
        artifact_path = target_root / relative_path
        spec["sha256"] = (
            _tree_digest(artifact_path)
            if artifact_path.is_dir()
            else _file_digest(artifact_path)
        )
    patch_digest = next(
        item["sha256"]
        for item in target["oracle"]["artifacts"]
        if item["kind"] == "patch"
    )
    source_digest = target["provenance"]["repository"]["source_reference"][
        "sha256"
    ]
    target["provenance"]["review"]["evidence_refs"] = [
        target["provenance"]["advisory_url"],
        f"patch:{patch_digest}",
        f"bundle:{_file_digest(target_bundle)}",
        f"repository-source:{source_digest}",
    ]
    _write_json(target_path, target)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "passed"
    assert report["provenance_level"] == "lab"
    assert report["repository_split"]["overlap"] == []
    assert report["repository_split"]["vulnerable_tree_overlap"]
    assert report["repository_split"]["patch_overlap"]
    assert "vulnerable_tree_split_overlap" in _reasons(report)
    assert "patch_split_overlap" in _reasons(report)


def test_same_advisory_event_cannot_inflate_case_or_split_counts(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    corpus_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "corpus",
    )
    source_root = corpus_root / "cases" / "rhp-001"
    target_root = corpus_root / "cases" / "rhp-016"
    source = _read_json(source_root / "case.json")
    target_path = target_root / "case.json"
    target = _read_json(target_path)
    shutil.copy2(
        source_root / "oracle" / "advisory.json",
        target_root / "oracle" / "advisory.json",
    )
    target["provenance"]["advisory_id"] = source["provenance"]["advisory_id"]
    target["provenance"]["advisory_url"] = source["provenance"]["advisory_url"]
    advisory_spec = next(
        item
        for item in target["oracle"]["artifacts"]
        if item["kind"] == "advisory"
    )
    advisory_spec["sha256"] = _file_digest(
        target_root / "oracle" / "advisory.json"
    )
    patch_digest = next(
        item["sha256"]
        for item in target["oracle"]["artifacts"]
        if item["kind"] == "patch"
    )
    bundle_digest = target["provenance"]["history_bundle"]["sha256"]
    source_digest = target["provenance"]["repository"]["source_reference"][
        "sha256"
    ]
    target["provenance"]["review"]["evidence_refs"] = [
        target["provenance"]["advisory_url"],
        f"patch:{patch_digest}",
        f"bundle:{bundle_digest}",
        f"repository-source:{source_digest}",
    ]
    _write_json(target_path, target)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "passed"
    assert report["provenance_level"] == "lab"
    assert report["repository_split"]["advisory_event_overlap"]
    assert "advisory_event_split_overlap" in _reasons(report)
    assert "advisory_event_must_be_unique" in _reasons(report)


def test_corpus_cannot_claim_field_proven_without_external_outcomes(
    tmp_path: Path,
    historical_corpus_template: Path,
):
    corpus_root = _copied_historical_corpus(
        historical_corpus_template,
        tmp_path / "corpus",
    )
    manifest_path = corpus_root / "suite-manifest.json"
    manifest = _read_json(manifest_path)
    manifest["capability_level"] = "field_proven"
    _write_json(manifest_path, manifest)

    report = audit_candidate_hunter_corpus(corpus_root)

    assert report["status"] == "failed"
    assert report["proven_level"] == "lab"
    assert "field_proven_requires_external_outcomes" in _reasons(report)


def test_cli_writes_lab_audit_and_fails_a_benchmark_requirement(
    tmp_path: Path,
):
    output_path = tmp_path / "corpus-audit.json"
    fixture_root = FIXTURE_ROOT / "candidate_hunter_release"

    assert (
        cli_main(
            [
                "candidate-hunter-corpus-audit",
                "--fixture-root",
                str(fixture_root),
                "--require-level",
                "lab",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    report = _read_json(output_path)
    assert report["proven_level"] == "lab"
    assert report["required_level"] == "lab"
    assert report["requirement_met"] is True

    assert (
        cli_main(
            [
                "candidate-hunter-corpus-audit",
                "--fixture-root",
                str(fixture_root),
                "--require-level",
                "benchmark",
                "--output",
                str(output_path),
            ]
        )
        == 1
    )
    report = _read_json(output_path)
    assert report["required_level"] == "benchmark"
    assert report["requirement_met"] is False


def test_cli_stdout_is_json_only(capsys: pytest.CaptureFixture[str]):
    exit_code = cli_main(
        [
            "candidate-hunter-corpus-audit",
            "--fixture-root",
            str(FIXTURE_ROOT / "candidate_hunter_release"),
            "--require-level",
            "lab",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out)["requirement_met"] is True
    assert captured.err.strip() == "Candidate Hunter corpus audit passed"


def _write_historical_corpus(tmp_path: Path) -> Path:
    root = tmp_path / "candidate_hunter_repository_history"
    development_repositories = (
        "github.com/acme/dev-a",
        "github.com/acme/dev-b",
        "github.com/acme/dev-c",
    )
    release_repositories = (
        "github.com/acme/release-d",
        "github.com/acme/release-e",
        "github.com/acme/release-f",
    )
    histories = {
        repository_id: _create_git_history(
            tmp_path / "_history_sources" / repository_id.rsplit("/", 1)[-1],
            repository_id.rsplit("/", 1)[-1],
        )
        for repository_id in (
            *development_repositories,
            *release_repositories,
        )
    }
    entries = []
    for index in range(1, 31):
        suite = "development" if index <= 15 else "release"
        repositories = (
            development_repositories
            if suite == "development"
            else release_repositories
        )
        repository_id = repositories[(index - 1) % len(repositories)]
        history = histories[repository_id]
        repository_lineage_id = f"R_TEST_{repository_id.rsplit('/', 1)[-1]}"
        case_id = f"rhp-{index:03d}"
        relative_case_path = f"cases/{case_id}"
        case_root = root / relative_case_path
        vulnerable_root = case_root / "input" / "vulnerable_snapshot"
        fixed_root = case_root / "oracle" / "fixed_snapshot"
        inputs_root = case_root / "input"
        oracle_root = case_root / "oracle"
        provenance_root = case_root / "provenance"
        vulnerable_root.mkdir(parents=True)
        fixed_root.mkdir(parents=True)
        inputs_root.mkdir(parents=True, exist_ok=True)
        provenance_root.mkdir(parents=True)

        (vulnerable_root / "handler.ts").write_bytes(
            history["vulnerable_source"].encode("utf-8")
        )
        (fixed_root / "handler.ts").write_bytes(
            history["fixed_source"].encode("utf-8")
        )
        (inputs_root / "scope.yaml").write_text(
            "authorized_for_local_benchmark: true\n",
            encoding="utf-8",
        )
        (inputs_root / "policy.md").write_text(
            "Offline historical benchmark policy. No live execution.\n",
            encoding="utf-8",
        )
        patch_path = oracle_root / "patch.diff"
        patch_path.write_bytes(history["patch"])
        advisory_path = oracle_root / "advisory.json"
        advisory_id = f"GHSA-test-{index:04d}"
        advisory_url = (
            f"https://github.com/acme/advisories/security/advisories/{advisory_id}"
        )
        _write_json(
            advisory_path,
            {
                "id": advisory_id,
                "url": advisory_url,
                "repository": repository_id,
            },
        )
        expected_root_path = oracle_root / "expected_root_cause.json"
        _write_json(
            expected_root_path,
            {"root_cause_id": f"historical-root-{index:03d}"},
        )
        evaluation_path = oracle_root / "evaluation.json"
        _write_json(evaluation_path, {"worth_validation": True})
        canary_path = oracle_root / "leak-canary.txt"
        canary_path.write_text(
            f"ORACLE-CANARY-{case_id}-DO-NOT-STAGE",
            encoding="utf-8",
        )
        source_path = provenance_root / "repository-source.json"
        _write_json(
            source_path,
            {
                "version": "github_repository_source_v1",
                "canonical_url": f"https://{repository_id}",
                "node_id": repository_lineage_id,
                "root_repository_node_id": repository_lineage_id,
                "captured_at": "2026-07-26T00:00:00+00:00",
            },
        )
        bundle_path = provenance_root / "history.bundle"
        shutil.copy2(history["bundle_path"], bundle_path)

        provenance = {
            "source_kind": "historical_patch",
            "repository": {
                "canonical_url": f"https://{repository_id}",
                "lineage_id": repository_lineage_id,
                "source_reference": {
                    "path": "provenance/repository-source.json",
                    "sha256": _file_digest(source_path),
                },
            },
            "license_spdx": "MIT",
            "advisory_id": advisory_id,
            "advisory_url": advisory_url,
            "vulnerable_revision": history["vulnerable_revision"],
            "fixed_revision": history["fixed_revision"],
            "vulnerable_tree_oid": history["vulnerable_tree_oid"],
            "fixed_tree_oid": history["fixed_tree_oid"],
            "retrieved_at": "2026-07-26T00:00:00+00:00",
            "history_bundle": {
                "path": "provenance/history.bundle",
                "sha256": _file_digest(bundle_path),
            },
            "review": {
                "status": "approved",
                "reviewer": "benchmark-curator",
                "reviewed_at": "2026-07-26T01:00:00+00:00",
                "evidence_refs": [
                    advisory_url,
                    f"patch:{_file_digest(patch_path)}",
                    f"bundle:{_file_digest(bundle_path)}",
                    f"repository-source:{_file_digest(source_path)}",
                ],
            },
        }
        _write_json(
            case_root / "case.json",
            {
                "case_id": case_id,
                "synthetic": False,
                "authorized_for_local_benchmark": True,
                "contains_real_user_data": False,
                "contains_secrets": False,
                "risk_family": "authorization",
                "construction": {
                    "origin": "upstream_historical_snapshot",
                    "manually_injected": False,
                    "template_generated": False,
                    "mutated_from_another_case": False,
                    "minimized_or_rewritten": False,
                    "teaching_fixture": False,
                },
                "hunter_input": {
                    "artifacts": [
                        _artifact_spec(
                            case_root,
                            "vulnerable_snapshot",
                            "input/vulnerable_snapshot",
                        ),
                        _artifact_spec(case_root, "scope", "input/scope.yaml"),
                        _artifact_spec(case_root, "policy", "input/policy.md"),
                    ]
                },
                "oracle": {
                    "artifacts": [
                        _artifact_spec(
                            case_root,
                            "fixed_snapshot",
                            "oracle/fixed_snapshot",
                        ),
                        _artifact_spec(case_root, "patch", "oracle/patch.diff"),
                        _artifact_spec(
                            case_root,
                            "advisory",
                            "oracle/advisory.json",
                        ),
                        _artifact_spec(
                            case_root,
                            "expected_root_cause",
                            "oracle/expected_root_cause.json",
                        ),
                        _artifact_spec(
                            case_root,
                            "evaluation",
                            "oracle/evaluation.json",
                        ),
                        _artifact_spec(
                            case_root,
                            "leak_canary",
                            "oracle/leak-canary.txt",
                        ),
                    ]
                },
                "provenance": provenance,
            },
        )
        entries.append(
            {
                "case_id": case_id,
                "suite": suite,
                "repository_lineage_id": repository_lineage_id,
                "path": relative_case_path,
            }
        )

    _write_json(
        root / "suite-manifest.json",
        {
            "version": "candidate_hunter_repository_history_fixture_v1",
            "capability_level": "lab",
            "cases": entries,
        },
    )
    return root


def _create_git_history(root: Path, repository_name: str) -> dict:
    root.mkdir(parents=True)
    _run_git(["init", "--quiet"], cwd=root)
    _run_git(["config", "user.name", "Benchmark Curator"], cwd=root)
    _run_git(["config", "user.email", "curator@example.invalid"], cwd=root)
    vulnerable_source = (
        f"export const {repository_name.replace('-', '_')} = "
        "(id: string) => store.get(id);\n"
    )
    fixed_source = (
        f"export const {repository_name.replace('-', '_')} = "
        "(id: string, owner: string) => store.getForOwner(id, owner);\n"
    )
    handler_path = root / "handler.ts"
    handler_path.write_text(vulnerable_source, encoding="utf-8")
    _run_git(["add", "handler.ts"], cwd=root)
    _run_git(["commit", "--quiet", "-m", "vulnerable snapshot"], cwd=root)
    vulnerable_revision = _run_git(
        ["rev-parse", "HEAD"],
        cwd=root,
        capture_text=True,
    )
    vulnerable_tree_oid = _run_git(
        ["rev-parse", "HEAD^{tree}"],
        cwd=root,
        capture_text=True,
    )
    handler_path.write_text(fixed_source, encoding="utf-8")
    _run_git(["add", "handler.ts"], cwd=root)
    _run_git(["commit", "--quiet", "-m", "fix ownership check"], cwd=root)
    fixed_revision = _run_git(
        ["rev-parse", "HEAD"],
        cwd=root,
        capture_text=True,
    )
    fixed_tree_oid = _run_git(
        ["rev-parse", "HEAD^{tree}"],
        cwd=root,
        capture_text=True,
    )
    _run_git(
        ["update-ref", "refs/corpus/vulnerable", vulnerable_revision],
        cwd=root,
    )
    _run_git(["update-ref", "refs/corpus/fixed", fixed_revision], cwd=root)
    bundle_path = root / "history.bundle"
    _run_git(
        [
            "bundle",
            "create",
            str(bundle_path),
            "refs/corpus/vulnerable",
            "refs/corpus/fixed",
        ],
        cwd=root,
    )
    patch = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            vulnerable_revision,
            fixed_revision,
            "--",
        ],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return {
        "vulnerable_source": vulnerable_source,
        "fixed_source": fixed_source,
        "vulnerable_revision": vulnerable_revision,
        "fixed_revision": fixed_revision,
        "vulnerable_tree_oid": vulnerable_tree_oid,
        "fixed_tree_oid": fixed_tree_oid,
        "bundle_path": bundle_path,
        "patch": patch,
    }


def _run_git(
    args: list[str],
    *,
    cwd: Path,
    capture_text: bool = False,
) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_DATE": "2026-07-26T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2026-07-26T00:00:00+00:00",
    }
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        env=env,
        stdout=subprocess.PIPE if capture_text else subprocess.DEVNULL,
        text=capture_text,
    )
    return result.stdout.strip() if capture_text else ""


def _artifact_spec(case_root: Path, kind: str, relative_path: str) -> dict:
    path = case_root / relative_path
    digest = _tree_digest(path) if path.is_dir() else _file_digest(path)
    return {"kind": kind, "path": relative_path, "sha256": digest}


def _tree_digest(root: Path) -> str:
    entries = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": _file_digest(path),
        }
        for path in root.rglob("*")
        if path.is_file()
    ]
    entries.sort(key=lambda entry: entry["path"])
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def _reasons(report: dict) -> set[str]:
    return {
        issue["reason"]
        for field in (
            "schema_failures",
            "safety_failures",
            "provenance_failures",
            "benchmark_blockers",
            "claim_failures",
        )
        for issue in report[field]
    }
