from __future__ import annotations

import asyncio
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil

import pytest

from app.codebase_map import map_authorized_code_files
from app.cross_source_candidate_generator import (
    CandidateModelConfig,
    ReplayCandidateReasoner,
    build_fact_pack,
    generate_cross_source_candidates,
)
from app.intelligence_benchmark import release_fixtures
from app.intelligence_benchmark.release_fixtures import (
    ReleaseFixtureError,
    load_release_fixture_gold,
    load_release_fixture_suite,
    stage_release_fixture_inputs,
)
from app.llm.base import ProviderName


LEGACY_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "candidate_hunter_release"
TYPESCRIPT_FIXTURE_ROOT = (
    Path(__file__).parent / "fixtures" / "candidate_hunter_typescript_release"
)
LEGACY_FIXTURE_TREE_DIGEST = (
    "b051ca8af471b150a73fc21d84a3d090f8149fa73d919e4b8bc400cd35552be3"
)
TYPESCRIPT_PROFILE = "candidate_hunter_typescript_express"
TYPESCRIPT_VERSION = "candidate_hunter_typescript_express_fixture_v1"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def _typescript_fixture_root(tmp_path: Path) -> Path:
    root = tmp_path / "candidate_hunter_typescript_release"
    cases = []
    patterns = ("object_ownership", "tenant_boundary", "role_boundary")
    input_specs = (
        ("scope", "inputs/scope.json"),
        ("policy", "inputs/policy.md"),
        ("api", "inputs/api.json"),
        ("har", "inputs/traffic.har.json"),
        ("code", "inputs/code.ts"),
    )
    for index in range(1, 25):
        suite = "development" if index <= 12 else "release"
        suite_index = index - 1 if suite == "development" else index - 13
        case_id = f"tse-{index:03d}"
        relative_root = f"cases/case-{index:03d}"
        case_root = root / relative_root
        inputs_root = case_root / "inputs"
        inputs_root.mkdir(parents=True)
        _write_json(
            case_root / "case.json",
            {
                "case_id": case_id,
                "synthetic": True,
                "authorized_for_local_benchmark": True,
                "contains_real_user_data": False,
                "contains_secrets": False,
                "inputs": [
                    {"kind": kind, "path": relative_path}
                    for kind, relative_path in input_specs
                ],
            },
        )
        _write_json(inputs_root / "scope.json", {"local_only": True})
        (inputs_root / "policy.md").write_text(
            "Synthetic local benchmark policy.", encoding="utf-8"
        )
        _write_json(inputs_root / "api.json", {"openapi": "3.0.0", "paths": {}})
        _write_json(inputs_root / "traffic.har.json", {"log": {"entries": []}})
        (inputs_root / "code.ts").write_text(
            'import { Router } from "express";\nconst router = Router();\n',
            encoding="utf-8",
        )
        cases.append(
            {
                "case_id": case_id,
                "suite": suite,
                "authorization_pattern": patterns[suite_index // 4],
                "path": relative_root,
            }
        )
    _write_json(
        root / "suite-manifest.json",
        {
            "profile": TYPESCRIPT_PROFILE,
            "version": TYPESCRIPT_VERSION,
            "cases": cases,
        },
    )
    return root


def _fixture_tree_digest(root: Path) -> str:
    digest = sha256()
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        relative_path = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative_path).to_bytes(4, "big"))
        digest.update(relative_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def test_legacy_release_fixture_tree_stays_byte_for_byte_unchanged():
    assert _fixture_tree_digest(LEGACY_FIXTURE_ROOT) == LEGACY_FIXTURE_TREE_DIGEST


def test_typescript_profile_loads_without_pre_capture_oracle_metadata(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)

    cases = load_release_fixture_suite(fixture_root, "development")

    assert len(cases) == 12
    assert {case.profile for case in cases} == {TYPESCRIPT_PROFILE}
    assert {case.authorization_pattern for case in cases} == {
        "object_ownership",
        "tenant_boundary",
        "role_boundary",
    }
    assert all(case.risk_family is None for case in cases)
    assert all(case.expected_disposition is None for case in cases)


def test_typescript_fixture_loader_rejects_unknown_profile(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["profile"] = "candidate_hunter_unknown"
    _write_json(manifest_path, manifest)

    with pytest.raises(ReleaseFixtureError, match="suite_manifest:unsupported_profile"):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_rejects_missing_profile(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["profile"]
    _write_json(manifest_path, manifest)

    with pytest.raises(ReleaseFixtureError, match="suite_manifest:unsupported_profile"):
        load_release_fixture_suite(fixture_root, "development")


def test_legacy_fixture_loader_rejects_unknown_version(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_release"
    shutil.copytree(LEGACY_FIXTURE_ROOT, fixture_root)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = "candidate_hunter_release_fixture_unknown"
    _write_json(manifest_path, manifest)

    with pytest.raises(ReleaseFixtureError, match="suite_manifest:unsupported_version"):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_requires_twelve_cases_per_suite(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][11]["suite"] = "release"
    _write_json(manifest_path, manifest)

    with pytest.raises(
        ReleaseFixtureError,
        match="suite_manifest:development:case_count",
    ):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_rejects_unknown_authorization_pattern(
    tmp_path: Path,
):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][0]["authorization_pattern"] = "object_access"
    _write_json(manifest_path, manifest)

    with pytest.raises(
        ReleaseFixtureError,
        match="suite_manifest:unsupported_authorization_pattern",
    ):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_requires_four_cases_per_pattern_per_suite(
    tmp_path: Path,
):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][0]["authorization_pattern"] = "tenant_boundary"
    _write_json(manifest_path, manifest)

    with pytest.raises(
        ReleaseFixtureError,
        match="suite_manifest:development:authorization_pattern_count",
    ):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_rejects_unknown_manifest_field(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["gold_id"] = "hidden-oracle"
    _write_json(manifest_path, manifest)

    with pytest.raises(
        ReleaseFixtureError,
        match="suite_manifest:unexpected_keys",
    ):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_rejects_oracle_field_in_manifest_entry(
    tmp_path: Path,
):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][0]["expected_disposition"] = "retain"
    _write_json(manifest_path, manifest)

    with pytest.raises(
        ReleaseFixtureError,
        match=r"suite_manifest\.cases\[0\]:unexpected_keys",
    ):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_rejects_oracle_field_in_case_metadata(
    tmp_path: Path,
):
    fixture_root = _typescript_fixture_root(tmp_path)
    case_path = fixture_root / "cases" / "case-001" / "case.json"
    metadata = json.loads(case_path.read_text(encoding="utf-8"))
    metadata["risk_family"] = "authorization"
    _write_json(case_path, metadata)

    with pytest.raises(
        ReleaseFixtureError,
        match="tse-001:case_metadata:unexpected_keys",
    ):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_staging_rejects_disposition_word(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    cases = load_release_fixture_suite(fixture_root, "development")
    (cases[0].root / "inputs" / "policy.md").write_text(
        "Synthetic local benchmark expected result: retain.",
        encoding="utf-8",
    )

    with pytest.raises(
        ReleaseFixtureError,
        match="tse-001:policy:oracle_disposition",
    ):
        stage_release_fixture_inputs(cases[0])


@pytest.mark.parametrize(
    "reserved_field",
    (
        "expected_disposition",
        "expected_roots",
        "gold_id",
        "root_cause_id",
        "disposition",
        "worth_validation",
        "required_evidence_refs",
        "decisive_refutation_refs",
        "duplicate_of",
        "scope_allowed",
        "authorization_pattern",
    ),
)
def test_typescript_fixture_staging_rejects_reserved_gold_field(
    reserved_field: str,
    tmp_path: Path,
):
    fixture_root = _typescript_fixture_root(tmp_path)
    cases = load_release_fixture_suite(fixture_root, "development")
    (cases[0].root / "inputs" / "policy.md").write_text(
        f"Synthetic local benchmark marker: {reserved_field}.",
        encoding="utf-8",
    )

    with pytest.raises(
        ReleaseFixtureError,
        match="tse-001:policy:oracle_field",
    ):
        stage_release_fixture_inputs(cases[0])


def test_typescript_fixture_loader_rejects_unknown_version(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = "candidate_hunter_typescript_express_fixture_unknown"
    _write_json(manifest_path, manifest)

    with pytest.raises(ReleaseFixtureError, match="suite_manifest:unsupported_version"):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_requires_exact_total_case_count(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"].pop()
    _write_json(manifest_path, manifest)

    with pytest.raises(ReleaseFixtureError, match="suite_manifest:case_count"):
        load_release_fixture_suite(fixture_root, "development")


@pytest.mark.parametrize(
    ("field", "reason"),
    (
        ("case_id", "duplicate_case_id"),
        ("path", "duplicate_path"),
    ),
)
def test_typescript_fixture_loader_rejects_duplicate_manifest_identity(
    field: str,
    reason: str,
    tmp_path: Path,
):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][1][field] = manifest["cases"][0][field]
    _write_json(manifest_path, manifest)

    with pytest.raises(ReleaseFixtureError, match=f"suite_manifest:{reason}"):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_rejects_manifest_path_escape(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"][0]["path"] = "../outside"
    _write_json(manifest_path, manifest)

    with pytest.raises(ReleaseFixtureError, match="path_escape"):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_rejects_case_id_mismatch(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    case_path = fixture_root / "cases" / "case-001" / "case.json"
    metadata = json.loads(case_path.read_text(encoding="utf-8"))
    metadata["case_id"] = "tse-unrelated"
    _write_json(case_path, metadata)

    with pytest.raises(ReleaseFixtureError, match="tse-001:case_id_mismatch"):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_rejects_unsafe_case_metadata(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    case_path = fixture_root / "cases" / "case-001" / "case.json"
    metadata = json.loads(case_path.read_text(encoding="utf-8"))
    metadata["synthetic"] = False
    _write_json(case_path, metadata)

    with pytest.raises(ReleaseFixtureError, match="tse-001:synthetic_must_be_true"):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_requires_all_five_input_kinds(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    case_path = fixture_root / "cases" / "case-001" / "case.json"
    metadata = json.loads(case_path.read_text(encoding="utf-8"))
    metadata["inputs"].pop()
    _write_json(case_path, metadata)

    with pytest.raises(ReleaseFixtureError, match="tse-001:input_kinds_incomplete"):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_requires_typescript_code_input(tmp_path: Path):
    fixture_root = _typescript_fixture_root(tmp_path)
    case_path = fixture_root / "cases" / "case-001" / "case.json"
    metadata = json.loads(case_path.read_text(encoding="utf-8"))
    code_input = next(item for item in metadata["inputs"] if item["kind"] == "code")
    code_input["path"] = "inputs/code.py"
    _write_json(case_path, metadata)

    with pytest.raises(ReleaseFixtureError, match="tse-001:typescript_code_required"):
        load_release_fixture_suite(fixture_root, "development")


def test_typescript_fixture_loader_only_materializes_requested_suite_case_files(
    tmp_path: Path,
):
    fixture_root = _typescript_fixture_root(tmp_path)
    (fixture_root / "cases" / "case-013" / "case.json").unlink()

    cases = load_release_fixture_suite(fixture_root, "development")

    assert len(cases) == 12
    assert {case.suite for case in cases} == {"development"}


def test_legacy_fixture_cases_keep_profile_and_oracle_adjacent_metadata():
    cases = load_release_fixture_suite(LEGACY_FIXTURE_ROOT, "development")

    assert {case.profile for case in cases} == {"candidate_hunter_release_legacy"}
    assert all(isinstance(case.risk_family, str) for case in cases)
    assert all(isinstance(case.expected_disposition, str) for case in cases)


def test_typescript_release_corpus_has_exact_suite_and_pattern_matrix():
    development_cases = load_release_fixture_suite(
        TYPESCRIPT_FIXTURE_ROOT,
        "development",
    )
    release_cases = load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release")

    assert [case.case_id for case in development_cases] == [
        f"tse-{index:03d}" for index in range(1, 13)
    ]
    assert [case.case_id for case in release_cases] == [
        f"tse-{index:03d}" for index in range(13, 25)
    ]
    for suite_cases in (development_cases, release_cases):
        assert {
            pattern: sum(
                case.authorization_pattern == pattern for case in suite_cases
            )
            for pattern in (
                "object_ownership",
                "tenant_boundary",
                "role_boundary",
            )
        } == {
            "object_ownership": 4,
            "tenant_boundary": 4,
            "role_boundary": 4,
        }


def test_typescript_release_corpus_stages_five_local_opaque_inputs_per_case():
    cases = (
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release"),
    )
    scenario_tokens = []

    for case in cases:
        staged = {item.kind: item for item in stage_release_fixture_inputs(case)}
        scope = json.loads(staged["scope"].text)
        scenario_token = scope["fixture_id"].removeprefix("fixture-")

        assert set(staged) == {"scope", "policy", "api", "har", "code"}
        assert scope["local_only"] is True
        assert scope["allowed_repos"] == ["${STAGED_CODE_ROOT}"]
        assert re.fullmatch(r"[a-z]\d[a-z]\d", scenario_token)
        assert scenario_token not in case.case_id.lower().replace("-", "")
        assert staged["code"].path.suffix == ".ts"
        assert 'from "express"' in staged["code"].text
        scenario_tokens.append(scenario_token)

    assert len(scenario_tokens) == len(set(scenario_tokens)) == 24


def test_typescript_release_corpus_staged_inputs_have_no_answer_or_identity_leak():
    cases = (
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release"),
    )
    disposition_pattern = re.compile(
        r"(?<![a-z])(?:retain|refute|deduplicate|suppress)(?![a-z])",
        re.IGNORECASE,
    )

    for case in cases:
        identity_variants = {
            case.case_id.lower(),
            case.case_id.lower().replace("-", "_"),
            case.case_id.lower().replace("-", ""),
        }
        for staged_input in stage_release_fixture_inputs(case):
            values = (
                staged_input.path.relative_to(TYPESCRIPT_FIXTURE_ROOT).as_posix(),
                staged_input.text,
            )
            for value in values:
                lowered = value.lower()
                assert not disposition_pattern.search(value)
                assert not any(identity in lowered for identity in identity_variants)


def test_typescript_release_corpus_code_facts_distinguish_all_four_outcomes():
    cases = (
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release"),
    )
    outcomes = ("retain", "refute", "deduplicate", "suppress")
    expected_control = {
        "object_ownership": "owner_id_filter",
        "tenant_boundary": "tenant_id_filter",
        "role_boundary": "role_check",
    }

    for index, case in enumerate(cases):
        outcome = outcomes[index % len(outcomes)]
        code_input = next(
            item for item in stage_release_fixture_inputs(case) if item.kind == "code"
        )
        result = map_authorized_code_files(
            {
                "authorized_code_files": [
                    {"path": code_input.path.name, "content": code_input.text}
                ]
            }
        )
        gaps = [
            fact
            for fact in result.facts
            if fact.fact_type == "authorization_gap_candidate"
        ]
        controls = [
            fact for fact in result.facts if fact.fact_type == "authz_check"
        ]

        if outcome == "retain":
            assert len(gaps) == 1
            assert controls == []
        elif outcome == "refute":
            assert len(gaps) == 1
            assert expected_control[case.authorization_pattern] in {
                fact.symbol_name for fact in controls
            }
        elif outcome == "deduplicate":
            assert len(gaps) == 2
            gap_handlers = {gap.symbol_name for gap in gaps}
            service_callers: dict[str, set[str]] = {}
            for fact in result.facts:
                if fact.fact_type != "service_call":
                    continue
                service_callers.setdefault(fact.symbol_name, set()).add(
                    fact.payload["caller"]
                )
            assert gap_handlers in service_callers.values()
        else:
            assert len(gaps) == 1
            assert "public_filter" in {fact.symbol_name for fact in controls}


def test_typescript_release_corpus_gold_is_observable_and_matrix_complete():
    cases = (
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release"),
    )
    outcomes = ("retain", "refute", "deduplicate", "suppress")
    matrix_cells = set()

    for index, case in enumerate(cases):
        expected_outcome = outcomes[index % len(outcomes)]
        staged = {item.kind: item for item in stage_release_fixture_inputs(case)}
        code_result = map_authorized_code_files(
            {
                "authorized_code_files": [
                    {
                        "path": staged["code"].path.name,
                        "content": staged["code"].text,
                    }
                ]
            }
        )
        observed_refs = {
            f"code:{fact.source_path}:{fact.symbol_name}"
            for fact in code_result.facts
            if fact.symbol_name
        }
        observed_routes = set()
        api = json.loads(staged["api"].text)
        for route_path, path_item in api["paths"].items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                route = (method.upper(), route_path)
                observed_routes.add(route)
                observed_refs.add(f"api:{route[0]}:{route[1]}")

        gold = load_release_fixture_gold(case)

        assert gold["authorization_pattern"] == case.authorization_pattern
        assert len(gold["expected_roots"]) == (
            2 if expected_outcome == "deduplicate" else 1
        )
        assert {root["disposition"] for root in gold["expected_roots"]} == (
            {"retain", "deduplicate"}
            if expected_outcome == "deduplicate"
            else {expected_outcome}
        )
        for root in gold["expected_roots"]:
            route = root["route"]
            assert (route["method"], route["path"]) in observed_routes
            assert set(root["required_evidence_refs"]) <= observed_refs
            assert set(root["decisive_refutation_refs"]) <= observed_refs
            assert root["scope_allowed"] is True
            assert root["worth_validation"] is (
                root["disposition"] == "retain"
            )
        if expected_outcome == "deduplicate":
            canonical = next(
                root
                for root in gold["expected_roots"]
                if root["disposition"] == "retain"
            )
            duplicate = next(
                root
                for root in gold["expected_roots"]
                if root["disposition"] == "deduplicate"
            )
            assert duplicate["duplicate_of"] == canonical["root_cause_id"]
        matrix_cells.add(
            (case.suite, case.authorization_pattern, expected_outcome)
        )

    assert len(matrix_cells) == 24


def test_development_and_release_matrix_pairs_are_structurally_independent():
    development = load_release_fixture_suite(
        TYPESCRIPT_FIXTURE_ROOT,
        "development",
    )
    release = load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release")

    for development_case, release_case in zip(development, release, strict=True):
        development_inputs = {
            item.kind: item for item in stage_release_fixture_inputs(development_case)
        }
        release_inputs = {
            item.kind: item for item in stage_release_fixture_inputs(release_case)
        }
        development_scope = json.loads(development_inputs["scope"].text)
        release_scope = json.loads(release_inputs["scope"].text)
        development_api = json.loads(development_inputs["api"].text)
        release_api = json.loads(release_inputs["api"].text)

        assert development_scope["fixture_id"] != release_scope["fixture_id"]
        assert set(development_api["paths"]) != set(release_api["paths"])
        assert sha256(development_inputs["code"].text.encode()).digest() != sha256(
            release_inputs["code"].text.encode()
        ).digest()
        assert "const router = Router();" in development_inputs["code"].text
        assert "const app = express();" in release_inputs["code"].text
        assert "async function" in development_inputs["code"].text
        assert " = async " in release_inputs["code"].text


def test_typescript_gold_loader_rejects_authorization_pattern_mismatch(
    tmp_path: Path,
):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    gold_path = case.root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["authorization_pattern"] = "tenant_boundary"
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match="tse-001:gold:authorization_pattern_mismatch",
    ):
        load_release_fixture_gold(case)


def test_typescript_gold_loader_rejects_unknown_top_level_field(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    gold_path = case.root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["label"] = "hidden"
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match="tse-001:gold:unexpected_keys",
    ):
        load_release_fixture_gold(case)


def test_typescript_gold_loader_requires_scope_allowed_true(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    gold_path = case.root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["expected_roots"][0]["scope_allowed"] = False
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match=r"tse-001:gold:expected_roots\[0\]:scope_allowed_must_be_true",
    ):
        load_release_fixture_gold(case)


def test_typescript_gold_loader_rejects_unknown_root_field(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    gold_path = case.root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["expected_roots"][0]["label"] = "hidden"
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match=r"tse-001:gold:expected_roots\[0\]:unexpected_keys",
    ):
        load_release_fixture_gold(case)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("gold_id", "", "gold_id_required"),
        ("root_cause_id", "", "root_cause_id_required"),
        ("vuln_type", "", "vuln_type_required"),
        ("disposition", "unknown", "unsupported_disposition"),
        ("worth_validation", "true", "worth_validation_must_be_boolean"),
        (
            "required_evidence_refs",
            "code:code.ts:readFolio",
            "required_evidence_refs_must_be_string_list",
        ),
        (
            "decisive_refutation_refs",
            [1],
            "decisive_refutation_refs_must_be_string_list",
        ),
        ("duplicate_of", "unexpected", "duplicate_of_must_be_null"),
    ),
)
def test_typescript_gold_loader_rejects_invalid_root_value(
    field: str,
    value: object,
    reason: str,
    tmp_path: Path,
):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    gold_path = case.root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["expected_roots"][0][field] = value
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match=rf"tse-001:gold:expected_roots\[0\]:{reason}",
    ):
        load_release_fixture_gold(case)


@pytest.mark.parametrize(
    ("route", "reason"),
    (
        ("GET /local/folios/a7m2/{folioId}", "route_must_be_object"),
        ({"method": "GET"}, "route_path_required"),
        (
            {"method": "", "path": "/local/folios/a7m2/{folioId}"},
            "route_method_required",
        ),
        (
            {
                "method": "GET",
                "path": "/local/folios/a7m2/{folioId}",
                "label": "hidden",
            },
            "route_unexpected_keys",
        ),
    ),
)
def test_typescript_gold_loader_rejects_invalid_route(
    route: object,
    reason: str,
    tmp_path: Path,
):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    gold_path = case.root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["expected_roots"][0]["route"] = route
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match=rf"tse-001:gold:expected_roots\[0\]:{reason}",
    ):
        load_release_fixture_gold(case)


def test_typescript_gold_loader_requires_refutation_evidence(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[1]
    gold_path = case.root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["expected_roots"][0]["decisive_refutation_refs"] = []
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match=r"tse-002:gold:expected_roots\[0\]:refutation_evidence_required",
    ):
        load_release_fixture_gold(case)


def test_typescript_gold_loader_requires_nonempty_roots(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    gold_path = case.root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["expected_roots"] = []
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match="tse-001:gold:expected_roots_empty",
    ):
        load_release_fixture_gold(case)


def test_typescript_gold_suite_loader_preserves_case_order():
    cases = load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development")
    loader = getattr(release_fixtures, "load_release_fixture_gold_suite", None)

    assert callable(loader)
    gold_suite = loader(cases)

    assert isinstance(gold_suite, tuple)
    assert gold_suite == tuple(load_release_fixture_gold(case) for case in cases)
    assert len(gold_suite) == 12


def test_gold_suite_loader_keeps_legacy_per_case_results():
    cases = load_release_fixture_suite(LEGACY_FIXTURE_ROOT, "development")

    assert release_fixtures.load_release_fixture_gold_suite(cases) == tuple(
        load_release_fixture_gold(case) for case in cases
    )


def test_typescript_gold_suite_loader_rejects_incomplete_outcome_matrix(
    tmp_path: Path,
):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    cases = load_release_fixture_suite(fixture_root, "development")
    gold_path = cases[1].root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["expected_roots"][0]["disposition"] = "retain"
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match="gold_suite:development:object_ownership:outcome_matrix",
    ):
        release_fixtures.load_release_fixture_gold_suite(cases)


def test_typescript_gold_suite_loader_requires_exact_case_count():
    cases = load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development")

    with pytest.raises(ReleaseFixtureError, match="gold_suite:case_count"):
        release_fixtures.load_release_fixture_gold_suite((*cases, cases[0]))


def test_typescript_gold_suite_loader_rejects_mixed_suites():
    development = load_release_fixture_suite(
        TYPESCRIPT_FIXTURE_ROOT,
        "development",
    )
    release = load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release")

    with pytest.raises(ReleaseFixtureError, match="gold_suite:suite_mismatch"):
        release_fixtures.load_release_fixture_gold_suite(
            (*development[:6], *release[6:])
        )


def test_typescript_gold_loader_rejects_unknown_duplicate_target(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[2]
    gold_path = case.root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    duplicate = next(
        root
        for root in gold["expected_roots"]
        if root["disposition"] == "deduplicate"
    )
    duplicate["duplicate_of"] = "missing_object_ownership_check:unknown"
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match="tse-003:gold:duplicate_target_unknown",
    ):
        load_release_fixture_gold(case)


@pytest.mark.parametrize(
    ("field", "reason"),
    (
        ("gold_id", "duplicate_gold_id"),
        ("root_cause_id", "duplicate_root_cause_id"),
    ),
)
def test_typescript_gold_loader_requires_unique_root_identity(
    field: str,
    reason: str,
    tmp_path: Path,
):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[2]
    gold_path = case.root / "gold.json"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["expected_roots"][1][field] = gold["expected_roots"][0][field]
    _write_json(gold_path, gold)

    with pytest.raises(
        ReleaseFixtureError,
        match=f"tse-003:gold:{reason}",
    ):
        load_release_fixture_gold(case)


def test_typescript_release_corpus_has_one_replay_response_per_case():
    cases = (
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release"),
    )

    for case in cases:
        replay_root = case.root / "replay"
        assert {
            path.relative_to(replay_root).as_posix()
            for path in replay_root.rglob("*")
            if path.is_file()
        } == {"response.json"}


def test_typescript_replay_responses_pass_real_schema_and_fact_validation():
    cases = (
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release"),
    )

    for case in cases:
        staged = {item.kind: item for item in stage_release_fixture_inputs(case)}
        code_result = map_authorized_code_files(
            {
                "authorized_code_files": [
                    {"path": "code.ts", "content": staged["code"].text}
                ]
            }
        )
        facts = []
        gaps = [
            fact
            for fact in code_result.facts
            if fact.fact_type == "authorization_gap_candidate"
        ]
        for gap in gaps:
            facts.append(
                {
                    "fact_ref": (
                        f"code:code.ts:{gap.symbol_name}"
                    ),
                    "fact_type": "authorization_gap_candidate",
                    "artifact_kind": "code",
                    "source_path": "code.ts",
                    "symbol_name": gap.symbol_name,
                    "handler": gap.symbol_name,
                    "route_method": gap.route_method,
                    "route_path": gap.route_path,
                    "root_cause": gap.payload["root_cause"],
                }
            )
        api = json.loads(staged["api"].text)
        for route_path, path_item in api["paths"].items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                facts.append(
                    {
                        "fact_ref": f"api:{method.upper()}:{route_path}",
                        "fact_type": "api_surface",
                        "artifact_kind": "api",
                        "route_method": method.upper(),
                        "route_path": route_path,
                    }
                )
        fact_pack = build_fact_pack(
            pipeline_run_id=f"run-{case.case_id}",
            scope_status="in_scope",
            source_files=[{"path": "code.ts", "content": staged["code"].text}],
            facts=facts,
            baseline_candidates=[],
        )
        payload = json.loads(
            (case.root / "replay" / "response.json").read_text(encoding="utf-8")
        )
        assert {
            (
                proposal["affected_endpoint"]["method"],
                proposal["affected_endpoint"]["path"],
            )
            for proposal in payload["proposals"]
        } == {
            (gap.route_method, gap.route_path)
            for gap in gaps
        }

        result = asyncio.run(
            generate_cross_source_candidates(
                fact_pack=fact_pack,
                baseline_candidates=[],
                model_config=CandidateModelConfig(
                    provider=ProviderName.OPENAI,
                    model="fixture-replay-v1",
                ),
                reasoner=ReplayCandidateReasoner(payload),
            )
        )

        assert result.model_status == "completed"
        assert len(result.accepted_candidates) == len(gaps)
        assert result.rejection_reason_counts == {}


def test_typescript_dedup_replays_give_retained_root_unique_priority():
    cases = (
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release"),
    )
    risk_priority = {"critical": 100, "high": 80, "medium": 60, "low": 40, "info": 20}

    for case in cases:
        gold = load_release_fixture_gold(case)
        roots = gold["expected_roots"]
        if {root["disposition"] for root in roots} != {"retain", "deduplicate"}:
            continue
        retained_root = next(root for root in roots if root["disposition"] == "retain")
        retained_symbol = retained_root["root_cause_id"].partition(":")[2]
        replay = release_fixtures.load_release_fixture_replay(case)
        priorities = {
            proposal["affected_code_path"]["symbol_name"].lower(): risk_priority[
                proposal["risk_estimate"]
            ]
            for proposal in replay["proposals"]
        }

        assert priorities[retained_symbol] > max(
            priority
            for symbol, priority in priorities.items()
            if symbol != retained_symbol
        ), case.case_id


def test_typescript_replay_loader_returns_parsed_response_object():
    case = load_release_fixture_suite(
        TYPESCRIPT_FIXTURE_ROOT,
        "development",
    )[0]
    loader = getattr(release_fixtures, "load_release_fixture_replay", None)

    assert callable(loader)
    assert loader(case) == json.loads(
        (case.root / "replay" / "response.json").read_text(encoding="utf-8")
    )


def test_typescript_replay_loader_rejects_extra_file(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    _write_json(case.root / "replay" / "extra.json", {"unexpected": True})

    with pytest.raises(
        ReleaseFixtureError,
        match="tse-001:replay:unexpected_files",
    ):
        release_fixtures.load_release_fixture_replay(case)


def test_typescript_suite_preflight_validates_inputs_and_replay_without_gold():
    cases = load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development")
    preflight = getattr(
        release_fixtures,
        "preflight_release_fixture_suite",
        None,
    )

    assert callable(preflight)
    assert preflight(cases) is None


def test_typescript_replay_payloads_have_no_oracle_or_permission_fields():
    cases = (
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "release"),
    )
    forbidden_keys = {
        "expecteddisposition",
        "expectedroots",
        "goldid",
        "disposition",
        "duplicateof",
        "executionallowed",
        "dispatchallowed",
        "validationallowed",
        "candidatepromotionallowed",
        "reportsubmissionallowed",
    }

    def keys(value: object) -> set[str]:
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value), set())
        if not isinstance(value, dict):
            return set()
        normalized = {
            "".join(character for character in str(key).lower() if character.isalnum())
            for key in value
        }
        return normalized | set().union(*(keys(item) for item in value.values()), set())

    for case in cases:
        payload = release_fixtures.load_release_fixture_replay(case)
        assert keys(payload).isdisjoint(forbidden_keys)


def test_typescript_replay_loader_rejects_missing_or_wrongly_named_response(
    tmp_path: Path,
):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    (case.root / "replay" / "response.json").rename(
        case.root / "replay" / "payload.json"
    )

    with pytest.raises(ReleaseFixtureError, match="tse-001:replay_missing"):
        release_fixtures.load_release_fixture_replay(case)


def test_typescript_replay_loader_rejects_invalid_json(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    (case.root / "replay" / "response.json").write_text(
        "not-json",
        encoding="utf-8",
    )

    with pytest.raises(ReleaseFixtureError, match="tse-001:replay:invalid_json"):
        release_fixtures.load_release_fixture_replay(case)


def test_typescript_replay_loader_rejects_unsafe_text(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    response_path = case.root / "replay" / "response.json"
    payload = json.loads(response_path.read_text(encoding="utf-8"))
    payload["proposals"][0]["impact_rationale"] = (
        "Authorization: Bearer synthetic-placeholder"
    )
    _write_json(response_path, payload)

    with pytest.raises(ReleaseFixtureError, match="secret_shaped_text"):
        release_fixtures.load_release_fixture_replay(case)


def test_typescript_replay_loader_rejects_path_escape(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    response_path = case.root / "replay" / "response.json"
    outside_path = tmp_path / "outside-response.json"
    _write_json(outside_path, {"schema_version": "outside", "proposals": []})
    response_path.unlink()
    try:
        response_path.symlink_to(outside_path)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ReleaseFixtureError, match="path_escape"):
        release_fixtures.load_release_fixture_replay(case)


def test_typescript_suite_preflight_never_loads_gold(monkeypatch):
    cases = load_release_fixture_suite(TYPESCRIPT_FIXTURE_ROOT, "development")
    gold_calls = []

    def fail_if_called(case):
        gold_calls.append(case.case_id)
        raise AssertionError("gold must remain closed during preflight")

    monkeypatch.setattr(release_fixtures, "load_release_fixture_gold", fail_if_called)

    release_fixtures.preflight_release_fixture_suite(cases)

    assert gold_calls == []


def test_typescript_suite_preflight_only_reads_requested_suite(tmp_path: Path):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    development = load_release_fixture_suite(fixture_root, "development")
    release = load_release_fixture_suite(fixture_root, "release")
    for case in release:
        (case.root / "replay" / "response.json").unlink()

    assert release_fixtures.preflight_release_fixture_suite(development) is None


def test_invalid_replay_schema_fails_in_real_reasoner_not_fixture_loader(
    tmp_path: Path,
):
    fixture_root = tmp_path / "candidate_hunter_typescript_release"
    shutil.copytree(TYPESCRIPT_FIXTURE_ROOT, fixture_root)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    response_path = case.root / "replay" / "response.json"
    payload = json.loads(response_path.read_text(encoding="utf-8"))
    payload["schema_version"] = "cross_source_candidate_model_unknown"
    _write_json(response_path, payload)
    loaded = release_fixtures.load_release_fixture_replay(case)
    fact_pack = build_fact_pack(
        pipeline_run_id="run-invalid-replay",
        scope_status="in_scope",
        source_files=[],
        facts=[],
        baseline_candidates=[],
    )

    result = asyncio.run(
        ReplayCandidateReasoner(loaded).generate(
            fact_pack=fact_pack,
            model_config=CandidateModelConfig(
                provider=ProviderName.OPENAI,
                model="fixture-replay-v1",
            ),
            request_key="invalid-replay",
        )
    )

    assert result.status == "invalid_schema"
