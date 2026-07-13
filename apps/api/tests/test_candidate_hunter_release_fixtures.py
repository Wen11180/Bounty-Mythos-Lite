from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from app.codebase_map import map_authorized_code_files
from app.intelligence_benchmark.release_fixtures import (
    ReleaseFixtureError,
    load_release_fixture_gold,
    load_release_fixture_suite,
    stage_release_fixture_inputs,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "candidate_hunter_release"


def _copied_fixture_root(tmp_path: Path) -> Path:
    fixture_root = tmp_path / "candidate_hunter_release"
    shutil.copytree(FIXTURE_ROOT, fixture_root)
    return fixture_root


def _manifest_entry(fixture_root: Path, case_id: str) -> dict:
    manifest = json.loads((fixture_root / "suite-manifest.json").read_text())
    return next(entry for entry in manifest["cases"] if entry["case_id"] == case_id)


def test_fixture_manifest_defines_complete_balanced_corpus():
    development_cases = load_release_fixture_suite(FIXTURE_ROOT, "development")
    release_cases = load_release_fixture_suite(FIXTURE_ROOT, "release")

    assert len(development_cases) == 12
    assert len(release_cases) == 12
    assert {case.case_id for case in development_cases}.isdisjoint(
        case.case_id for case in release_cases
    )
    assert {case.expected_disposition for case in development_cases} == {
        "retain",
        "refute",
        "deduplicate",
        "suppress",
    }
    assert {case.expected_disposition for case in release_cases} == {
        "retain",
        "refute",
        "deduplicate",
        "suppress",
    }
    assert {case.risk_family for case in development_cases + release_cases} == {
        "authorization",
        "authentication",
        "configuration",
        "data_exposure",
        "injection",
        "workflow",
    }


def test_release_corpus_uses_opaque_typescript_express_inputs():
    cases = (
        *load_release_fixture_suite(FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(FIXTURE_ROOT, "release"),
    )

    for case in cases:
        code_input = next(
            item for item in stage_release_fixture_inputs(case) if item.kind == "code"
        )
        assert code_input.path.suffix == ".ts"
        assert 'from "express"' in code_input.text


def test_refute_fixtures_cover_distinct_typescript_authorization_controls():
    cases = (
        *load_release_fixture_suite(FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(FIXTURE_ROOT, "release"),
    )
    authz_symbols = set()

    for case in cases:
        if case.expected_disposition != "refute":
            continue
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
        authz_symbols.update(
            fact.symbol_name
            for fact in result.facts
            if fact.fact_type == "authz_check" and fact.symbol_name
        )

    assert {"owner_id_filter", "role_check", "tenant_id_filter"} <= authz_symbols


def test_fixture_loader_requires_typescript_code_input(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    entry = _manifest_entry(fixture_root, "dev-001")
    case_root = fixture_root / entry["path"]
    code_path = case_root / "inputs" / "code.ts"
    javascript_path = case_root / "inputs" / "code.js"
    code_path.rename(javascript_path)
    case_path = case_root / "case.json"
    case = json.loads(case_path.read_text())
    for item in case["inputs"]:
        if item["kind"] == "code":
            item["path"] = "inputs/code.js"
    case_path.write_text(json.dumps(case))

    with pytest.raises(ReleaseFixtureError, match="typescript_code_required"):
        load_release_fixture_suite(fixture_root, "development")


def test_staged_inputs_do_not_reveal_expected_dispositions():
    cases = (
        *load_release_fixture_suite(FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(FIXTURE_ROOT, "release"),
    )
    disposition_pattern = re.compile(
        r"(?<![a-z])(?:retain|refute|deduplicate|suppress)(?![a-z])",
        re.IGNORECASE,
    )

    leaks = []
    for case in cases:
        for staged_input in stage_release_fixture_inputs(case):
            relative_path = staged_input.path.relative_to(FIXTURE_ROOT).as_posix()
            for location, value in (
                (f"{case.case_id}:path", relative_path),
                (f"{case.case_id}:{staged_input.kind}", staged_input.text),
            ):
                if disposition_pattern.search(value):
                    leaks.append(location)

    assert leaks == []


def test_staged_inputs_do_not_embed_case_identity():
    cases = (
        *load_release_fixture_suite(FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(FIXTURE_ROOT, "release"),
    )

    leaks = []
    for case in cases:
        identity_variants = {
            case.case_id.lower(),
            case.case_id.lower().replace("-", "_"),
            case.case_id.lower().replace("-", ""),
        }
        for staged_input in stage_release_fixture_inputs(case):
            relative_path = staged_input.path.relative_to(FIXTURE_ROOT).as_posix()
            for location, value in (
                (f"{case.case_id}:path", relative_path),
                (f"{case.case_id}:{staged_input.kind}", staged_input.text),
            ):
                lowered = value.lower()
                if any(identity in lowered for identity in identity_variants):
                    leaks.append(location)

    assert leaks == []


def test_staged_scenario_tokens_are_opaque_and_not_case_ordinals():
    cases = (
        *load_release_fixture_suite(FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(FIXTURE_ROOT, "release"),
    )
    scenario_tokens = []

    for case in cases:
        staged_inputs = {
            item.kind: item for item in stage_release_fixture_inputs(case)
        }
        scope = json.loads(staged_inputs["scope"].text)
        scenario_token = scope["fixture_id"].removeprefix("fixture-")
        case_ordinal = case.root.name.removeprefix("case-")
        staged_text = "\n".join(item.text for item in staged_inputs.values())

        assert re.fullmatch(r"[a-z]\d[a-z]\d", scenario_token)
        assert scenario_token != f"c{case_ordinal}"
        assert f"c{case_ordinal}" not in staged_text.lower()
        scenario_tokens.append(scenario_token)

    assert len(scenario_tokens) == len(set(scenario_tokens))


def test_case_ids_and_directories_are_opaque():
    cases = (
        *load_release_fixture_suite(FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(FIXTURE_ROOT, "release"),
    )
    semantic_labels = {
        "development",
        "release",
        "authorization",
        "authentication",
        "configuration",
        "data_exposure",
        "injection",
        "workflow",
        "retain",
        "refute",
        "deduplicate",
        "suppress",
    }

    for case in cases:
        expected_prefix = "dev" if case.suite == "development" else "rel"
        assert re.fullmatch(rf"{expected_prefix}-\d{{3}}", case.case_id)
        assert re.fullmatch(
            r"cases/case-\d{3}",
            case.root.relative_to(FIXTURE_ROOT).as_posix(),
        )
        identity_text = f"{case.case_id}/{case.root.name}".lower()
        assert not any(label in identity_text for label in semantic_labels)


def test_fixture_outcomes_are_distinguished_by_observed_semantics():
    cases = (
        *load_release_fixture_suite(FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(FIXTURE_ROOT, "release"),
    )

    for case in cases:
        staged_inputs = {
            item.kind: item for item in stage_release_fixture_inputs(case)
        }
        result = map_authorized_code_files(
            {
                "authorized_code_files": [
                    {
                        "path": staged_inputs["code"].path.name,
                        "content": staged_inputs["code"].text,
                    }
                ]
            }
        )
        fact_types = [fact.fact_type for fact in result.facts]
        routes = [
            fact for fact in result.facts if fact.fact_type == "route_handler"
        ]
        service_calls = [
            fact for fact in result.facts if fact.fact_type == "service_call"
        ]

        if case.expected_disposition == "retain":
            assert fact_types.count("authorization_gap_candidate") == 1
            assert "authz_check" not in fact_types
        elif case.expected_disposition == "refute":
            assert routes
            assert "sensitive_sink" in fact_types
            assert fact_types.count("authorization_gap_candidate") == 1
            assert any(
                fact.fact_type == "authz_check"
                and fact.authz_hint
                in {
                    "owner_or_admin_check",
                    "ownership_boundary_check",
                    "role_check",
                }
                for fact in result.facts
            )
        elif case.expected_disposition == "deduplicate":
            assert len(routes) == 2
            assert routes[0].route_path < routes[1].route_path
            assert len(
                {
                    fact.symbol_name
                    for fact in service_calls
                    if fact.payload.get("caller")
                    in {route.payload.get("handler") for route in routes}
                }
            ) == 1
            assert fact_types.count("authorization_gap_candidate") == 2
        else:
            assert routes
            assert fact_types.count("authorization_gap_candidate") == 1
            assert any(
                fact.fact_type == "authz_check"
                and fact.authz_hint == "public_filter"
                for fact in result.facts
            )


def test_risk_families_have_distinct_observed_code_signatures():
    cases = (
        *load_release_fixture_suite(FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(FIXTURE_ROOT, "release"),
    )
    signatures_by_family: dict[str, set[tuple[str, str, str]]] = {}

    for case in cases:
        code = next(
            item.text
            for item in stage_release_fixture_inputs(case)
            if item.kind == "code"
        )
        result = map_authorized_code_files(
            {
                "authorized_code_files": [
                    {
                        "path": next(
                            item.path.name
                            for item in stage_release_fixture_inputs(case)
                            if item.kind == "code"
                        ),
                        "content": code,
                    }
                ]
            }
        )
        primary_gap = next(
            fact
            for fact in result.facts
            if fact.fact_type == "authorization_gap_candidate"
            and "/summary" not in (fact.route_path or "")
        )
        route_resource = (primary_gap.route_path or "").split("/")[2]
        sink_symbol = primary_gap.payload["sink_symbols"][0]
        signatures_by_family.setdefault(case.risk_family, set()).add(
            (primary_gap.symbol_name or "", sink_symbol, route_resource)
        )

    assert all(len(signatures) == 1 for signatures in signatures_by_family.values())
    assert len({next(iter(values)) for values in signatures_by_family.values()}) == 6


def test_case_identity_and_manifest_order_do_not_change_staged_semantics(
    tmp_path: Path,
):
    fixture_root = _copied_fixture_root(tmp_path)

    def staged_semantics(root: Path) -> list[tuple[tuple[str, str, str], ...]]:
        cases = (
            *load_release_fixture_suite(root, "development"),
            *load_release_fixture_suite(root, "release"),
        )
        return [
            tuple(
                sorted(
                    (item.kind, item.path.name, item.text)
                    for item in stage_release_fixture_inputs(case)
                )
            )
            for case in cases
        ]

    baseline = staged_semantics(fixture_root)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    suite_numbers = {"development": 100, "release": 100}
    for entry in manifest["cases"]:
        suite = entry["suite"]
        suite_numbers[suite] += 1
        prefix = "dev" if suite == "development" else "rel"
        replacement_id = f"{prefix}-{suite_numbers[suite]:03d}"
        case_path = fixture_root / entry["path"] / "case.json"
        case = json.loads(case_path.read_text())
        case["case_id"] = replacement_id
        case_path.write_text(json.dumps(case))
        entry["case_id"] = replacement_id
    manifest["cases"].reverse()
    manifest_path.write_text(json.dumps(manifest))

    assert staged_semantics(fixture_root) == baseline


def test_gold_oracles_reference_only_observed_routes_and_fact_refs():
    cases = (
        *load_release_fixture_suite(FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(FIXTURE_ROOT, "release"),
    )

    for case in cases:
        staged_inputs = {
            item.kind: item for item in stage_release_fixture_inputs(case)
        }
        code_result = map_authorized_code_files(
            {
                "authorized_code_files": [
                    {
                        "path": staged_inputs["code"].path.name,
                        "content": staged_inputs["code"].text,
                    }
                ]
            }
        )
        observed_refs = {
            f"code:{fact.source_path}:{fact.symbol_name}"
            for fact in code_result.facts
            if fact.symbol_name
        }
        api = json.loads(staged_inputs["api"].text)
        observed_routes = set()
        for route_path, path_item in api["paths"].items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                route = (method.upper(), route_path)
                observed_routes.add(route)
                route_ref = f"api:{route[0]}:{route[1]}"
                observed_refs.add(route_ref)
                if "security" in operation:
                    security_state = (
                        "security_required" if operation["security"] else "public_access"
                    )
                    observed_refs.add(f"{route_ref}:{security_state}")

        gold = load_release_fixture_gold(case)
        for root in gold["expected_roots"]:
            route = root["route"]
            assert (route["method"], route["path"]) in observed_routes
            assert set(root["required_evidence_refs"]).issubset(observed_refs)
            assert set(root["decisive_refutation_refs"]).issubset(observed_refs)


def test_fixture_loader_stages_inputs_before_explicit_gold_load(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    (case.root / "gold.json").write_text(
        '{"expected_roots": [], "authorization": "Bearer synthetic-placeholder"}'
    )

    staged_inputs = stage_release_fixture_inputs(case)

    assert {item.kind for item in staged_inputs} == {"scope", "policy", "api", "har", "code"}
    with pytest.raises(ReleaseFixtureError, match="secret_shaped_text"):
        load_release_fixture_gold(case)


def test_fixture_loader_rejects_unsafe_metadata_before_staging_inputs(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    entry = _manifest_entry(fixture_root, "dev-001")
    case_path = fixture_root / entry["path"] / "case.json"
    case = json.loads(case_path.read_text())
    case["synthetic"] = False
    case_path.write_text(json.dumps(case))
    (fixture_root / entry["path"] / "inputs" / "policy.md").write_text(
        "Authorization: Bearer synthetic-placeholder"
    )

    with pytest.raises(ReleaseFixtureError, match="synthetic"):
        load_release_fixture_suite(fixture_root, "development")


def test_fixture_loader_rejects_secret_shaped_case_metadata(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    entry = _manifest_entry(fixture_root, "dev-001")
    case_path = fixture_root / entry["path"] / "case.json"
    case = json.loads(case_path.read_text())
    case["review_note"] = "Authorization: Bearer synthetic-placeholder"
    case_path.write_text(json.dumps(case))

    with pytest.raises(ReleaseFixtureError, match="secret_shaped_text"):
        load_release_fixture_suite(fixture_root, "development")


def test_fixture_loader_rejects_manifest_path_escape(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["cases"][0]["path"] = "../outside"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ReleaseFixtureError, match="path_escape"):
        load_release_fixture_suite(fixture_root, "development")


def test_fixture_loader_rejects_secret_shaped_manifest_text(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["review_note"] = "Authorization: Bearer synthetic-placeholder"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ReleaseFixtureError, match="secret_shaped_text"):
        load_release_fixture_suite(fixture_root, "development")


def test_fixture_loader_requires_three_risk_families_per_suite(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    entry = _manifest_entry(fixture_root, "dev-001")
    entry["risk_family"] = "authentication"
    case_path = fixture_root / entry["path"] / "case.json"
    case = json.loads(case_path.read_text())
    case["risk_family"] = "authentication"
    case_path.write_text(json.dumps(case))
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for manifest_entry in manifest["cases"]:
        if manifest_entry["case_id"] == entry["case_id"]:
            manifest_entry["risk_family"] = "authentication"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ReleaseFixtureError, match="development:risk_family_count"):
        load_release_fixture_suite(fixture_root, "development")


def test_fixture_loader_requires_each_family_to_cover_all_dispositions(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    entry = _manifest_entry(fixture_root, "dev-001")
    entry["expected_disposition"] = "refute"
    case_path = fixture_root / entry["path"] / "case.json"
    case = json.loads(case_path.read_text())
    case["expected_disposition"] = "refute"
    case_path.write_text(json.dumps(case))
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for manifest_entry in manifest["cases"]:
        if manifest_entry["case_id"] == entry["case_id"]:
            manifest_entry["expected_disposition"] = "refute"
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(
        ReleaseFixtureError,
        match="development:authorization:dispositions_incomplete",
    ):
        load_release_fixture_suite(fixture_root, "development")


def test_fixture_loader_uses_manifest_suite_instead_of_case_directory(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    manifest_path = fixture_root / "suite-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest["cases"]:
        if entry["suite"] == "development" and entry["risk_family"] == "authorization":
            entry["suite"] = "release"
        elif entry["suite"] == "release" and entry["risk_family"] == "authentication":
            entry["suite"] = "development"
    manifest_path.write_text(json.dumps(manifest))

    development_cases = load_release_fixture_suite(fixture_root, "development")

    assert "rel-001" in {
        case.case_id for case in development_cases
    }


def test_every_static_fixture_has_safe_staged_inputs_and_an_explicit_oracle():
    cases = (
        *load_release_fixture_suite(FIXTURE_ROOT, "development"),
        *load_release_fixture_suite(FIXTURE_ROOT, "release"),
    )

    for case in cases:
        assert len(stage_release_fixture_inputs(case)) == 5
        assert load_release_fixture_gold(case)["expected_roots"]


def test_fixture_loader_rejects_unsupported_input_kind(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    entry = _manifest_entry(fixture_root, "dev-001")
    case_path = fixture_root / entry["path"] / "case.json"
    case = json.loads(case_path.read_text())
    case["inputs"][0]["kind"] = "network"
    case_path.write_text(json.dumps(case))

    with pytest.raises(ReleaseFixtureError, match="unsupported_input_kind"):
        load_release_fixture_suite(fixture_root, "development")


def test_fixture_loader_rejects_gold_declared_as_an_input(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    entry = _manifest_entry(fixture_root, "dev-001")
    case_path = fixture_root / entry["path"] / "case.json"
    case = json.loads(case_path.read_text())
    case["inputs"][0]["path"] = "inputs/gold.json"
    case_path.write_text(json.dumps(case))

    with pytest.raises(ReleaseFixtureError, match="gold_must_be_outside_inputs"):
        load_release_fixture_suite(fixture_root, "development")


def test_fixture_loader_rejects_unsafe_staged_input_text(tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    (case.root / "inputs" / "policy.md").write_text(
        "Authorization: Bearer synthetic-placeholder"
    )

    with pytest.raises(ReleaseFixtureError, match="secret_shaped_text"):
        stage_release_fixture_inputs(case)


@pytest.mark.parametrize(
    "unsafe_text",
    [
        "Cookie: synthetic-session-placeholder",
        "token: synthetic-placeholder",
        "apiKey: synthetic-placeholder",
    ],
)
def test_fixture_loader_rejects_secret_shaped_plaintext(unsafe_text: str, tmp_path: Path):
    fixture_root = _copied_fixture_root(tmp_path)
    case = load_release_fixture_suite(fixture_root, "development")[0]
    (case.root / "inputs" / "policy.md").write_text(unsafe_text)

    with pytest.raises(ReleaseFixtureError, match="secret_shaped_text"):
        stage_release_fixture_inputs(case)
