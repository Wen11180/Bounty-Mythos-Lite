from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXPECTED_CASE_COUNT = 24
SUITES = {"development", "release"}
LEGACY_PROFILE = "candidate_hunter_release_legacy"
LEGACY_VERSION = "candidate_hunter_release_fixture_v1"
TYPESCRIPT_PROFILE = "candidate_hunter_typescript_express"
TYPESCRIPT_VERSION = "candidate_hunter_typescript_express_fixture_v1"
TYPESCRIPT_V2_PROFILE = "candidate_hunter_typescript_express_v2"
TYPESCRIPT_V2_VERSION = "candidate_hunter_typescript_express_fixture_v2"
TYPESCRIPT_VERSIONS = {
    TYPESCRIPT_PROFILE: TYPESCRIPT_VERSION,
    TYPESCRIPT_V2_PROFILE: TYPESCRIPT_V2_VERSION,
}
AUTHORIZATION_PATTERNS = {"object_ownership", "tenant_boundary", "role_boundary"}
TYPESCRIPT_ORACLE_FIELDS = {
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
}
RISK_FAMILIES = {
    "authorization",
    "authentication",
    "configuration",
    "data_exposure",
    "injection",
    "workflow",
}
DISPOSITIONS = {"retain", "refute", "deduplicate", "suppress"}
INPUT_KINDS = {"scope", "policy", "api", "har", "code"}
TYPESCRIPT_GOLD_OUTCOMES = {
    TYPESCRIPT_PROFILE: {
        pattern: frozenset(DISPOSITIONS) for pattern in AUTHORIZATION_PATTERNS
    },
    TYPESCRIPT_V2_PROFILE: {
        "object_ownership": frozenset(DISPOSITIONS),
        "tenant_boundary": frozenset(DISPOSITIONS),
        "role_boundary": frozenset({"retain", "deduplicate", "suppress"}),
    },
}


class ReleaseFixtureError(ValueError):
    pass


def _is_typescript_profile(profile: str) -> bool:
    return profile in TYPESCRIPT_VERSIONS


@dataclass(frozen=True)
class ReleaseFixtureInput:
    kind: str
    path: Path
    text: str


@dataclass(frozen=True)
class ReleaseFixtureCase:
    case_id: str
    suite: str
    risk_family: str | None
    expected_disposition: str | None
    root: Path
    metadata: dict[str, Any]
    input_specs: tuple[tuple[str, str], ...]
    profile: str = LEGACY_PROFILE
    authorization_pattern: str | None = None


def load_release_fixture_suite(
    fixture_root: Path,
    suite: str,
) -> tuple[ReleaseFixtureCase, ...]:
    if suite not in SUITES:
        raise ReleaseFixtureError("suite:unsupported")
    root = Path(fixture_root).resolve()
    if not root.is_dir():
        raise ReleaseFixtureError("fixture_root:missing")

    manifest_path = _resolve_under(root, "suite-manifest.json")
    manifest_text = _read_text(manifest_path, "suite_manifest")
    if reason := _fixture_text_violation(manifest_text):
        raise ReleaseFixtureError(f"suite_manifest:{reason}")
    manifest = _parse_json_text(manifest_text, "suite_manifest")
    profile = manifest.get("profile")
    if profile is not None and not isinstance(profile, str):
        raise ReleaseFixtureError("suite_manifest:unsupported_profile")
    if profile not in {None, *TYPESCRIPT_VERSIONS}:
        raise ReleaseFixtureError("suite_manifest:unsupported_profile")
    if (
        profile is None
        and manifest.get("version") in TYPESCRIPT_VERSIONS.values()
    ):
        raise ReleaseFixtureError("suite_manifest:unsupported_profile")
    if isinstance(profile, str) and _is_typescript_profile(profile):
        if manifest.get("version") != TYPESCRIPT_VERSIONS[profile]:
            raise ReleaseFixtureError("suite_manifest:unsupported_version")
        entries = _typescript_manifest_entries(manifest)
        _validate_typescript_manifest(entries)
        cases = tuple(
            _load_typescript_case(root, entry, profile=profile)
            for entry in entries
            if entry["suite"] == suite
        )
        return tuple(sorted(cases, key=lambda case: case.case_id))
    if manifest.get("version") != LEGACY_VERSION:
        raise ReleaseFixtureError("suite_manifest:unsupported_version")
    entries = _manifest_entries(manifest)
    _validate_manifest(entries)
    cases = tuple(_load_case(root, entry) for entry in entries)
    return tuple(sorted(
        (case for case in cases if case.suite == suite),
        key=lambda case: case.case_id,
    ))




def _is_optional_advisory_input(path: Path, inputs_root: Path) -> bool:
    """Allow offline advisory/residual files under inputs without manifest declaration.

    Advisory JSON and residual checklist files are optional multi-engine / human-gate
    inputs, not required release kinds.
    """
    try:
        rel = path.resolve().relative_to(inputs_root.resolve())
    except ValueError:
        return False
    parts = rel.parts
    if not parts:
        return False
    if parts[0] == "advisory" and path.suffix.lower() == ".json":
        return True
    if len(parts) == 1 and parts[0].lower() == "advisory.json":
        return True
    # residual checklist auto-ingest (JSON / Markdown)
    if parts[0] == "residual" and path.suffix.lower() in {".json", ".md"}:
        return True
    if len(parts) == 1 and parts[0].lower() in {
        "residual.json",
        "residual_checklist.json",
        "residual_checklist.md",
    }:
        return True
    # durable offline residual/patch human review approvals (context only)
    if parts[0] == "approvals" and path.suffix.lower() == ".json":
        return True
    if len(parts) == 1 and parts[0].lower() in {
        "human_review_approvals.json",
        "approvals.json",
    }:
        return True
    return False

def stage_release_fixture_inputs(
    case: ReleaseFixtureCase,
) -> tuple[ReleaseFixtureInput, ...]:
    _validate_case_metadata(case.metadata, case.case_id)
    inputs_root = _resolve_under(case.root, "inputs")
    if not inputs_root.is_dir():
        raise ReleaseFixtureError(f"{case.case_id}:inputs_missing")

    declared_paths: set[Path] = set()
    staged_inputs: list[ReleaseFixtureInput] = []
    for kind, relative_path in case.input_specs:
        path = _resolve_under(case.root, relative_path)
        if not path.is_file():
            raise ReleaseFixtureError(f"{case.case_id}:{kind}:input_missing")
        if not _is_under(path, inputs_root):
            raise ReleaseFixtureError(f"{case.case_id}:{kind}:input_outside_inputs")
        declared_paths.add(path)
        text = _read_text(path, f"{case.case_id}:{kind}")
        if reason := _fixture_text_violation(text):
            raise ReleaseFixtureError(f"{case.case_id}:{kind}:{reason}")
        if _is_typescript_profile(case.profile):
            if reason := _typescript_oracle_violation(text):
                raise ReleaseFixtureError(f"{case.case_id}:{kind}:{reason}")
        staged_inputs.append(ReleaseFixtureInput(kind=kind, path=path, text=text))

    actual_paths = {
        path.resolve()
        for path in inputs_root.rglob("*")
        if path.is_file() and not _is_optional_advisory_input(path, inputs_root)
    }
    if actual_paths != declared_paths:
        raise ReleaseFixtureError(f"{case.case_id}:undeclared_input_file")
    return tuple(staged_inputs)


def load_release_fixture_gold(case: ReleaseFixtureCase) -> dict[str, Any]:
    gold_path = _resolve_under(case.root, "gold.json")
    if not gold_path.is_file():
        raise ReleaseFixtureError(f"{case.case_id}:gold_missing")
    text = _read_text(gold_path, f"{case.case_id}:gold")
    if reason := _fixture_text_violation(text):
        raise ReleaseFixtureError(f"{case.case_id}:gold:{reason}")
    gold = _parse_json_text(text, f"{case.case_id}:gold")
    if _is_typescript_profile(case.profile) and set(gold) != {
        "authorization_pattern",
        "expected_roots",
    }:
        raise ReleaseFixtureError(f"{case.case_id}:gold:unexpected_keys")
    if (
        _is_typescript_profile(case.profile)
        and gold.get("authorization_pattern") != case.authorization_pattern
    ):
        raise ReleaseFixtureError(
            f"{case.case_id}:gold:authorization_pattern_mismatch"
        )
    if not isinstance(gold.get("expected_roots"), list):
        raise ReleaseFixtureError(f"{case.case_id}:gold:expected_roots_missing")
    if _is_typescript_profile(case.profile):
        if not gold["expected_roots"]:
            raise ReleaseFixtureError(f"{case.case_id}:gold:expected_roots_empty")
        for index, root in enumerate(gold["expected_roots"]):
            label = f"{case.case_id}:gold:expected_roots[{index}]"
            if not isinstance(root, dict):
                raise ReleaseFixtureError(f"{label}:must_be_object")
            if set(root) != {
                "gold_id",
                "root_cause_id",
                "route",
                "vuln_type",
                "disposition",
                "worth_validation",
                "required_evidence_refs",
                "decisive_refutation_refs",
                "duplicate_of",
                "scope_allowed",
            }:
                raise ReleaseFixtureError(f"{label}:unexpected_keys")
            for field in ("gold_id", "root_cause_id", "vuln_type"):
                if not isinstance(root.get(field), str) or not root[field].strip():
                    raise ReleaseFixtureError(f"{label}:{field}_required")
            route = root.get("route")
            if not isinstance(route, dict):
                raise ReleaseFixtureError(f"{label}:route_must_be_object")
            for field in ("method", "path"):
                if not isinstance(route.get(field), str) or not route[field].strip():
                    raise ReleaseFixtureError(f"{label}:route_{field}_required")
            if set(route) != {"method", "path"}:
                raise ReleaseFixtureError(f"{label}:route_unexpected_keys")
            disposition = root.get("disposition")
            if disposition not in DISPOSITIONS:
                raise ReleaseFixtureError(f"{label}:unsupported_disposition")
            if not isinstance(root.get("worth_validation"), bool):
                raise ReleaseFixtureError(
                    f"{label}:worth_validation_must_be_boolean"
                )
            for field in (
                "required_evidence_refs",
                "decisive_refutation_refs",
            ):
                value = root.get(field)
                if not isinstance(value, list) or any(
                    not isinstance(item, str) or not item.strip()
                    for item in value
                ):
                    raise ReleaseFixtureError(
                        f"{label}:{field}_must_be_string_list"
                    )
            if (
                disposition == "refute"
                and not root["decisive_refutation_refs"]
            ):
                raise ReleaseFixtureError(
                    f"{label}:refutation_evidence_required"
                )
            duplicate_of = root.get("duplicate_of")
            if disposition == "deduplicate":
                if not isinstance(duplicate_of, str) or not duplicate_of.strip():
                    raise ReleaseFixtureError(
                        f"{label}:duplicate_of_must_be_nonempty_string"
                    )
            elif duplicate_of is not None:
                raise ReleaseFixtureError(f"{label}:duplicate_of_must_be_null")
            if root.get("scope_allowed") is not True:
                raise ReleaseFixtureError(f"{label}:scope_allowed_must_be_true")
        for field in ("gold_id", "root_cause_id"):
            values = [root[field] for root in gold["expected_roots"]]
            if len(values) != len(set(values)):
                raise ReleaseFixtureError(
                    f"{case.case_id}:gold:duplicate_{field}"
                )
        roots_by_id = {
            root["root_cause_id"]: root for root in gold["expected_roots"]
        }
        for root in gold["expected_roots"]:
            if root["disposition"] != "deduplicate":
                continue
            target = roots_by_id.get(root["duplicate_of"])
            if target is None:
                raise ReleaseFixtureError(
                    f"{case.case_id}:gold:duplicate_target_unknown"
                )
            if target["disposition"] != "retain":
                raise ReleaseFixtureError(
                    f"{case.case_id}:gold:duplicate_target_must_retain"
                )
    return gold


def load_release_fixture_gold_suite(
    cases: tuple[ReleaseFixtureCase, ...],
) -> tuple[dict[str, Any], ...]:
    if cases and all(_is_typescript_profile(case.profile) for case in cases):
        if len(cases) != EXPECTED_CASE_COUNT // len(SUITES):
            raise ReleaseFixtureError("gold_suite:case_count")
        if len({case.suite for case in cases}) != 1:
            raise ReleaseFixtureError("gold_suite:suite_mismatch")
    gold_suite = tuple(load_release_fixture_gold(case) for case in cases)
    if not cases or not all(_is_typescript_profile(case.profile) for case in cases):
        return gold_suite
    profiles = {case.profile for case in cases}
    if len(profiles) != 1:
        raise ReleaseFixtureError("gold_suite:profile_mismatch")
    profile = profiles.pop()
    suite = cases[0].suite
    for pattern in AUTHORIZATION_PATTERNS:
        outcomes = {
            _typescript_gold_outcome(gold)
            for case, gold in zip(cases, gold_suite, strict=True)
            if case.authorization_pattern == pattern
        }
        if outcomes != TYPESCRIPT_GOLD_OUTCOMES[profile][pattern]:
            raise ReleaseFixtureError(
                f"gold_suite:{suite}:{pattern}:outcome_matrix"
            )
    return gold_suite


def load_release_fixture_replay(case: ReleaseFixtureCase) -> dict[str, Any]:
    if not _is_typescript_profile(case.profile):
        raise ReleaseFixtureError(f"{case.case_id}:replay:unsupported_profile")
    replay_path = _resolve_under(case.root, "replay/response.json")
    if not replay_path.is_file():
        raise ReleaseFixtureError(f"{case.case_id}:replay_missing")
    replay_root = _resolve_under(case.root, "replay")
    actual_files = {
        path.relative_to(replay_root).as_posix()
        for path in replay_root.rglob("*")
        if path.is_file()
    }
    if actual_files != {"response.json"}:
        raise ReleaseFixtureError(f"{case.case_id}:replay:unexpected_files")
    text = _read_text(replay_path, f"{case.case_id}:replay")
    if reason := _fixture_text_violation(text):
        raise ReleaseFixtureError(f"{case.case_id}:replay:{reason}")
    return _parse_json_text(text, f"{case.case_id}:replay")


def preflight_release_fixture_suite(
    cases: tuple[ReleaseFixtureCase, ...],
) -> None:
    for case in cases:
        stage_release_fixture_inputs(case)
        load_release_fixture_replay(case)


def _typescript_gold_outcome(gold: dict[str, Any]) -> str:
    dispositions = [root["disposition"] for root in gold["expected_roots"]]
    if dispositions.count("retain") == 1 and dispositions.count("deduplicate") == 1:
        return "deduplicate"
    if len(dispositions) == 1:
        return dispositions[0]
    return "invalid"


def _manifest_entries(manifest: Any) -> list[dict[str, str]]:
    if not isinstance(manifest, dict) or not isinstance(manifest.get("cases"), list):
        raise ReleaseFixtureError("suite_manifest:cases_missing")
    if set(manifest) != {"version", "capability_level", "cases"}:
        raise ReleaseFixtureError("suite_manifest:unexpected_keys")
    if manifest.get("capability_level") != "lab":
        raise ReleaseFixtureError("suite_manifest:capability_level_must_be_lab")
    entries: list[dict[str, str]] = []
    for index, value in enumerate(manifest["cases"]):
        if not isinstance(value, dict):
            raise ReleaseFixtureError(f"suite_manifest.cases[{index}]:must_be_object")
        entry = {
            field: _required_text(value.get(field), f"suite_manifest.cases[{index}].{field}")
            for field in ("case_id", "suite", "risk_family", "expected_disposition", "path")
        }
        entries.append(entry)
    return entries


def _typescript_manifest_entries(manifest: Any) -> list[dict[str, str]]:
    if not isinstance(manifest, dict) or not isinstance(manifest.get("cases"), list):
        raise ReleaseFixtureError("suite_manifest:cases_missing")
    if set(manifest) != {"profile", "version", "capability_level", "cases"}:
        raise ReleaseFixtureError("suite_manifest:unexpected_keys")
    if manifest.get("capability_level") != "lab":
        raise ReleaseFixtureError("suite_manifest:capability_level_must_be_lab")
    entries: list[dict[str, str]] = []
    for index, value in enumerate(manifest["cases"]):
        if not isinstance(value, dict):
            raise ReleaseFixtureError(f"suite_manifest.cases[{index}]:must_be_object")
        fields = ("case_id", "suite", "authorization_pattern", "path")
        if set(value) != set(fields):
            raise ReleaseFixtureError(
                f"suite_manifest.cases[{index}]:unexpected_keys"
            )
        entries.append(
            {
                field: _required_text(
                    value.get(field),
                    f"suite_manifest.cases[{index}].{field}",
                )
                for field in fields
            }
        )
    return entries


def _validate_manifest_identity(entries: list[dict[str, str]]) -> None:
    if len(entries) != EXPECTED_CASE_COUNT:
        raise ReleaseFixtureError("suite_manifest:case_count")
    case_ids = [entry["case_id"] for entry in entries]
    paths = [entry["path"] for entry in entries]
    if len(case_ids) != len(set(case_ids)):
        raise ReleaseFixtureError("suite_manifest:duplicate_case_id")
    if len(paths) != len(set(paths)):
        raise ReleaseFixtureError("suite_manifest:duplicate_path")
    if any(entry["suite"] not in SUITES for entry in entries):
        raise ReleaseFixtureError("suite_manifest:unsupported_suite")


def _validate_manifest(entries: list[dict[str, str]]) -> None:
    _validate_manifest_identity(entries)
    if any(entry["risk_family"] not in RISK_FAMILIES for entry in entries):
        raise ReleaseFixtureError("suite_manifest:unsupported_risk_family")
    if any(entry["expected_disposition"] not in DISPOSITIONS for entry in entries):
        raise ReleaseFixtureError("suite_manifest:unsupported_disposition")
    if {entry["risk_family"] for entry in entries} != RISK_FAMILIES:
        raise ReleaseFixtureError("suite_manifest:risk_families_incomplete")
    for suite in SUITES:
        suite_entries = [entry for entry in entries if entry["suite"] == suite]
        if len(suite_entries) != EXPECTED_CASE_COUNT // len(SUITES):
            raise ReleaseFixtureError(f"suite_manifest:{suite}:case_count")
        if len({entry["risk_family"] for entry in suite_entries}) != len(RISK_FAMILIES) // len(
            SUITES
        ):
            raise ReleaseFixtureError(f"suite_manifest:{suite}:risk_family_count")
        if {entry["expected_disposition"] for entry in suite_entries} != DISPOSITIONS:
            raise ReleaseFixtureError(f"suite_manifest:{suite}:dispositions_incomplete")
        for risk_family in {entry["risk_family"] for entry in suite_entries}:
            family_entries = [
                entry for entry in suite_entries if entry["risk_family"] == risk_family
            ]
            if (
                len(family_entries) != len(DISPOSITIONS)
                or {entry["expected_disposition"] for entry in family_entries}
                != DISPOSITIONS
            ):
                raise ReleaseFixtureError(
                    f"suite_manifest:{suite}:{risk_family}:dispositions_incomplete"
                )


def _validate_typescript_manifest(entries: list[dict[str, str]]) -> None:
    _validate_manifest_identity(entries)
    if any(
        entry["authorization_pattern"] not in AUTHORIZATION_PATTERNS
        for entry in entries
    ):
        raise ReleaseFixtureError(
            "suite_manifest:unsupported_authorization_pattern"
        )
    for suite in ("development", "release"):
        suite_entries = [entry for entry in entries if entry["suite"] == suite]
        if len(suite_entries) != EXPECTED_CASE_COUNT // len(SUITES):
            raise ReleaseFixtureError(f"suite_manifest:{suite}:case_count")
        if any(
            sum(
                entry["authorization_pattern"] == pattern
                for entry in suite_entries
            )
            != 4
            for pattern in AUTHORIZATION_PATTERNS
        ):
            raise ReleaseFixtureError(
                f"suite_manifest:{suite}:authorization_pattern_count"
            )


def _load_case(root: Path, entry: dict[str, str]) -> ReleaseFixtureCase:
    case_root = _resolve_under(root, entry["path"])
    if not case_root.is_dir():
        raise ReleaseFixtureError(f"{entry['case_id']}:case_missing")
    metadata_path = _resolve_under(case_root, "case.json")
    metadata_text = _read_text(metadata_path, entry["case_id"])
    if reason := _fixture_text_violation(metadata_text):
        raise ReleaseFixtureError(f"{entry['case_id']}:case_metadata:{reason}")
    metadata = _parse_json_text(metadata_text, entry["case_id"])
    _validate_case_metadata(metadata, entry["case_id"])
    for field in ("case_id", "risk_family", "expected_disposition"):
        if _required_text(metadata.get(field), f"{entry['case_id']}.{field}") != entry[field]:
            raise ReleaseFixtureError(f"{entry['case_id']}:{field}_mismatch")
    input_specs = _input_specs(metadata, entry["case_id"])
    return ReleaseFixtureCase(
        case_id=entry["case_id"],
        suite=entry["suite"],
        risk_family=entry["risk_family"],
        expected_disposition=entry["expected_disposition"],
        root=case_root,
        metadata=metadata,
        input_specs=input_specs,
    )


def _load_typescript_case(
    root: Path,
    entry: dict[str, str],
    *,
    profile: str,
) -> ReleaseFixtureCase:
    case_root = _resolve_under(root, entry["path"])
    if not case_root.is_dir():
        raise ReleaseFixtureError(f"{entry['case_id']}:case_missing")
    metadata_path = _resolve_under(case_root, "case.json")
    metadata_text = _read_text(metadata_path, entry["case_id"])
    if reason := _fixture_text_violation(metadata_text):
        raise ReleaseFixtureError(f"{entry['case_id']}:case_metadata:{reason}")
    metadata = _parse_json_text(metadata_text, entry["case_id"])
    _validate_typescript_case_metadata(metadata, entry["case_id"])
    if (
        _required_text(metadata.get("case_id"), f"{entry['case_id']}.case_id")
        != entry["case_id"]
    ):
        raise ReleaseFixtureError(f"{entry['case_id']}:case_id_mismatch")
    return ReleaseFixtureCase(
        case_id=entry["case_id"],
        suite=entry["suite"],
        risk_family=None,
        expected_disposition=None,
        root=case_root,
        metadata=metadata,
        input_specs=_input_specs(metadata, entry["case_id"]),
        profile=profile,
        authorization_pattern=entry["authorization_pattern"],
    )


def _validate_case_metadata(metadata: Any, case_id: str) -> None:
    if not isinstance(metadata, dict):
        raise ReleaseFixtureError(f"{case_id}:case_metadata_must_be_object")
    required_values = {
        "synthetic": True,
        "authorized_for_local_benchmark": True,
        "contains_real_user_data": False,
        "contains_secrets": False,
    }
    for field, expected in required_values.items():
        if metadata.get(field) is not expected:
            raise ReleaseFixtureError(f"{case_id}:{field}_must_be_{str(expected).lower()}")


def _validate_typescript_case_metadata(
    metadata: dict[str, Any],
    case_id: str,
) -> None:
    _validate_case_metadata(metadata, case_id)
    if set(metadata) != {
        "case_id",
        "synthetic",
        "authorized_for_local_benchmark",
        "contains_real_user_data",
        "contains_secrets",
        "inputs",
    }:
        raise ReleaseFixtureError(f"{case_id}:case_metadata:unexpected_keys")


def _input_specs(metadata: dict[str, Any], case_id: str) -> tuple[tuple[str, str], ...]:
    inputs = metadata.get("inputs")
    if not isinstance(inputs, list):
        raise ReleaseFixtureError(f"{case_id}:inputs_must_be_list")
    specs: list[tuple[str, str]] = []
    kinds: set[str] = set()
    paths: set[str] = set()
    for index, item in enumerate(inputs):
        if not isinstance(item, dict):
            raise ReleaseFixtureError(f"{case_id}:inputs[{index}]:must_be_object")
        kind = _required_text(item.get("kind"), f"{case_id}:inputs[{index}].kind")
        relative_path = _required_text(item.get("path"), f"{case_id}:inputs[{index}].path")
        if kind not in INPUT_KINDS:
            raise ReleaseFixtureError(f"{case_id}:unsupported_input_kind")
        if kind == "code" and Path(relative_path).suffix.lower() != ".ts":
            raise ReleaseFixtureError(f"{case_id}:typescript_code_required")
        if kind in kinds or relative_path in paths:
            raise ReleaseFixtureError(f"{case_id}:duplicate_input")
        if not relative_path.startswith("inputs/"):
            raise ReleaseFixtureError(f"{case_id}:input_outside_inputs")
        if Path(relative_path).name == "gold.json":
            raise ReleaseFixtureError(f"{case_id}:gold_must_be_outside_inputs")
        kinds.add(kind)
        paths.add(relative_path)
        specs.append((kind, relative_path))
    if kinds != INPUT_KINDS:
        raise ReleaseFixtureError(f"{case_id}:input_kinds_incomplete")
    return tuple(specs)


def _fixture_text_violation(text: str) -> str | None:
    lowered = text.lower()
    patterns = {
        "secret_shaped_text:authorization_bearer": (
            "authorization: bearer",
            "authorization=bearer",
            "bearer ",
        ),
        "secret_shaped_text:cookie": ("cookie:", "set-cookie:", "cookie="),
        "secret_shaped_text:token": (
            "access_token=",
            "access_token:",
            "refresh_token=",
            "refresh_token:",
            "token=",
            "token:",
        ),
        "secret_shaped_text:credential": (
            "password=",
            "password:",
            "client_secret=",
            "client_secret:",
            "api_key=",
            "api_key:",
            "apikey=",
            "apikey:",
        ),
        "real_user_data_marker": ("real user data",),
        "external_url": ("http://", "https://"),
    }
    for reason, matches in patterns.items():
        if any(match in lowered for match in matches):
            return reason
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return _structured_fixture_violation(parsed)


def _typescript_oracle_violation(text: str) -> str | None:
    lowered = text.lower()
    if any(
        re.search(rf"\b{re.escape(disposition)}\b", lowered)
        for disposition in DISPOSITIONS
    ):
        return "oracle_disposition"
    if any(
        re.search(rf"\b{re.escape(field)}\b", lowered)
        for field in TYPESCRIPT_ORACLE_FIELDS
    ):
        return "oracle_field"
    return None


def _structured_fixture_violation(value: Any) -> str | None:
    if isinstance(value, list):
        return next(
            (reason for item in value if (reason := _structured_fixture_violation(item))),
            None,
        )
    if not isinstance(value, dict):
        return None
    sensitive_keys = {
        "authorization",
        "authorizationheader",
        "cookie",
        "password",
        "apikey",
        "accesstoken",
        "refreshtoken",
        "clientsecret",
        "secret",
        "token",
        "credential",
        "credentials",
    }
    for key, item in value.items():
        normalized = "".join(character for character in str(key).lower() if character.isalnum())
        if normalized in {"containsrealuserdata", "realuserdata"} and item is not False:
            return "real_user_data_marker"
        if normalized in sensitive_keys and _has_value(item):
            return "secret_shaped_text:structured_value"
        if reason := _structured_fixture_violation(item):
            return reason
    return None


def _has_value(value: Any) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def _resolve_under(root: Path, relative_path: str) -> Path:
    candidate = (root / relative_path).resolve()
    if not _is_under(candidate, root):
        raise ReleaseFixtureError("path_escape")
    return candidate


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _required_text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReleaseFixtureError(f"{path}:required")
    return value.strip()


def _parse_json_text(text: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReleaseFixtureError(f"{label}:invalid_json") from exc
    if not isinstance(value, dict):
        raise ReleaseFixtureError(f"{label}:must_be_object")
    return value


def _read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseFixtureError(f"{label}:unreadable") from exc


__all__ = [
    "ReleaseFixtureCase",
    "ReleaseFixtureError",
    "ReleaseFixtureInput",
    "load_release_fixture_gold",
    "load_release_fixture_gold_suite",
    "load_release_fixture_replay",
    "load_release_fixture_suite",
    "preflight_release_fixture_suite",
    "stage_release_fixture_inputs",
]
