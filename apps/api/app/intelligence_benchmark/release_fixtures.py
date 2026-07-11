from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXPECTED_CASE_COUNT = 24
SUITES = {"development", "release"}
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


class ReleaseFixtureError(ValueError):
    pass


@dataclass(frozen=True)
class ReleaseFixtureInput:
    kind: str
    path: Path
    text: str


@dataclass(frozen=True)
class ReleaseFixtureCase:
    case_id: str
    suite: str
    risk_family: str
    expected_disposition: str
    root: Path
    metadata: dict[str, Any]
    input_specs: tuple[tuple[str, str], ...]


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
    entries = _manifest_entries(manifest)
    _validate_manifest(entries)
    cases = tuple(_load_case(root, entry) for entry in entries)
    return tuple(sorted(
        (case for case in cases if case.suite == suite),
        key=lambda case: case.case_id,
    ))


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
        staged_inputs.append(ReleaseFixtureInput(kind=kind, path=path, text=text))

    actual_paths = {
        path.resolve()
        for path in inputs_root.rglob("*")
        if path.is_file()
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
    if not isinstance(gold.get("expected_roots"), list):
        raise ReleaseFixtureError(f"{case.case_id}:gold:expected_roots_missing")
    return gold


def _manifest_entries(manifest: Any) -> list[dict[str, str]]:
    if not isinstance(manifest, dict) or not isinstance(manifest.get("cases"), list):
        raise ReleaseFixtureError("suite_manifest:cases_missing")
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


def _validate_manifest(entries: list[dict[str, str]]) -> None:
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
    "load_release_fixture_suite",
    "stage_release_fixture_inputs",
]
