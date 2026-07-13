from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.intelligence_benchmark.release_fixtures import (
    INPUT_KINDS,
    ReleaseFixtureCase,
    ReleaseFixtureError,
    load_release_fixture_gold,
    stage_release_fixture_inputs,
)


class AuthorizedLabPackageError(ValueError):
    pass


PACKAGE_MANIFEST_NAMES = ("package.json", "case.json")


def load_authorized_lab_package(package_root: Path) -> ReleaseFixtureCase:
    """Load a user-authorized local research package outside the locked 24-case suite.

    Required package shape mirrors release fixtures:
      package.json|case.json
      inputs/{scope,policy,api,har,code}
    Gold is optional. Fail-closed safety flags are mandatory.
    """
    root = Path(package_root).resolve()
    if not root.is_dir():
        raise AuthorizedLabPackageError("package_root:missing")

    metadata = _read_manifest(root)
    package_id = _package_id(metadata)
    try:
        _validate_lab_metadata(metadata, package_id)
        input_specs = _input_specs(metadata, package_id)
    except ReleaseFixtureError as exc:
        raise AuthorizedLabPackageError(str(exc)) from exc

    risk_family = _optional_text(metadata.get("risk_family")) or "authorization"
    expected_disposition = (
        _optional_text(metadata.get("expected_disposition")) or "retain"
    )
    # Normalize flags so existing fixture staging/validation can reuse the package.
    metadata = {
        **metadata,
        "case_id": package_id,
        "synthetic": True,
        "authorized_for_local_benchmark": True,
        "contains_real_user_data": False,
        "contains_secrets": False,
        "inputs": [
            {"kind": kind, "path": relative_path}
            for kind, relative_path in input_specs
        ],
    }
    return ReleaseFixtureCase(
        case_id=package_id,
        suite="lab",
        risk_family=risk_family,
        expected_disposition=expected_disposition,
        root=root,
        metadata=metadata,
        input_specs=input_specs,
    )


def stage_authorized_lab_package_inputs(package: ReleaseFixtureCase):
    """Stage declared package inputs; reuses release fixture staging fail-closed rules."""
    try:
        return stage_release_fixture_inputs(package)
    except ReleaseFixtureError as exc:
        raise AuthorizedLabPackageError(str(exc)) from exc


def authorized_lab_package_has_gold(package: ReleaseFixtureCase) -> bool:
    return (package.root / "gold.json").is_file()


def load_authorized_lab_package_gold(package: ReleaseFixtureCase) -> dict[str, Any] | None:
    if not authorized_lab_package_has_gold(package):
        return None
    try:
        return load_release_fixture_gold(package)
    except ReleaseFixtureError as exc:
        raise AuthorizedLabPackageError(str(exc)) from exc


def _read_manifest(root: Path) -> dict[str, Any]:
    for name in PACKAGE_MANIFEST_NAMES:
        path = root / name
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorizedLabPackageError(f"package_manifest:unreadable:{name}") from exc
        if not isinstance(value, dict):
            raise AuthorizedLabPackageError("package_manifest:must_be_object")
        return value
    raise AuthorizedLabPackageError("package_manifest:missing")


def _package_id(metadata: dict[str, Any]) -> str:
    for field in ("package_id", "case_id"):
        value = metadata.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise AuthorizedLabPackageError("package_id:required")


def _validate_lab_metadata(metadata: dict[str, Any], package_id: str) -> None:
    if metadata.get("contains_real_user_data") is not False:
        raise AuthorizedLabPackageError(f"{package_id}:contains_real_user_data_must_be_false")
    if metadata.get("contains_secrets") is not False:
        raise AuthorizedLabPackageError(f"{package_id}:contains_secrets_must_be_false")
    authorized = metadata.get("authorized_for_local_research")
    if authorized is None:
        authorized = metadata.get("authorized_for_local_benchmark")
    if authorized is not True:
        raise AuthorizedLabPackageError(
            f"{package_id}:authorized_for_local_research_or_benchmark_required"
        )


def _input_specs(metadata: dict[str, Any], package_id: str) -> tuple[tuple[str, str], ...]:
    inputs = metadata.get("inputs")
    if not isinstance(inputs, list):
        raise AuthorizedLabPackageError(f"{package_id}:inputs_must_be_list")
    specs: list[tuple[str, str]] = []
    kinds: set[str] = set()
    paths: set[str] = set()
    for index, item in enumerate(inputs):
        if not isinstance(item, dict):
            raise AuthorizedLabPackageError(f"{package_id}:inputs[{index}]:must_be_object")
        kind = item.get("kind")
        relative_path = item.get("path")
        if not isinstance(kind, str) or not kind.strip():
            raise AuthorizedLabPackageError(f"{package_id}:inputs[{index}].kind:required")
        if not isinstance(relative_path, str) or not relative_path.strip():
            raise AuthorizedLabPackageError(f"{package_id}:inputs[{index}].path:required")
        kind = kind.strip()
        relative_path = relative_path.strip()
        if kind not in INPUT_KINDS:
            raise AuthorizedLabPackageError(f"{package_id}:unsupported_input_kind")
        if kind == "code" and Path(relative_path).suffix.lower() != ".ts":
            raise AuthorizedLabPackageError(f"{package_id}:typescript_code_required")
        if kind in kinds or relative_path in paths:
            raise AuthorizedLabPackageError(f"{package_id}:duplicate_input")
        if not relative_path.startswith("inputs/"):
            raise AuthorizedLabPackageError(f"{package_id}:input_outside_inputs")
        if Path(relative_path).name == "gold.json":
            raise AuthorizedLabPackageError(f"{package_id}:gold_must_be_outside_inputs")
        kinds.add(kind)
        paths.add(relative_path)
        specs.append((kind, relative_path))
    if kinds != INPUT_KINDS:
        raise AuthorizedLabPackageError(f"{package_id}:input_kinds_incomplete")
    return tuple(specs)


def _optional_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


__all__ = [
    "AuthorizedLabPackageError",
    "PACKAGE_MANIFEST_NAMES",
    "authorized_lab_package_has_gold",
    "load_authorized_lab_package",
    "load_authorized_lab_package_gold",
    "stage_authorized_lab_package_inputs",
]
