from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.intelligence_benchmark.authorized_lab_package import (
    AuthorizedLabPackageError,
    load_authorized_lab_package,
    stage_authorized_lab_package_inputs,
)


LAB_ROOT = (
    Path(__file__).parent
    / "fixtures"
    / "authorized_lab_packages"
    / "lab-authz-unguarded-notes"
)


def test_load_authorized_lab_package_smoke_shape():
    package = load_authorized_lab_package(LAB_ROOT)
    assert package.case_id == "lab-authz-unguarded-notes"
    assert package.suite == "lab"
    assert package.metadata["authorized_for_local_benchmark"] is True
    assert package.metadata["contains_real_user_data"] is False
    assert package.metadata["contains_secrets"] is False
    kinds = {kind for kind, _ in package.input_specs}
    assert kinds == {"scope", "policy", "api", "har", "code"}


def test_stage_authorized_lab_package_inputs_fail_closed():
    package = load_authorized_lab_package(LAB_ROOT)
    staged = stage_authorized_lab_package_inputs(package)
    assert {item.kind for item in staged} == {"scope", "policy", "api", "har", "code"}
    code = next(item for item in staged if item.kind == "code")
    assert code.path.suffix == ".ts"
    assert "read_note" in code.text


def test_authorized_lab_package_rejects_missing_authorization(tmp_path: Path):
    package_root = tmp_path / "bad-package"
    (package_root / "inputs").mkdir(parents=True)
    for name, body in {
        "scope.json": '{"allowed_repos":["${STAGED_CODE_ROOT}"],"local_only":true}',
        "policy.md": "lab only",
        "api.json": "{}",
        "traffic.har.json": '{"log":{"version":"1.2","entries":[]}}',
        "code.ts": 'import { Router } from "express";\n',
    }.items():
        (package_root / "inputs" / name).write_text(body, encoding="utf-8")
    (package_root / "package.json").write_text(
        json.dumps(
            {
                "package_id": "bad-package",
                "contains_real_user_data": False,
                "contains_secrets": False,
                "inputs": [
                    {"kind": "scope", "path": "inputs/scope.json"},
                    {"kind": "policy", "path": "inputs/policy.md"},
                    {"kind": "api", "path": "inputs/api.json"},
                    {"kind": "har", "path": "inputs/traffic.har.json"},
                    {"kind": "code", "path": "inputs/code.ts"},
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(AuthorizedLabPackageError, match="authorized_for_local"):
        load_authorized_lab_package(package_root)


def test_authorized_lab_package_rejects_real_user_data_flag(tmp_path: Path):
    package_root = tmp_path / "bad-user-data"
    (package_root / "inputs").mkdir(parents=True)
    for name, body in {
        "scope.json": '{"allowed_repos":["${STAGED_CODE_ROOT}"],"local_only":true}',
        "policy.md": "lab only",
        "api.json": "{}",
        "traffic.har.json": '{"log":{"version":"1.2","entries":[]}}',
        "code.ts": 'import { Router } from "express";\n',
    }.items():
        (package_root / "inputs" / name).write_text(body, encoding="utf-8")
    (package_root / "package.json").write_text(
        json.dumps(
            {
                "package_id": "bad-user-data",
                "authorized_for_local_research": True,
                "contains_real_user_data": True,
                "contains_secrets": False,
                "inputs": [
                    {"kind": "scope", "path": "inputs/scope.json"},
                    {"kind": "policy", "path": "inputs/policy.md"},
                    {"kind": "api", "path": "inputs/api.json"},
                    {"kind": "har", "path": "inputs/traffic.har.json"},
                    {"kind": "code", "path": "inputs/code.ts"},
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(AuthorizedLabPackageError, match="contains_real_user_data"):
        load_authorized_lab_package(package_root)


EDU_LAB_ROOT = (
    Path(__file__).parent
    / "fixtures"
    / "authorized_lab_packages"
    / "lab-owasp-bola-invoice-export"
)


def test_load_educational_bola_lab_package_shape():
    package = load_authorized_lab_package(EDU_LAB_ROOT)
    assert package.case_id == "lab-owasp-bola-invoice-export"
    assert package.suite == "lab"
    assert package.expected_disposition == "retain"
    assert package.metadata["authorized_for_local_research"] is True
    staged = stage_authorized_lab_package_inputs(package)
    code = next(item for item in staged if item.kind == "code")
    assert "export_invoice" in code.text
    assert "export_file" in code.text
