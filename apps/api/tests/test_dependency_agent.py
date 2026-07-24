from __future__ import annotations

from pathlib import Path
from shutil import copytree, ignore_patterns

import pytest

import app.dependency_agent as dependency_agent
from app.dependency_agent import (
    DependencyAgentError,
    STATUS_OK,
    STATUS_SKIPPED,
    attach_dependency_profile_to_bridge_result,
    build_dependency_input_manifest,
    build_dependency_profile,
    dependency_input_manifest_matches,
)
from app.industrial_scheduler import build_industrial_scheduler_plan


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"
PKG_CAL = ROOT / "authorized_packages" / "my-gh-cal-ssrf"


def test_dependency_profile_ssrf_retain_express_from_import():
    profile = build_dependency_profile(package_root=PKG_SSRF)
    assert profile.status == STATUS_OK
    assert "npm" in profile.ecosystems
    packages = {c.package for c in profile.components}
    assert "express" in packages
    express = next(c for c in profile.components if c.package == "express")
    assert express.reachable == "yes"
    assert profile.execution_allowed is False
    assert profile.validation_allowed is False
    assert profile.report_submission_allowed is False
    assert profile.confirmed_vulnerability is False
    assert profile.live_advisory_lookup is False
    assert profile.network_access is False


def test_dependency_profile_cal_ssrf_multiple_npm_imports(tmp_path: Path):
    package_root = tmp_path / PKG_CAL.name
    copytree(
        PKG_CAL,
        package_root,
        ignore=ignore_patterns("_upstream"),
    )
    upstream = package_root / "_upstream"
    upstream.mkdir()
    (upstream / "synthetic_dependencies.ts").write_text(
        'import axios from "axios";\n'
        'import ipaddr from "ipaddr.js";\n',
        encoding="utf-8",
    )

    profile = build_dependency_profile(package_root=package_root)

    assert profile.status == STATUS_OK
    assert profile.component_count >= 3
    assert profile.reachable_count >= 1
    packages = {c.package for c in profile.components}
    assert {"axios", "express", "ipaddr.js"}.issubset(packages)
    assert profile.live_advisory_lookup is False
    assert profile.execution_allowed is False


def test_dependency_manifest_package_json_and_requirements():
    profile = build_dependency_profile(
        package_id="manifest-mix",
        authorized_code_files=[
            {
                "path": "package.json",
                "content": (
                    "{\n"
                    '  "name": "demo",\n'
                    '  "dependencies": {"lodash": "4.17.21", "express": "^4.18.0"},\n'
                    '  "devDependencies": {"typescript": "5.0.0"}\n'
                    "}\n"
                ),
            },
            {
                "path": "requirements.txt",
                "content": "PyYAML==6.0\nrequests>=2.0\n",
            },
            {
                "path": "app.py",
                "content": "import yaml\nimport requests\n",
            },
        ],
    )
    assert profile.status == STATUS_OK
    packages = {c.package.lower() for c in profile.components}
    assert "lodash" in packages
    assert "express" in packages
    assert "pyyaml" in packages or "yaml" in packages
    assert "requests" in packages
    assert "npm" in profile.ecosystems
    assert "pypi" in profile.ecosystems
    # import alias yaml -> pyyaml should merge / canonicalize
    assert any(c.package.lower() == "pyyaml" for c in profile.components)
    yaml_comp = next(c for c in profile.components if c.package.lower() == "pyyaml")
    assert yaml_comp.reachable == "yes"
    assert profile.live_advisory_lookup is False


def test_offline_advisory_flag_never_live():
    profile = build_dependency_profile(
        package_id="offline-adv",
        authorized_code_files=[
            {
                "path": "package.json",
                "content": '{"dependencies": {"lodash": "4.17.20"}}',
            },
            {
                "path": "src/index.js",
                "content": "const _ = require('lodash');\n",
            },
        ],
        offline_advisories=[
            {
                "package": "lodash",
                "ecosystem": "npm",
                "advisory_ids": ["OFFLINE-LODASH-1"],
                "known_advisory": True,
            }
        ],
    )
    assert profile.status == STATUS_OK
    lodash = next(c for c in profile.components if c.package == "lodash")
    assert lodash.known_advisory is True
    assert "OFFLINE-LODASH-1" in lodash.advisory_ids
    assert lodash.reachable == "yes"
    assert profile.advisory_flagged_count >= 1
    assert profile.live_advisory_lookup is False
    assert profile.confirmed_vulnerability is False
    assert profile.network_access is False


def test_dependency_missing_package_is_skipped_fail_closed():
    profile = build_dependency_profile(
        package_root=ROOT / "authorized_packages" / "does-not-exist-dep-xyz"
    )
    assert profile.status == STATUS_SKIPPED
    assert profile.execution_allowed is False
    assert profile.report_submission_allowed is False
    assert profile.live_advisory_lookup is False


def test_attach_dependency_never_unlocks_submission():
    bridged = attach_dependency_profile_to_bridge_result(
        {
            "package_id": "pkg",
            "drafts": [{"candidate_id": "H-1"}],
            "submission_blocked": True,
            "execution_allowed": True,
            "report_submission_allowed": True,
            "confirmed_vulnerability": True,
        },
        package_root=PKG_SSRF,
    )
    assert bridged["execution_allowed"] is False
    assert bridged["validation_allowed"] is False
    assert bridged["report_submission_allowed"] is False
    assert bridged["confirmed_vulnerability"] is False
    assert bridged["submission_blocked"] is True
    assert bridged["dependency_profile_present"] is True
    assert isinstance(bridged["dependency_profile"], dict)
    assert bridged["dependency_profile"]["execution_allowed"] is False
    assert bridged["dependency_profile"]["live_advisory_lookup"] is False
    assert int(bridged.get("sbom_component_count") or 0) >= 1
    assert "npm" in (bridged.get("sbom_ecosystems") or [])


def test_secretish_dependency_filenames_skipped():
    profile = build_dependency_profile(
        package_id="secret-skip-dep",
        authorized_code_files=[
            {
                "path": "inputs/api_token_package.json",
                "content": '{"dependencies": {"evil": "1.0.0"}}',
            },
            {
                "path": "package.json",
                "content": '{"dependencies": {"express": "4.18.0"}}',
            },
            {
                "path": "src/app.ts",
                "content": "import express from 'express';\n",
            },
        ],
    )
    assert any("skipped_blocked_name" in n for n in profile.notes)
    packages = {c.package for c in profile.components}
    assert "express" in packages
    assert "evil" not in packages
    assert profile.execution_allowed is False


def test_dependency_profile_and_manifest_fail_closed_on_input_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    package_root = tmp_path / "authorized-package"
    inputs = package_root / "inputs"
    inputs.mkdir(parents=True)
    (inputs / "first.py").write_text("import requests\n", encoding="utf-8")
    (inputs / "second.py").write_text("import httpx\n", encoding="utf-8")
    monkeypatch.setattr(dependency_agent, "_MAX_DEPENDENCY_INPUT_FILES", 1)

    with pytest.raises(DependencyAgentError, match="dependency_input_limit_exceeded"):
        build_dependency_input_manifest(package_root)

    profile = build_dependency_profile(package_root=package_root)

    assert profile.status == STATUS_SKIPPED
    assert "dependency_input_limit_exceeded" in profile.notes
    assert profile.execution_allowed is False
    assert profile.validation_allowed is False
    assert profile.report_submission_allowed is False


def test_dependency_input_limit_counts_nonmatching_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    package_root = tmp_path / "authorized-package"
    inputs = package_root / "inputs"
    inputs.mkdir(parents=True)
    for index in range(3):
        (inputs / f"note-{index}.txt").write_text("ignored\n", encoding="utf-8")
    monkeypatch.setattr(dependency_agent, "_MAX_DEPENDENCY_INPUT_FILES", 1)

    with pytest.raises(DependencyAgentError, match="dependency_input_limit_exceeded"):
        build_dependency_input_manifest(package_root)

    profile = build_dependency_profile(package_root=package_root)

    assert profile.status == STATUS_SKIPPED
    assert "dependency_input_limit_exceeded" in profile.notes


def test_dependency_input_manifest_binds_case_id_metadata(tmp_path: Path):
    package_root = tmp_path / "authorized-package"
    package_root.mkdir()
    case = package_root / "case.json"
    case.write_text('{"case_id": "case-a"}', encoding="utf-8")

    manifest = build_dependency_input_manifest(package_root)
    profile = build_dependency_profile(package_root=package_root)

    assert profile.package_id == "case-a"
    assert [entry["source_path"] for entry in manifest] == ["case.json"]
    assert dependency_input_manifest_matches(package_root, manifest) is True

    case.write_text('{"case_id": "case-b"}', encoding="utf-8")

    assert dependency_input_manifest_matches(package_root, manifest) is False


def test_dependency_profile_fails_closed_on_external_scan_root_symlink(tmp_path: Path):
    package_root = tmp_path / "authorized-package"
    package_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "source.py").write_text("import requests\n", encoding="utf-8")
    inputs_link = package_root / "inputs"
    try:
        inputs_link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    with pytest.raises(DependencyAgentError, match="dependency_input_path_escape"):
        build_dependency_input_manifest(package_root)

    profile = build_dependency_profile(package_root=package_root)

    assert profile.status == STATUS_SKIPPED
    assert "dependency_input_path_escape" in profile.notes


def test_dependency_profile_fails_closed_on_scan_directory_cycle(tmp_path: Path):
    package_root = tmp_path / "authorized-package"
    inputs = package_root / "inputs"
    inputs.mkdir(parents=True)
    loop = inputs / "loop"
    try:
        loop.symlink_to(inputs, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    with pytest.raises(DependencyAgentError, match="dependency_input_path_cycle"):
        build_dependency_input_manifest(package_root)

    profile = build_dependency_profile(package_root=package_root)

    assert profile.status == STATUS_SKIPPED
    assert "dependency_input_path_cycle" in profile.notes


def test_industrial_scheduler_includes_dependency_after_intake():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True},
            "hypotheses": [
                {
                    "finding_id": "H-001",
                    "vuln_type": "ssrf",
                    "severity": "high",
                    "status": "unverified_hypothesis",
                }
            ],
        }
    )
    by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-001c" in by_id
    assert by_id["T-001c"].agent == "dependency_agent"
    assert by_id["T-001c"].depends_on == ["T-001b"]
    assert by_id["T-001c"].execution_allowed is False
    assert by_id["T-002"].depends_on == ["T-001c"]
    assert by_id["T-003"].depends_on == ["T-001c"]
    assert by_id["T-004"].depends_on == ["T-001c"]
    assert any(batch.batch_id == "B-001c" for batch in plan.parallel_batches)
    assert "dependency_agent" in {task.agent for task in plan.dag_tasks}
