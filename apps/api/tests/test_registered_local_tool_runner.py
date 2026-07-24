import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.execution_registry.local_runner as local_runner
from app.dependency_agent import DependencyAgentError, build_dependency_input_manifest
from app.execution_registry import ExecutionAuthorizationRequest
from app.execution_registry.local_runner import (
    RegisteredLocalToolRunRequest,
    local_tool_advisory_artifact_data,
    run_registered_local_tool,
)
from app.scope_guard import ScopeGuardRule


def _rule(*, allowed_validation: list[str]):
    return ScopeGuardRule(
        asset="api.example.test",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=allowed_validation,
        forbidden=[],
        human_approval_required=False,
    )


def _request(package_root: Path, *, tool_id: str = "semgrep_local", allowed_tools=None):
    validation_mode = (
        "static_analyzer"
        if tool_id in {"semgrep_local", "codeql_local", "dependency_sbom_local"}
        else tool_id
    )
    resolved_allowed_tools = [validation_mode] if allowed_tools is None else allowed_tools
    return RegisteredLocalToolRunRequest(
        authorization=ExecutionAuthorizationRequest(
            tool_id=tool_id,
            asset="api.example.test",
            campaign_allowed_tools=resolved_allowed_tools,
            scope_rule=_rule(allowed_validation=[validation_mode]),
            human_approved=True,
        ),
        package_root=str(package_root),
        package_id="authorized-fixture",
        dependency_input_manifest=(
            [
                item
                for item in build_dependency_input_manifest(package_root)
            ]
            if tool_id == "dependency_sbom_local"
            else None
        ),
    )


def test_registered_semgrep_runs_only_after_registry_eligibility(tmp_path: Path, monkeypatch):
    (tmp_path / "inputs").mkdir()
    code_path = tmp_path / "inputs" / "code.py"
    code_path.write_text("requests.get(url)\n", encoding="utf-8")

    def fake_run(command, **kwargs):
        assert "--metrics" in command
        return SimpleNamespace(
            returncode=1,
            stdout=json.dumps(
                {
                    "results": [
                        {
                            "check_id": "mythos.local.ssrf-fetch",
                            "path": str(code_path),
                            "start": {"line": 1},
                            "extra": {"message": "outbound fetch"},
                        }
                    ]
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "app.semgrep_runner.find_semgrep_binary",
        lambda explicit=None: "semgrep-fake",
    )
    result = run_registered_local_tool(
        _request(tmp_path),
        semgrep_subprocess_runner=fake_run,
    )

    assert result.status == "completed"
    assert result.tool_id == "semgrep_local"
    assert result.command_executed is True
    assert result.finding_count == 1
    assert result.advisory_findings == [
        {
            "rule_id": "mythos.local.ssrf-fetch",
            "path": "inputs/code.py",
            "line": 1,
        }
    ]
    assert result.command_hash.startswith("sha256:")
    assert result.authorization.eligible is True
    assert result.authorization.network_access is False
    assert result.candidate_promotion_allowed is False
    assert result.report_submission_allowed is False


def test_registered_semgrep_hash_ignores_embedded_rule_tempfile_path(
    tmp_path: Path,
    monkeypatch,
):
    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs" / "code.py").write_text(
        "requests.get(url)\n",
        encoding="utf-8",
    )

    def fake_run(_command, **_kwargs):
        return SimpleNamespace(returncode=0, stdout='{"results": []}', stderr="")

    monkeypatch.setattr(
        "app.semgrep_runner.find_semgrep_binary",
        lambda explicit=None: "semgrep-fake",
    )
    first = run_registered_local_tool(
        _request(tmp_path),
        semgrep_subprocess_runner=fake_run,
    )
    second = run_registered_local_tool(
        _request(tmp_path),
        semgrep_subprocess_runner=fake_run,
    )

    assert first.status == "completed"
    assert second.status == "completed"
    assert first.command_hash == second.command_hash


def test_codeql_hash_ignores_generated_sarif_fallback_directory(tmp_path: Path):
    first = [
        "codeql",
        "database",
        "analyze",
        "database",
        "suite.qls",
        f"--output={tmp_path / 'mythos-codeql-first' / 'results.sarif'}",
    ]
    second = [
        "codeql",
        "database",
        "analyze",
        "database",
        "suite.qls",
        f"--output={tmp_path / 'mythos-codeql-second' / 'results.sarif'}",
    ]

    assert local_runner._command_hash(
        first,
        tool_id="codeql_local",
        package_root=str(tmp_path),
    ) == local_runner._command_hash(
        second,
        tool_id="codeql_local",
        package_root=str(tmp_path),
    )


def test_registered_local_advisory_preserves_safe_codeql_rule_id(tmp_path: Path):
    findings = local_runner._advisory_findings(
        [
            {"rule_id": "py/path-injection", "path": "src/routes.py", "line": 7},
            {"rule_id": "../path-injection", "path": "src/routes.py", "line": 8},
        ],
        package_root=str(tmp_path),
    )

    assert findings == [
        {"rule_id": "py/path-injection", "path": "src/routes.py", "line": 7}
    ]


def test_registry_denial_prevents_local_runner_invocation(tmp_path: Path):
    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs" / "code.py").write_text("print(1)\n", encoding="utf-8")

    result = run_registered_local_tool(
        _request(tmp_path, allowed_tools=[]),
        semgrep_subprocess_runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("runner should not be called")
        ),
    )

    assert result.status == "blocked"
    assert result.command_executed is False
    assert result.authorization.reason == "tool_not_campaign_allowed"


def test_remote_capability_cannot_use_local_runner(tmp_path: Path):
    result = run_registered_local_tool(
        _request(
            tmp_path,
            tool_id="two_account_authorization_check",
            allowed_tools=["two_account_authorization_check"],
        )
    )

    assert result.status == "blocked"
    assert result.command_executed is False
    assert result.authorization.reason == "execution_lease_required"


def test_registered_dependency_sbom_profile_is_offline_redacted_advisory_only(
    tmp_path: Path,
):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "4.17.20"}}',
        encoding="utf-8",
    )
    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs" / "index.js").write_text(
        "const lodash = require('lodash');\n",
        encoding="utf-8",
    )
    raw_marker = "dependency-description-must-not-be-persisted"
    (tmp_path / "inputs" / "dependencies.json").write_text(
        json.dumps(
            {
                "components": [
                    {
                        "name": "lodash",
                        "version": "4.17.20",
                        "ecosystem": "npm",
                        "known_advisory": True,
                        "advisory_ids": ["OFFLINE-LODASH-1"],
                        "priority": "high",
                        "description": raw_marker,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = run_registered_local_tool(
        _request(tmp_path, tool_id="dependency_sbom_local")
    )

    assert result.status == "completed"
    assert result.runner_status == "dependency_sbom_local_completed"
    assert result.command_executed is True
    assert result.finding_count == 1
    assert result.advisory_findings == []
    assert result.dependency_profile is not None
    assert result.dependency_profile.component_count >= 1
    assert result.dependency_profile.network_access is False
    assert [advisory.model_dump() for advisory in result.dependency_advisories] == [
        {
            "package": "lodash",
            "version": "4.17.20",
            "ecosystem": "npm",
            "advisory_id": "OFFLINE-LODASH-1",
            "priority": "high",
            "source_paths": ["inputs/index.js"],
        }
    ]
    assert raw_marker not in result.model_dump_json()
    assert result.candidate_promotion_allowed is False
    assert result.report_submission_allowed is False


def test_dependency_snapshot_manifest_blocks_post_approval_mutation(tmp_path: Path):
    package_json = tmp_path / "package.json"
    package_json.write_text(
        '{"dependencies": {"lodash": "4.17.20"}}',
        encoding="utf-8",
    )
    request = _request(tmp_path, tool_id="dependency_sbom_local")
    package_json.write_text(
        '{"dependencies": {"lodash": "4.17.21"}}',
        encoding="utf-8",
    )

    result = run_registered_local_tool(request)

    assert result.status == "blocked"
    assert result.runner_status == "dependency_snapshot_invalid"
    assert result.command_executed is False
    assert result.finding_count == 0


def test_dependency_projection_rejects_secret_shaped_metadata(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "4.17.20"}}',
        encoding="utf-8",
    )
    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs" / "index.js").write_text(
        "const lodash = require('lodash');\n",
        encoding="utf-8",
    )
    raw_secrets = [
        "token:DO_NOT_PERSIST",
        "ghp_DO_NOT_PERSIST_1234567890123456",
        "AKIAIOSFODNN7EXAMPLE",
    ]
    (tmp_path / "inputs" / "dependencies.json").write_text(
        json.dumps(
            {
                "components": [
                    {
                        "name": "lodash",
                        "version": "api_key=DO_NOT_PERSIST",
                        "ecosystem": "npm",
                        "known_advisory": True,
                        "advisory_ids": raw_secrets,
                        "used_by": [
                            "inputs/token:DO_NOT_PERSIST.js",
                            "inputs/ghp_DO_NOT_PERSIST_1234567890123456.js",
                            "inputs/AKIAIOSFODNN7EXAMPLE.js",
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = run_registered_local_tool(
        _request(tmp_path, tool_id="dependency_sbom_local")
    )
    artifact_kind, payload_summary, derived_facts = local_tool_advisory_artifact_data(
        result
    )

    assert artifact_kind == "dependency_sbom_advisory"
    serialized = json.dumps(
        {
            "result": result.model_dump(mode="json"),
            "payload_summary": payload_summary,
            "derived_facts": derived_facts,
        }
    )
    for raw_secret in raw_secrets:
        assert raw_secret not in serialized
    assert "api_key=DO_NOT_PERSIST" not in serialized


def test_dependency_input_manifest_fails_closed_when_candidate_limit_exceeded(
    tmp_path: Path,
):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for index in range(1_201):
        (inputs / f"module_{index:04d}.js").write_text(
            "module.exports = {};\n",
            encoding="utf-8",
        )

    with pytest.raises(
        DependencyAgentError,
        match="dependency_input_limit_exceeded",
    ):
        build_dependency_input_manifest(tmp_path)
