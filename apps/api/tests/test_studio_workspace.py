from pathlib import Path

from app.studio_workspace import (
    StudioArtifactImport,
    create_workspace,
    import_workspace_artifact,
    load_workspace_manifest,
    record_workspace_run,
)


def test_create_workspace_writes_local_manifest(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    manifest = load_workspace_manifest(workspace.path)

    assert workspace.path == tmp_path / "acme-api"
    assert manifest["name"] == "acme-api"
    assert manifest["safety"]["scope_guard_status"] == "missing_scope"
    assert manifest["artifacts"] == []
    assert manifest["runs"] == []


def test_create_workspace_uses_safe_path_name_and_keeps_manifest_name(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="Acme API/Prod")

    manifest = load_workspace_manifest(workspace.path)

    assert workspace.path == tmp_path / "Acme-API-Prod"
    assert manifest["name"] == "Acme API/Prod"


def test_import_workspace_artifact_records_reference_without_copying_secret_text(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")
    policy_path = tmp_path / "policy.md"
    policy_path.write_text(
        "Authorization: Bearer secret-token\nin scope api.example.com",
        encoding="utf-8",
    )

    updated = import_workspace_artifact(
        workspace.path,
        StudioArtifactImport(kind="policy", source_path=str(policy_path)),
    )

    artifact = updated["artifacts"][0]
    assert artifact["kind"] == "policy"
    assert artifact["source_path"] == str(policy_path)
    assert artifact["source_hash"].startswith("sha256:")
    assert "source_sha256" not in artifact
    assert artifact["sensitivity_label"] == "sensitive"
    assert artifact["redaction_status"] == "needs_review"
    assert "secret-token" not in str(updated)


def test_import_workspace_artifact_marks_non_sensitive_text_low(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")
    policy_path = tmp_path / "policy.md"
    policy_path.write_text("in scope api.example.com", encoding="utf-8")

    updated = import_workspace_artifact(
        workspace.path,
        StudioArtifactImport(kind="policy", source_path=str(policy_path)),
    )

    artifact = updated["artifacts"][0]
    assert artifact["sensitivity_label"] == "low"
    assert artifact["redaction_status"] == "not_required"


def test_record_workspace_run_accepts_missing_report_path(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_run(
        workspace.path,
        run_id="run-1",
        status="blocked",
        report_path=None,
        candidate_count=3,
    )

    run = updated["runs"][0]
    assert run["run_id"] == "run-1"
    assert run["report_path"] is None
    assert run["candidate_count"] == 3
