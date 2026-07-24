from __future__ import annotations

from contextlib import closing
import hashlib
from importlib import import_module
import json
from pathlib import Path
import shutil
import sqlite3
from zipfile import ZipFile, ZipInfo

import pytest


def test_create_backup_captures_sqlite_and_workspace_without_transients(
    tmp_path: Path,
) -> None:
    try:
        desktop_backup = import_module("app.desktop_backup")
    except ModuleNotFoundError:
        pytest.fail("desktop backup module is missing")
    create_desktop_backup = getattr(desktop_backup, "create_desktop_backup", None)
    validate_desktop_backup = getattr(desktop_backup, "validate_desktop_backup", None)
    assert callable(create_desktop_backup)
    assert callable(validate_desktop_backup)

    user_data = tmp_path / "user-data"
    database_path = user_data / "data" / "bounty-mythos.db"
    database_path.parent.mkdir(parents=True)
    connection = sqlite3.connect(database_path)
    connection.execute("pragma journal_mode = wal")
    connection.execute("create table alembic_version (version_num text not null)")
    connection.execute("insert into alembic_version values ('0015_campaign_task_execution_lease')")
    connection.execute("create table research_notes (body text not null)")
    connection.execute("insert into research_notes values ('portable-note')")
    connection.commit()

    workspace = user_data / "workspaces" / "workspace-a"
    reports = workspace / "reports"
    reports.mkdir(parents=True)
    (workspace / "manifest.json").write_text('{"name":"workspace-a"}', encoding="utf-8")
    (reports / "draft.md").write_text("submission blocked", encoding="utf-8")
    (workspace / "active.lock").write_text("lock", encoding="utf-8")
    (workspace / "scratch.tmp").write_text("temporary", encoding="utf-8")
    cache = workspace / "__pycache__"
    cache.mkdir()
    (cache / "cached.pyc").write_bytes(b"cache")
    destination = tmp_path / "portable.mythos-backup.zip"

    try:
        result = create_desktop_backup(
            user_data_dir=user_data,
            destination=destination,
            application_version="0.1.0",
        )
    finally:
        connection.close()

    assert result == {
        "status": "created",
        "archive_name": destination.name,
        "file_count": 3,
    }
    with ZipFile(destination) as archive:
        names = sorted(archive.namelist())
        assert names == [
            "data/bounty-mythos.db",
            "manifest.json",
            "workspaces/workspace-a/manifest.json",
            "workspaces/workspace-a/reports/draft.md",
        ]
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format_version"] == 1
        assert manifest["application_version"] == "0.1.0"
        assert manifest["alembic_revision"] == "0015_campaign_task_execution_lease"
        assert manifest["submission_blocked"] is True
        assert manifest["report_submission_allowed"] is False
        assert [item["path"] for item in manifest["files"]] == names[0:1] + names[2:]
        for item in manifest["files"]:
            payload = archive.read(item["path"])
            assert item["size"] == len(payload)
            assert item["sha256"] == hashlib.sha256(payload).hexdigest()

        extracted_database = tmp_path / "extracted.db"
        extracted_database.write_bytes(archive.read("data/bounty-mythos.db"))

    with closing(sqlite3.connect(extracted_database)) as restored:
        note = restored.execute("select body from research_notes").fetchone()
    assert note == ("portable-note",)

    validated = validate_desktop_backup(destination)
    assert validated["format_version"] == 1
    assert validated["submission_blocked"] is True

    with pytest.raises(desktop_backup.DesktopBackupError, match="backup_destination_exists"):
        create_desktop_backup(
            user_data_dir=user_data,
            destination=destination,
            application_version="0.1.0",
        )
    overwritten = create_desktop_backup(
        user_data_dir=user_data,
        destination=destination,
        application_version="0.1.0",
        overwrite=True,
    )
    assert overwritten["status"] == "created"


def test_validate_backup_rejects_traversal_hash_and_symlink_entries(tmp_path: Path) -> None:
    try:
        desktop_backup = import_module("app.desktop_backup")
    except ModuleNotFoundError:
        pytest.fail("desktop backup module is missing")
    validate_desktop_backup = getattr(desktop_backup, "validate_desktop_backup", None)
    backup_error = getattr(desktop_backup, "DesktopBackupError", ValueError)
    assert callable(validate_desktop_backup)

    traversal_archive = tmp_path / "traversal.zip"
    with ZipFile(traversal_archive, "w") as archive:
        archive.writestr("../outside.txt", b"outside")
    with pytest.raises(backup_error, match="backup_archive_path_invalid"):
        validate_desktop_backup(traversal_archive)

    hash_archive = tmp_path / "hash.zip"
    manifest = {
        "format_version": 1,
        "application_version": "0.1.0",
        "alembic_revision": "0015",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "files": [{"path": "data/bounty-mythos.db", "size": 3, "sha256": "0" * 64}],
    }
    with ZipFile(hash_archive, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("data/bounty-mythos.db", b"bad")
    with pytest.raises(backup_error, match="backup_archive_hash_mismatch"):
        validate_desktop_backup(hash_archive)

    symlink_archive = tmp_path / "symlink.zip"
    symlink_info = ZipInfo("data/link")
    symlink_info.external_attr = (0o120777 << 16) | 0x10
    with ZipFile(symlink_archive, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr(symlink_info, "target")
    with pytest.raises(backup_error, match="backup_archive_symlink"):
        validate_desktop_backup(symlink_archive)

    malformed_archive = tmp_path / "malformed.zip"
    malformed_manifest = {
        "format_version": 1,
        "application_version": "0.1.0",
        "alembic_revision": "0015",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "files": ["not-an-entry"],
    }
    with ZipFile(malformed_archive, "w") as archive:
        archive.writestr("manifest.json", json.dumps(malformed_manifest))
    with pytest.raises(backup_error, match="backup_manifest_files_invalid"):
        validate_desktop_backup(malformed_archive)

    unexpected_path_archive = tmp_path / "unexpected-path.zip"
    unexpected_payloads = {
        "data/bounty-mythos.db": b"database",
        "data/unexpected.txt": b"unexpected",
    }
    unexpected_manifest = {
        "format_version": 1,
        "application_version": "0.1.0",
        "alembic_revision": "0015",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "files": [
            {
                "path": path,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for path, payload in sorted(unexpected_payloads.items())
        ],
    }
    with ZipFile(unexpected_path_archive, "w") as archive:
        archive.writestr("manifest.json", json.dumps(unexpected_manifest))
        for path, payload in unexpected_payloads.items():
            archive.writestr(path, payload)
    with pytest.raises(backup_error, match="backup_manifest_files_invalid"):
        validate_desktop_backup(unexpected_path_archive)

    non_zip = tmp_path / "not-a-zip"
    non_zip.write_bytes(b"not a zip")
    with pytest.raises(backup_error, match="backup_archive_invalid"):
        validate_desktop_backup(non_zip)


def test_restore_backup_replaces_state_and_rolls_back_when_migration_fails(
    tmp_path: Path,
) -> None:
    try:
        desktop_backup = import_module("app.desktop_backup")
    except ModuleNotFoundError:
        pytest.fail("desktop backup module is missing")
    create_desktop_backup = getattr(desktop_backup, "create_desktop_backup", None)
    restore_desktop_backup = getattr(desktop_backup, "restore_desktop_backup", None)
    backup_error = getattr(desktop_backup, "DesktopBackupError", ValueError)
    assert callable(create_desktop_backup)
    assert callable(restore_desktop_backup)

    source = tmp_path / "source"
    _write_state(source, "portable-state", "portable-note")
    source_archive = tmp_path / "source.mythos-backup.zip"
    create_desktop_backup(
        user_data_dir=source,
        destination=source_archive,
        application_version="0.1.0",
    )

    target = tmp_path / "target"
    _write_state(target, "old-state", "old-note")
    portable_archive = target / "portable.mythos-backup.zip"
    portable_archive.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_archive, portable_archive)

    migrated: list[Path] = []

    def migrate(database_path: Path) -> None:
        migrated.append(database_path)
        with closing(sqlite3.connect(database_path)) as connection:
            connection.execute("create table migration_marker (value text not null)")
            connection.execute("insert into migration_marker values ('upgraded')")
            connection.commit()

    result = restore_desktop_backup(
        user_data_dir=target,
        archive_path=portable_archive,
        migrate=migrate,
    )

    assert result["status"] == "restored"
    assert migrated == [target / "data" / "bounty-mythos.db"]
    assert (target / "workspaces" / "workspace-a" / "state.txt").read_text() == "portable-state"
    with closing(sqlite3.connect(target / "data" / "bounty-mythos.db")) as connection:
        assert connection.execute("select body from research_notes").fetchone() == ("portable-note",)
        assert connection.execute("select value from migration_marker").fetchone() == ("upgraded",)
    rollback_archive = target / "backups" / result["rollback_archive_name"]
    assert rollback_archive.is_file()

    shutil.rmtree(target / "data")
    shutil.rmtree(target / "workspaces")
    _write_state(target, "new-state", "new-note")

    def fail_migration(_database_path: Path) -> None:
        raise RuntimeError("migration failed")

    with pytest.raises(backup_error, match="restore_failed_rolled_back"):
        restore_desktop_backup(
            user_data_dir=target,
            archive_path=portable_archive,
            migrate=fail_migration,
        )
    assert (target / "workspaces" / "workspace-a" / "state.txt").read_text() == "new-state"
    with closing(sqlite3.connect(target / "data" / "bounty-mythos.db")) as connection:
        assert connection.execute("select body from research_notes").fetchone() == ("new-note",)


def test_create_backup_supports_legacy_database_and_rejects_state_destination(
    tmp_path: Path,
) -> None:
    desktop_backup = import_module("app.desktop_backup")
    user_data = tmp_path / "user-data"
    database_path = user_data / "data" / "bounty-mythos.db"
    database_path.parent.mkdir(parents=True)
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("create table legacy_records (value text not null)")
        connection.execute("insert into legacy_records values ('legacy')")
        connection.commit()
    (user_data / "workspaces").mkdir(parents=True)
    destination = tmp_path / "legacy.mythos-backup.zip"

    desktop_backup.create_desktop_backup(
        user_data_dir=user_data,
        destination=destination,
        application_version="0.1.0",
    )

    assert desktop_backup.validate_desktop_backup(destination)["alembic_revision"] is None
    with pytest.raises(desktop_backup.DesktopBackupError, match="backup_destination_inside_state"):
        desktop_backup.create_desktop_backup(
            user_data_dir=user_data,
            destination=user_data / "workspaces" / "nested.mythos-backup.zip",
            application_version="0.1.0",
        )


def test_create_backup_rejects_a_linked_workspace_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desktop_backup = import_module("app.desktop_backup")
    user_data = tmp_path / "user-data"
    _write_state(user_data, "workspace-state", "note")
    workspace_root = user_data / "workspaces"
    real_is_link = desktop_backup._is_link_or_reparse_point
    monkeypatch.setattr(
        desktop_backup,
        "_is_link_or_reparse_point",
        lambda candidate: candidate == workspace_root or real_is_link(candidate),
    )

    with pytest.raises(desktop_backup.DesktopBackupError, match="backup_workspace_symlink"):
        desktop_backup.create_desktop_backup(
            user_data_dir=user_data,
            destination=tmp_path / "portable.mythos-backup.zip",
            application_version="0.1.0",
        )


def test_restore_rejects_archive_inside_live_state(tmp_path: Path) -> None:
    desktop_backup = import_module("app.desktop_backup")
    source = tmp_path / "source"
    target = tmp_path / "target"
    _write_state(source, "portable-state", "portable-note")
    _write_state(target, "old-state", "old-note")
    source_archive = tmp_path / "portable.mythos-backup.zip"
    desktop_backup.create_desktop_backup(
        user_data_dir=source,
        destination=source_archive,
        application_version="0.1.0",
    )
    live_archive = target / "workspaces" / "portable.mythos-backup.zip"
    shutil.copy2(source_archive, live_archive)

    with pytest.raises(desktop_backup.DesktopBackupError, match="backup_archive_inside_state"):
        desktop_backup.restore_desktop_backup(
            user_data_dir=target,
            archive_path=live_archive,
        )


def test_restore_keeps_live_state_when_initial_directory_move_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desktop_backup = import_module("app.desktop_backup")
    source = tmp_path / "source"
    target = tmp_path / "target"
    _write_state(source, "portable-state", "portable-note")
    _write_state(target, "old-state", "old-note")
    archive = tmp_path / "portable.mythos-backup.zip"
    desktop_backup.create_desktop_backup(
        user_data_dir=source,
        destination=archive,
        application_version="0.1.0",
    )
    real_replace = desktop_backup.os.replace

    def fail_workspace_move(source_path, destination_path) -> None:
        if Path(source_path) == target / "workspaces":
            raise OSError("simulated workspace move failure")
        real_replace(source_path, destination_path)

    monkeypatch.setattr(desktop_backup.os, "replace", fail_workspace_move)

    with pytest.raises(desktop_backup.DesktopBackupError, match="restore_failed_rolled_back"):
        desktop_backup.restore_desktop_backup(
            user_data_dir=target,
            archive_path=archive,
        )

    assert (target / "workspaces" / "workspace-a" / "state.txt").read_text() == "old-state"
    with closing(sqlite3.connect(target / "data" / "bounty-mythos.db")) as connection:
        assert connection.execute("select body from research_notes").fetchone() == ("old-note",)


def _write_state(user_data: Path, workspace_state: str, note: str) -> None:
    database_path = user_data / "data" / "bounty-mythos.db"
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("create table alembic_version (version_num text not null)")
        connection.execute("insert into alembic_version values ('0015')")
        connection.execute("create table research_notes (body text not null)")
        connection.execute("insert into research_notes values (?)", (note,))
        connection.commit()
    workspace = user_data / "workspaces" / "workspace-a"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "manifest.json").write_text('{"name":"workspace-a"}', encoding="utf-8")
    (workspace / "state.txt").write_text(workspace_state, encoding="utf-8")
