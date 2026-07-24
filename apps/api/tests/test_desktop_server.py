from pathlib import Path
import os
import json

import pytest

import app.desktop_server as desktop_server

from app.desktop_server import (
    build_desktop_environment,
    parse_desktop_server_args,
    run_desktop_migrations,
)


def test_desktop_entry_uses_loopback_ports_and_user_data_paths(tmp_path: Path) -> None:
    resources = tmp_path / "resources"
    resources.mkdir()
    user_data = tmp_path / "user-data"

    config = parse_desktop_server_args(
        [
            "--host",
            "127.0.0.1",
            "--port",
            "48123",
            "--web-port",
            "48124",
            "--user-data-dir",
            str(user_data),
            "--resources-dir",
            str(resources),
        ]
    )
    environment = build_desktop_environment(config)

    assert config.host == "127.0.0.1"
    assert config.port == 48123
    assert environment["DATABASE_URL"].endswith("/data/bounty-mythos.db")
    assert environment["STUDIO_WORKSPACE_ROOT"] == str(user_data / "workspaces")
    assert environment["STUDIO_WEB_ORIGIN"] == "http://127.0.0.1:48124"
    assert environment["WORKER_DISPATCH_MODE"] == "inline"
    assert Path(environment["MYTHOS_API_RESOURCES"]) == resources.resolve()


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.20", "example.test"])
def test_desktop_entry_rejects_non_loopback_hosts(
    host: str,
    tmp_path: Path,
) -> None:
    with pytest.raises(SystemExit):
        parse_desktop_server_args(
            [
                "--host",
                host,
                "--port",
                "48123",
                "--web-port",
                "48124",
                "--user-data-dir",
                str(tmp_path / "user-data"),
                "--resources-dir",
                str(tmp_path / "resources"),
            ]
        )


def test_desktop_entry_runs_head_migrations_from_injected_resources(
    tmp_path: Path,
) -> None:
    resources = tmp_path / "resources"
    migrations = resources / "migrations"
    migrations.mkdir(parents=True)
    (resources / "alembic.ini").write_text(
        "[alembic]\nscript_location = migrations\n",
        encoding="utf-8",
    )
    user_data = tmp_path / "user-data"
    config = parse_desktop_server_args(
        [
            "--host",
            "127.0.0.1",
            "--port",
            "48123",
            "--web-port",
            "48124",
            "--user-data-dir",
            str(user_data),
            "--resources-dir",
            str(resources),
        ]
    )
    calls: list[tuple[str, str, str]] = []

    def upgrade(alembic_config, revision: str) -> None:
        calls.append(
            (
                alembic_config.config_file_name,
                alembic_config.get_main_option("script_location"),
                revision,
            )
        )

    run_desktop_migrations(config, upgrade=upgrade)

    assert calls == [(str(resources / "alembic.ini"), str(migrations), "head")]
    assert (user_data / "data").is_dir()
    assert (user_data / "workspaces").is_dir()


def test_desktop_entry_parses_one_backup_or_restore_maintenance_operation(
    tmp_path: Path,
) -> None:
    common = [
        "--user-data-dir",
        str(tmp_path / "user-data"),
        "--resources-dir",
        str(tmp_path / "resources"),
        "--application-version",
        "0.1.0",
    ]
    backup = parse_desktop_server_args(
        [
            *common,
            "--maintenance",
            "backup",
            "--destination",
            str(tmp_path / "portable.mythos-backup.zip"),
            "--overwrite",
        ]
    )
    restore = parse_desktop_server_args(
        [
            *common,
            "--maintenance",
            "restore",
            "--archive",
            str(tmp_path / "portable.mythos-backup.zip"),
        ]
    )

    assert backup.maintenance == "backup"
    assert backup.destination == tmp_path / "portable.mythos-backup.zip"
    assert backup.archive is None
    assert backup.overwrite is True
    assert backup.application_version == "0.1.0"
    assert restore.maintenance == "restore"
    assert restore.archive == tmp_path / "portable.mythos-backup.zip"
    assert restore.destination is None

    for invalid in (
        [*common, "--maintenance", "backup"],
        [*common, "--maintenance", "restore"],
        [*common, "--destination", str(tmp_path / "backup.zip")],
        [
            *common,
            "--maintenance",
            "backup",
            "--destination",
            str(tmp_path / "backup.zip"),
            "--archive",
            str(tmp_path / "restore.zip"),
        ],
    ):
        with pytest.raises(SystemExit):
            parse_desktop_server_args(invalid)


def test_desktop_backup_maintenance_does_not_mutate_process_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import desktop_server

    monkeypatch.setenv("WORKER_DISPATCH_MODE", "celery")
    monkeypatch.setattr(
        desktop_server,
        "create_desktop_backup",
        lambda **_kwargs: {"status": "created"},
    )

    assert desktop_server.main(
        [
            "--user-data-dir",
            str(tmp_path / "user-data"),
            "--resources-dir",
            str(tmp_path / "resources"),
            "--maintenance",
            "backup",
            "--destination",
            str(tmp_path / "portable.mythos-backup.zip"),
        ]
    ) == 0
    assert os.environ["WORKER_DISPATCH_MODE"] == "celery"


def test_desktop_migration_backup_precedes_pending_upgrade(tmp_path: Path) -> None:
    resources = tmp_path / "resources"
    migrations = resources / "migrations"
    migrations.mkdir(parents=True)
    (resources / "alembic.ini").write_text(
        "[alembic]\nscript_location = migrations\n",
        encoding="utf-8",
    )
    user_data = tmp_path / "user-data"
    database = user_data / "data" / "bounty-mythos.db"
    database.parent.mkdir(parents=True)
    database.write_bytes(b"existing database")
    config = parse_desktop_server_args(
        [
            "--user-data-dir",
            str(user_data),
            "--resources-dir",
            str(resources),
            "--application-version",
            "0.1.0",
        ]
    )
    calls: list[tuple[str, Path]] = []

    def backup(**kwargs) -> dict:
        calls.append(("backup", Path(kwargs["destination"])))
        return {"status": "created"}

    def upgrade(_alembic_config, _revision: str) -> None:
        calls.append(("upgrade", database))

    run_desktop_migrations(
        config,
        upgrade=upgrade,
        backup=backup,
        requires_upgrade=lambda _database, _migrations: True,
    )

    assert [name for name, _path in calls] == ["backup", "upgrade"]
    backup_path = calls[0][1]
    assert backup_path.parent == user_data / "backups"
    assert backup_path.name.startswith("pre-migration-")
    assert backup_path.name.endswith(".mythos-backup.zip")


def test_desktop_maintenance_main_runs_backup_without_starting_uvicorn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = []

    def backup(**kwargs) -> dict:
        calls.append(kwargs)
        return {"status": "created", "archive_name": "portable.zip", "file_count": 3}

    monkeypatch.setattr(desktop_server, "create_desktop_backup", backup)
    result = desktop_server.main(
        [
            "--user-data-dir",
            str(tmp_path / "user-data"),
            "--resources-dir",
            str(tmp_path / "resources"),
            "--maintenance",
            "backup",
            "--destination",
            str(tmp_path / "portable.zip"),
            "--application-version",
            "0.1.0",
            "--overwrite",
        ]
    )

    assert result == 0
    assert calls[0]["overwrite"] is True
    assert json.loads(capsys.readouterr().out)["status"] == "created"


def test_desktop_maintenance_main_runs_restore_without_starting_uvicorn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = []

    def restore(**kwargs) -> dict:
        calls.append(kwargs)
        return {
            "status": "restored",
            "archive_name": "portable.zip",
            "rollback_archive_name": "pre-restore.zip",
        }

    monkeypatch.setattr(desktop_server, "restore_desktop_backup", restore)
    result = desktop_server.main(
        [
            "--user-data-dir",
            str(tmp_path / "user-data"),
            "--resources-dir",
            str(tmp_path / "resources"),
            "--maintenance",
            "restore",
            "--archive",
            str(tmp_path / "portable.zip"),
        ]
    )

    assert result == 0
    assert calls[0]["migrate"]
    assert json.loads(capsys.readouterr().out)["status"] == "restored"
