from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import sqlite3

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.desktop_backup import create_desktop_backup, restore_desktop_backup


@dataclass(frozen=True)
class DesktopServerConfig:
    host: str
    port: int
    web_port: int
    user_data_dir: Path
    resources_dir: Path
    maintenance: str | None = None
    destination: Path | None = None
    archive: Path | None = None
    application_version: str = "unknown"
    overwrite: bool = False


def parse_desktop_server_args(argv: Sequence[str] | None = None) -> DesktopServerConfig:
    parser = argparse.ArgumentParser(description="Run the local Mythos API server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=_port, default=48123)
    parser.add_argument("--web-port", type=_port, default=48124)
    parser.add_argument("--user-data-dir", type=Path, required=True)
    parser.add_argument("--resources-dir", type=Path, required=True)
    parser.add_argument("--maintenance", choices=("backup", "restore"))
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--application-version", default="unknown")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    if not _is_loopback(args.host):
        parser.error("host_must_be_loopback")
    if args.port == args.web_port:
        parser.error("api_and_web_ports_must_differ")
    if args.maintenance == "backup" and (args.destination is None or args.archive is not None):
        parser.error("backup_requires_destination_only")
    if args.maintenance == "restore" and (args.archive is None or args.destination is not None):
        parser.error("restore_requires_archive_only")
    if args.maintenance is None and (args.destination is not None or args.archive is not None):
        parser.error("maintenance_path_requires_operation")
    if args.overwrite and args.maintenance != "backup":
        parser.error("overwrite_requires_backup")
    return DesktopServerConfig(
        host=args.host,
        port=args.port,
        web_port=args.web_port,
        user_data_dir=args.user_data_dir,
        resources_dir=args.resources_dir,
        maintenance=args.maintenance,
        destination=args.destination,
        archive=args.archive,
        application_version=args.application_version,
        overwrite=args.overwrite,
    )


def build_desktop_environment(config: DesktopServerConfig) -> dict[str, str]:
    user_data_dir = config.user_data_dir
    data_dir = user_data_dir / "data"
    workspace_root = user_data_dir / "workspaces"
    data_dir.mkdir(parents=True, exist_ok=True)
    workspace_root.mkdir(parents=True, exist_ok=True)
    database_path = data_dir / "bounty-mythos.db"
    return {
        "DATABASE_URL": f"sqlite:///{database_path.as_posix()}",
        "STUDIO_WORKSPACE_ROOT": str(workspace_root),
        "STUDIO_WEB_ORIGIN": f"http://{config.host}:{config.web_port}",
        "WORKER_DISPATCH_MODE": "inline",
        "MYTHOS_API_RESOURCES": str(config.resources_dir.resolve()),
    }


def run_desktop_migrations(
    config: DesktopServerConfig,
    *,
    upgrade: Callable[[Config, str], None] = command.upgrade,
    backup: Callable[..., dict] | None = create_desktop_backup,
    requires_upgrade: Callable[[Path, Path], bool] | None = None,
) -> None:
    environment = build_desktop_environment(config)
    resources_dir = Path(environment["MYTHOS_API_RESOURCES"])
    config_path = resources_dir / "alembic.ini"
    migrations_dir = resources_dir / "migrations"
    if not config_path.is_file() or not migrations_dir.is_dir():
        raise FileNotFoundError("desktop_migration_resources_missing")
    alembic_config = Config(str(config_path))
    alembic_config.set_main_option("script_location", str(migrations_dir))
    alembic_config.attributes["database_url_override"] = environment["DATABASE_URL"]
    database_path = config.user_data_dir / "data" / "bounty-mythos.db"
    upgrade_check = requires_upgrade or _requires_upgrade
    if (
        backup is not None
        and database_path.is_file()
        and database_path.stat().st_size > 0
        and upgrade_check(database_path, migrations_dir)
    ):
        backups = config.user_data_dir / "backups"
        backups.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup(
            user_data_dir=config.user_data_dir,
            destination=backups / f"pre-migration-{timestamp}.mythos-backup.zip",
            application_version=config.application_version,
        )
    upgrade(alembic_config, "head")


def main(argv: Sequence[str] | None = None) -> int:
    config = parse_desktop_server_args(argv)

    if config.maintenance == "backup":
        result = create_desktop_backup(
            user_data_dir=config.user_data_dir,
            destination=config.destination,
            application_version=config.application_version,
            overwrite=config.overwrite,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    if config.maintenance == "restore":
        result = restore_desktop_backup(
            user_data_dir=config.user_data_dir,
            archive_path=config.archive,
            application_version=config.application_version,
            migrate=lambda _database_path: run_desktop_migrations(config, backup=None),
        )
        print(json.dumps(result, sort_keys=True))
        return 0

    os.environ.update(build_desktop_environment(config))
    run_desktop_migrations(config)

    import uvicorn

    uvicorn.run("app.main:app", host=config.host, port=config.port)
    return 0


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port_must_be_integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port_out_of_range")
    return port


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _requires_upgrade(database_path: Path, migrations_dir: Path) -> bool:
    alembic_config = Config(str(migrations_dir.parent / "alembic.ini"))
    alembic_config.set_main_option("script_location", str(migrations_dir))
    script = ScriptDirectory.from_config(alembic_config)
    try:
        with closing(sqlite3.connect(database_path)) as connection:
            row = connection.execute("select version_num from alembic_version").fetchone()
    except sqlite3.Error:
        return True
    return not row or row[0] != script.get_current_head()


if __name__ == "__main__":
    raise SystemExit(main())
