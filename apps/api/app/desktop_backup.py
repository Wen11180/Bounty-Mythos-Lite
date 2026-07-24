from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import shutil
import sqlite3
import stat
import tempfile
from typing import Any, Callable
from zipfile import BadZipFile, ZIP_DEFLATED, ZipFile


MAX_BACKUP_BYTES = 4 * 1024 * 1024 * 1024
_TRANSIENT_DIRECTORIES = {
    "__pycache__",
    "cache",
    "code cache",
    "dawngraphitecache",
    "dawnwebgpucache",
    "gpucache",
}
_TRANSIENT_SUFFIXES = {".lock", ".pyc", ".tmp"}


class DesktopBackupError(ValueError):
    pass


def create_desktop_backup(
    *,
    user_data_dir: str | Path,
    destination: str | Path,
    application_version: str,
    overwrite: bool = False,
) -> dict[str, Any]:
    user_data = Path(user_data_dir).resolve()
    destination_path = Path(destination).resolve()
    if _is_within(user_data / "data", destination_path) or _is_within(
        user_data / "workspaces",
        destination_path,
    ):
        raise DesktopBackupError("backup_destination_inside_state")
    if destination_path.exists() and not overwrite:
        raise DesktopBackupError("backup_destination_exists")
    destination_path.parent.mkdir(parents=True, exist_ok=True)

    database_path = user_data / "data" / "bounty-mythos.db"
    if not database_path.is_file():
        raise DesktopBackupError("backup_database_missing")

    temporary_archive: Path | None = None
    try:
        with tempfile.TemporaryDirectory(
            prefix=".mythos-backup-stage-",
            dir=destination_path.parent,
        ) as temporary_directory:
            staging_root = Path(temporary_directory)
            staged_database = staging_root / "data" / "bounty-mythos.db"
            staged_database.parent.mkdir(parents=True)
            _backup_sqlite(database_path, staged_database)
            _copy_workspaces(user_data / "workspaces", staging_root / "workspaces")

            entries = _manifest_entries(staging_root)
            manifest = {
                "format_version": 1,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "application_version": str(application_version),
                "alembic_revision": _alembic_revision(staged_database),
                "submission_blocked": True,
                "report_submission_allowed": False,
                "files": entries,
            }
            (staging_root / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True),
                encoding="utf-8",
            )

            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=".mythos-backup-",
                suffix=".zip",
                dir=destination_path.parent,
            )
            os.close(file_descriptor)
            temporary_archive = Path(temporary_name)
            with ZipFile(temporary_archive, "w", compression=ZIP_DEFLATED) as archive:
                for source in _archive_files(staging_root):
                    archive.write(source, source.relative_to(staging_root).as_posix())
            if temporary_archive.stat().st_size > MAX_BACKUP_BYTES:
                raise DesktopBackupError("backup_archive_too_large")
            os.replace(temporary_archive, destination_path)
            temporary_archive = None
    finally:
        if temporary_archive is not None:
            temporary_archive.unlink(missing_ok=True)

    return {
        "status": "created",
        "archive_name": destination_path.name,
        "file_count": len(entries),
    }


def validate_desktop_backup(archive_path: str | Path) -> dict[str, Any]:
    path = Path(archive_path).resolve()
    if not path.is_file():
        raise DesktopBackupError("backup_archive_missing")
    if path.stat().st_size > MAX_BACKUP_BYTES:
        raise DesktopBackupError("backup_archive_too_large")
    try:
        with ZipFile(path) as archive:
            infos = archive.infolist()
            names = [_archive_name(info.filename) for info in infos]
            if len(names) != len(set(names)):
                raise DesktopBackupError("backup_archive_duplicate_path")
            if "manifest.json" not in names:
                raise DesktopBackupError("backup_manifest_missing")
            for info, name in zip(infos, names, strict=True):
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise DesktopBackupError("backup_archive_symlink")
                if info.is_dir():
                    raise DesktopBackupError("backup_archive_directory")
                if info.file_size > MAX_BACKUP_BYTES:
                    raise DesktopBackupError("backup_archive_too_large")
                if name == "manifest.json":
                    continue
            try:
                manifest = json.loads(archive.read("manifest.json"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DesktopBackupError("backup_manifest_invalid") from exc
            _validate_manifest(manifest, names)
            total_bytes = 0
            for item in manifest["files"]:
                item_path = item["path"]
                payload = archive.read(item_path)
                total_bytes += len(payload)
                if total_bytes > MAX_BACKUP_BYTES:
                    raise DesktopBackupError("backup_archive_too_large")
                if len(payload) != item["size"]:
                    raise DesktopBackupError("backup_archive_size_mismatch")
                if hashlib.sha256(payload).hexdigest() != item["sha256"]:
                    raise DesktopBackupError("backup_archive_hash_mismatch")
            return manifest
    except DesktopBackupError:
        raise
    except (BadZipFile, OSError, ValueError, KeyError, TypeError) as exc:
        raise DesktopBackupError("backup_archive_invalid") from exc


def restore_desktop_backup(
    *,
    user_data_dir: str | Path,
    archive_path: str | Path,
    migrate: Callable[[Path], None] | None = None,
    application_version: str = "unknown",
) -> dict[str, Any]:
    user_data = Path(user_data_dir).resolve()
    archive = Path(archive_path).resolve()
    if _is_within(user_data / "data", archive) or _is_within(
        user_data / "workspaces",
        archive,
    ):
        raise DesktopBackupError("backup_archive_inside_state")
    manifest = validate_desktop_backup(archive)
    rollback_archive: Path | None = None
    database_path = user_data / "data" / "bounty-mythos.db"
    if database_path.is_file():
        backups = user_data / "backups"
        backups.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        rollback_archive = backups / f"pre-restore-{timestamp}.mythos-backup.zip"
        create_desktop_backup(
            user_data_dir=user_data,
            destination=rollback_archive,
            application_version=application_version,
        )

    user_data.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".mythos-restore-stage-",
        dir=user_data.parent,
    ) as temporary_directory:
        temporary_root = Path(temporary_directory)
        restored_root = temporary_root / "restored"
        saved_root = temporary_root / "saved"
        _extract_backup(archive, manifest, restored_root)
        replaced = False
        try:
            _move_live_state(user_data, saved_root)
            replaced = True
            _install_staged_state(restored_root, user_data)
            if migrate is not None:
                migrate(database_path)
        except Exception as exc:
            if replaced:
                _remove_live_state(user_data)
                _install_staged_state(saved_root, user_data)
            raise DesktopBackupError("restore_failed_rolled_back") from exc

    return {
        "status": "restored",
        "archive_name": archive.name,
        "rollback_archive_name": rollback_archive.name if rollback_archive else None,
    }


def _extract_backup(archive_path: Path, manifest: dict[str, Any], destination: Path) -> None:
    with ZipFile(archive_path) as archive:
        for item in manifest["files"]:
            relative = PurePosixPath(item["path"])
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item["path"]) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def _move_live_state(user_data: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    moved = []
    try:
        for name in ("data", "workspaces"):
            source = user_data / name
            if source.exists():
                os.replace(source, destination / name)
                moved.append(name)
    except Exception:
        for name in reversed(moved):
            os.replace(destination / name, user_data / name)
        raise


def _install_staged_state(source: Path, user_data: Path) -> None:
    user_data.mkdir(parents=True, exist_ok=True)
    staged_data = source / "data"
    if not staged_data.is_dir():
        raise DesktopBackupError("backup_database_missing")
    os.replace(staged_data, user_data / "data")
    staged_workspaces = source / "workspaces"
    if staged_workspaces.is_dir():
        os.replace(staged_workspaces, user_data / "workspaces")
    else:
        (user_data / "workspaces").mkdir(parents=True, exist_ok=True)


def _remove_live_state(user_data: Path) -> None:
    for name in ("data", "workspaces"):
        path = user_data / name
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def _validate_manifest(manifest: Any, names: list[str]) -> None:
    if not isinstance(manifest, dict) or manifest.get("format_version") != 1:
        raise DesktopBackupError("backup_manifest_version_unsupported")
    if manifest.get("submission_blocked") is not True:
        raise DesktopBackupError("backup_submission_not_blocked")
    if manifest.get("report_submission_allowed") is not False:
        raise DesktopBackupError("backup_submission_not_blocked")
    files = manifest.get("files")
    if not isinstance(files, list) or any(not isinstance(item, dict) for item in files):
        raise DesktopBackupError("backup_manifest_files_invalid")
    if files != sorted(files, key=lambda item: item.get("path", "")):
        raise DesktopBackupError("backup_manifest_files_invalid")
    try:
        paths = [item["path"] for item in files]
        for item in files:
            if (
                _archive_name(item["path"]) != item["path"]
                or not isinstance(item["size"], int)
                or item["size"] < 0
                or not isinstance(item["sha256"], str)
                or len(item["sha256"]) != 64
                or any(character not in "0123456789abcdef" for character in item["sha256"])
            ):
                raise DesktopBackupError("backup_manifest_files_invalid")
    except (KeyError, TypeError):
        raise DesktopBackupError("backup_manifest_files_invalid") from None
    if len(paths) != len(set(paths)) or set(paths) != set(names) - {"manifest.json"}:
        raise DesktopBackupError("backup_manifest_files_invalid")
    if "data/bounty-mythos.db" not in paths:
        raise DesktopBackupError("backup_database_missing")
    if any(
        item_path != "data/bounty-mythos.db"
        and not item_path.startswith("workspaces/")
        for item_path in paths
    ):
        raise DesktopBackupError("backup_manifest_files_invalid")


def _archive_name(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise DesktopBackupError("backup_archive_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise DesktopBackupError("backup_archive_path_invalid")
    if ":" in path.parts[0] or value != path.as_posix():
        raise DesktopBackupError("backup_archive_path_invalid")
    return value


def _backup_sqlite(source: Path, destination: Path) -> None:
    with closing(sqlite3.connect(source)) as source_connection:
        with closing(sqlite3.connect(destination)) as destination_connection:
            source_connection.backup(destination_connection)


def _copy_workspaces(source_root: Path, destination_root: Path) -> None:
    if _is_link_or_reparse_point(source_root):
        raise DesktopBackupError("backup_workspace_symlink")
    if not source_root.exists():
        return
    if not source_root.is_dir():
        raise DesktopBackupError("backup_workspace_invalid")
    for current, directories, files in os.walk(source_root, followlinks=False):
        current_path = Path(current)
        for directory in list(directories):
            candidate = current_path / directory
            if _is_link_or_reparse_point(candidate):
                raise DesktopBackupError("backup_workspace_symlink")
            if directory.casefold() in _TRANSIENT_DIRECTORIES:
                directories.remove(directory)
        for filename in files:
            source = current_path / filename
            if _is_link_or_reparse_point(source):
                raise DesktopBackupError("backup_workspace_symlink")
            if not source.is_file():
                raise DesktopBackupError("backup_workspace_file_invalid")
            if source.suffix.casefold() in _TRANSIENT_SUFFIXES:
                continue
            relative = source.relative_to(source_root)
            destination = destination_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def _is_link_or_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_point
    )


def _manifest_entries(staging_root: Path) -> list[dict[str, Any]]:
    entries = []
    total_bytes = 0
    for source in _archive_files(staging_root):
        size = source.stat().st_size
        total_bytes += size
        if total_bytes > MAX_BACKUP_BYTES:
            raise DesktopBackupError("backup_archive_too_large")
        entries.append(
            {
                "path": source.relative_to(staging_root).as_posix(),
                "size": size,
                "sha256": _sha256(source),
            }
        )
    return entries


def _archive_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _alembic_revision(database_path: Path) -> str | None:
    try:
        with closing(sqlite3.connect(database_path)) as connection:
            row = connection.execute("select version_num from alembic_version").fetchone()
    except sqlite3.Error:
        return None
    return str(row[0]) if row else None


def _is_within(parent: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(parent.resolve())
        return True
    except ValueError:
        return False
