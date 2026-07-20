# Personal Data Backup and Restore Implementation Plan

> Execute one phase at a time. Every production behavior starts with a
> focused failing test. Existing Scope Guard, human approval, redaction, and
> submission-blocked contracts are unchanged.

## Phase 0: Verified Contracts

| Need | Existing contract | Source |
| --- | --- | --- |
| Frozen API entry and migration resources | `parse_desktop_server_args`, `build_desktop_environment`, `run_desktop_migrations`, `main` | `apps/api/app/desktop_server.py:16-100` |
| Mutable state locations | `data/bounty-mythos.db` and `workspaces/` under Electron userData | `apps/studio/packaged-runtime.cjs:4-31` |
| Packaged child lifecycle | `createPackagedRuntime().start()` and `.stop()` | `apps/studio/packaged-runtime.cjs:52-132` |
| Local path selection | `selectStudioFile` and `selectStudioDirectory` return one path and read no contents | `apps/studio/path-dialog.cjs:1-27`, `apps/studio/path-dialog.test.cjs` |
| Renderer bridge boundary | context-isolated `mythosStudio` preload API | `apps/studio/preload.cjs:1-36` |
| Desktop startup | start services, wait for API/Web, then load Studio | `apps/studio/main.cjs:180-218` |
| Workspace writes | manifest and report exports use workspace-relative paths | `apps/api/app/studio_workspace.py:121-154`, `737-850`, `994-1005` |

### Allowed APIs

- Python standard library `sqlite3.Connection.backup`, `zipfile`, `hashlib`,
  `tempfile`, `shutil`, and `os.replace`.
- Existing Alembic `command.upgrade` seam in `desktop_server.py`.
- Existing Node `child_process.spawn`/`execFileSync` and Electron IPC/path
  dialog seams.
- Existing Studio `ActionButton` and desktop bridge type in
  `apps/web/app/studio/studio-workbench.tsx:90-106`.

### Guards

- Do not copy a live SQLite file byte-for-byte.
- Do not extract ZIP entries before validating normalized relative paths and
  rejecting links.
- Do not replace state while API/Web children are running.
- Do not accept a remote URL, shell command, or renderer-supplied file
  contents; only local paths selected by the main process are allowed.
- Do not include caches, locks, temporary files, raw credentials, cookies,
  authorization headers, or real-user data outside the user's existing local
  research state.
- Do not alter validation execution, Scope Guard, approval, or report gates.

## Phase 1: Archive Core (RED/GREEN)

### Files

- Add `apps/api/app/desktop_backup.py`.
- Add `apps/api/tests/test_desktop_backup.py`.

### RED tests

1. A SQLite database is captured through a consistent backup and can be
   opened from the archive after the source connection changes.
2. Workspace files and manifest/report exports are included; cache, lock,
   temporary, symlink, and out-of-scope files are excluded or rejected.
3. The manifest has format version 1, application version, Alembic revision,
   fixed submission-blocked state, sorted POSIX paths, sizes, and SHA-256.
4. Archive creation refuses an existing destination, traversal paths, and a
   staged archive over the fixed 4 GiB limit.
5. A malformed archive, unsupported version, missing entry, or hash mismatch
   is rejected before any live state changes.

### GREEN implementation

1. Stage `data/bounty-mythos.db` with `sqlite3.Connection.backup` into a
   temporary directory below the user-data parent.
2. Copy only regular files below `workspaces/`, filtering the explicit
   transient-name/suffix set; reject symlinks instead of following them.
3. Build the manifest from staged files, write it deterministically, and
   atomically rename the completed ZIP into the operator destination.
4. Keep all archive paths POSIX-relative and enforce the 4 GiB byte budget
   while staging and while reading an archive.

### Verify

```powershell
Set-Location apps/api
& .\.venv\Scripts\python.exe -m pytest -q tests/test_desktop_backup.py
```

## Phase 2: Restore, Rollback, and Migration Backup

### Files

- Extend `apps/api/app/desktop_backup.py`.
- Extend `apps/api/app/desktop_server.py`.
- Extend `apps/api/tests/test_desktop_backup.py` and
  `apps/api/tests/test_desktop_server.py`.

### RED tests

1. A valid portable archive restores the database and workspace and upgrades
   the restored database to the bundled migration head.
2. Restore creates a pre-restore rollback archive before replacing state.
3. A replacement or migration failure restores the rollback state and emits
   only `restore_failed_rolled_back`.
4. Existing databases receive a pre-migration backup before startup upgrade;
   a new empty database does not create a meaningless backup.
5. Maintenance argument parsing requires exactly one operation and its local
   path, while normal server startup remains backward compatible.

### GREEN implementation

1. Add `--maintenance {backup,restore}`, `--destination`, and `--archive`
   modes to the frozen API entry; maintenance exits before Uvicorn.
2. Validate and extract into a temporary sibling, create the rollback archive,
   replace database/workspaces with `os.replace`, then run Alembic head.
3. On any post-replacement exception, restore the rollback staging tree and
   return the fixed failure result.
4. Call the pre-migration backup only when a non-empty database already
   exists, and fail closed if that backup cannot be created.

### Verify

```powershell
Set-Location apps/api
& .\.venv\Scripts\python.exe -m pytest -q tests/test_desktop_backup.py tests/test_desktop_server.py
```

## Phase 3: Packaged Runtime Maintenance Lifecycle

### Files

- Extend `apps/studio/packaged-runtime.cjs`.
- Extend `apps/studio/packaged-runtime.test.cjs`.

### RED tests

1. `createBackup(destination)` stops both children, invokes the frozen API
   maintenance command with loopback/userData/resource arguments, restarts
   both services, and returns a bounded result.
2. `restoreBackup(archive)` follows the same lifecycle and restarts even when
   the maintenance command fails.
3. Development runtime refuses packaged maintenance rather than invoking a
   system Python/Node executable.
4. Destination and archive paths remain local values passed as arguments,
   never shell strings.

### GREEN implementation

1. Store the active launch config in `createPackagedRuntime`.
2. Add a non-shell `execFileSync` maintenance helper using the packaged API
   executable and the exact flags from Phase 2.
3. Stop/restart in `try/finally`; preserve the existing child cleanup and
   loopback assertions.

### Verify

```powershell
Set-Location apps/studio
node --test packaged-runtime.test.cjs
```

## Phase 4: Electron Bridge and Personal UI Entry

### Files

- Extend `apps/studio/path-dialog.cjs`, `path-dialog.test.cjs`.
- Extend `apps/studio/main.cjs`, `preload.cjs`, and desktop-shell tests.
- Extend `apps/web/app/studio/studio-workbench.tsx` and its focused tests.
- Extend E2E bridge fixtures only where the new optional methods require it.

### RED tests

1. Save dialog filters `.mythos-backup.zip` and returns one local path.
2. Restore dialog filters the same suffix and asks for explicit confirmation.
3. Preload exposes bounded `createBackup`/`restoreBackup` methods without file
   reads, writes, shell, or spawn access.
4. Main handlers reject missing packaged runtime and map failures to fixed
   review-safe messages.
5. Studio renders one compact data-recovery control with backup/restore states
   and does not add validation or report-submission controls.

### GREEN implementation

1. Add save/open dialog helpers and IPC handlers that pass only selected paths.
2. Add preload methods and typed optional bridge members.
3. Add a small Studio data-recovery section using existing controls; browser
   mode remains functional when the desktop bridge is absent.

### Verify

```powershell
Set-Location apps/studio
node --test path-dialog.test.cjs desktop-shell.test.cjs packaged-runtime.test.cjs

Set-Location ../web
npm test -- --test-name-pattern "backup|restore|desktop bridge|studio workbench"
```

## Phase 5: Packaged Smoke and Full Regression

1. Build the frozen runtime and Windows package with the existing command.
2. In a fresh userData directory, create a backup, mutate a disposable
   workspace, restore it, and verify API/Web return 200 after restart.
3. Verify the archive contains no caches, links, credentials, or build files;
   verify rollback remains available after restore.
4. Run API, Web, Studio, lint, build, bundle, and E2E suites.
5. Run `git diff --check` and exact safety greps for loopback binding,
   submission blocking, and renderer isolation.

## Completion Evidence

This slice is complete only when the archive unit tests, maintenance/runtime
tests, UI tests, packaged backup/restore smoke, and full regression suites all
pass with no service or test processes left running.
