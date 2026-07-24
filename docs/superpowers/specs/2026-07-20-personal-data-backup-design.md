# Personal Data Backup and Restore Design

Date: 2026-07-20

Status: Approved for implementation for personal, local-only use.

## Goal

Give the desktop application a portable, local backup format for the mutable
research state under Electron `userData`. A backup must be restorable on
another Windows machine without requiring the original installation path,
while preserving the existing loopback-only and submission-blocked rules.

This slice covers backup and restore only. Startup diagnostics, benchmark
fixtures, and the full daily workflow are subsequent slices.

## Scope

Back up these stateful inputs:

- `data/bounty-mythos.db`, captured with SQLite's online backup API.
- The complete `workspaces/` tree, including manifests, report drafts, and
  audit exports.

Exclude caches, lock files, temporary files, Chromium state, build output,
and any file outside the two state roots. The archive is a regular ZIP file
named by the operator with a `.mythos-backup.zip` suffix.

## Archive Contract

The archive contains:

```text
manifest.json
data/bounty-mythos.db
workspaces/...
```

`manifest.json` contains `format_version: 1`, creation time, application
version, the current Alembic revision, a `submission_blocked: true` marker,
and a sorted list of relative file entries with byte size and SHA-256.
Archive paths use `/`, are relative, and may not contain `..`, absolute roots,
or symbolic links. The manifest is generated from the staged files rather
than the live tree.

## Components and Data Flow

1. `app.desktop_backup` owns archive creation, validation, SQLite backup,
   extraction, hashing, and rollback. It has no HTTP or Electron dependency.
2. `desktop_server.py` exposes maintenance modes for `backup` and `restore`
   in addition to its existing server mode. Maintenance modes perform one
   operation and exit without starting Uvicorn.
3. `packaged-runtime.cjs` stops API/Web children, invokes the frozen API
   executable in maintenance mode, and restarts the same children in a
   `finally` path. The existing API/Web ports and loopback checks remain the
   source of truth.
4. Electron main/preload expose only local save/open dialogs and the two
   maintenance operations. The renderer receives a bounded success or fixed
   failure message, never raw archive contents or credentials.

Backup flow:

```text
operator selects local destination
-> Electron stops packaged services
-> frozen API stages SQLite + workspace files
-> manifest and hashes are written
-> ZIP is atomically renamed to destination
-> services restart
```

Restore flow:

```text
operator selects a .mythos-backup.zip and confirms
-> frozen API validates paths, manifest, hashes, and format version
-> current state is saved as a rollback archive
-> staged DB/workspaces replace the live state
-> migrations upgrade the restored DB to the bundled head
-> services restart; rollback is used if replacement or migration fails
```

Backups are portable and are not encrypted by the application in this first
slice. The operator is responsible for storing them on a protected local
volume (for example, BitLocker or an encrypted removable drive). No cloud
upload or automatic sharing is introduced.

## Failure Handling

- Refuse an existing destination unless the operator explicitly chooses an
  overwrite through the save dialog.
- Refuse malformed ZIPs, unsupported format versions, path traversal,
  symlinks, missing manifest entries, hash mismatches, and archives larger
  than the fixed 4 GiB local staging budget.
- Create a pre-restore rollback archive before changing live state.
- If any replacement or migration step fails, restore the rollback state and
  return a fixed `restore_failed_rolled_back` result.
- Never delete the only known copy of the live database or workspace.
- Keep report submission blocked and do not turn restored records into
  execution permission.

## Verification

Python tests cover:

- consistent SQLite backup and workspace inclusion/exclusion;
- manifest hashes and portable relative paths;
- traversal, symlink, malformed archive, and hash mismatch rejection;
- successful restore with migration upgrade;
- failed restore followed by verified rollback.

Desktop tests cover maintenance argument parsing, service stop/restart on
success and failure, local dialog filtering, and the bounded preload bridge.
The packaged smoke test covers a backup followed by restore in a fresh
`userData` directory and verifies both loopback services return afterward.

## Deferred Work

Password-based archive encryption, cloud synchronization, automatic periodic
backups, cross-platform packaging, and backup browsing in the control center
remain out of scope for this personal-use slice.
