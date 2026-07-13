# Extracted facts from public Node.js core sources

Fetched for local authorized research under HackerOne nodejs core SOURCE_CODE scope.
Upstream files stored under _upstream/ (not loaded by Mythos package inputs).

## permission.js (internal/process/permission)
- isEnabled(): true when --permission or --permission-audit is set
- has(scope, reference): validates scope/reference then delegates to binding permission.has
- drop(scope, reference): revokes grants
- availableFlags include --allow-fs-read, --allow-fs-write, --allow-net, --allow-worker, etc.

## perm_fs_permission.cc (FSPermission)
- Separate grant trees for read (in) and write (out)
- GrantAccess / RevokeAccess / RebuildTree maintain radix path sets
- is_granted(env, perm, param):
  - kFileSystem requires allow_all_in_ && allow_all_out_
  - kFileSystemRead: empty param -> allow_all_in_; else !deny_all_in_ && (allow_all_in_ || tree lookup)
  - kFileSystemWrite: analogous for out tree
- Path grants support directory wildcard forms

## fs.js permission gates (public API surface)
- Path-based stats/reads check permission.isEnabled() && !permission.has('fs.read', path) then ERR_ACCESS_DENIED
- Symlink APIs require permission.has('fs') (full read+write) when permission model enabled
- Several fd-based APIs are disabled entirely when permission model is enabled (fdatasync/fsync/fchmod/fchown/futimes class)

## SECURITY.md Permission Model Boundaries
- Permission model is opt-in blast-radius reduction for trusted application code, not a sandbox vs intentional misuse
- Operator-controlled flags are operator responsibility
- realpath/symlink resolution to an already-allowed path is intended behavior, not a bypass
- worker_threads inherit parent permission restrictions; empty execArgv does not grant extra rights
- node:vfs is not a security boundary

## Research implications for local core review
1. Core fs path operations are not unguarded id/path-to-sink paths when --permission is enabled: they consult fs.read/fs.write grants.
2. Faithful modeling should REFUTE naive missing-ownership/missing-auth claims if owner boundary + path grants are present in the model.
3. Residual research value is version drift, alternate bindings, incomplete grants, or threat-model edge cases documented as non-vuln vs true core bugs.
4. Website and third-party npm issues are out of this package and often out of program/IBB eligibility.
