# Local environment probe + Node residual fill-in

Date: 2026-07-12

## 1. Do you already have residual environments?

| Environment | Found on this machine? | Evidence |
| --- | --- | --- |
| Node.js **runtime** | **Yes** | `v24.15.0` at `C:\Program Files\nodejs\node.exe` |
| Node.js **core source tree** | **No** | no `src/node.cc` / `lib/internal/process/permission.js` clone |
| WordPress Core tree | **No** | no `wp-includes/version.php` |
| GitLab GDK / self-managed source | **No** | no `gdk-config.yml` / gitlab rails tree |
| Docker | Yes | Docker 29.5.3 |
| WSL Ubuntu | Present, **Stopped** | not used for residual this round |
| PHP | No | |
| Ruby | Yes | 3.3.7 (not a GitLab install) |
| Git | Yes | 2.54.0 |

Conclusion: you did not already have a full source residual lab. You **do** have a lawful Node runtime pin suitable for permission-model residual smoke.

## 2. Node residual matrix (runtime pin)

Version pin: **Node.js v24.15.0** (`process.execPath` = Program Files nodejs)

Method: local temp dirs only under `%TEMP%\mythos-node-residual`.  
Allowed dir granted via `--allow-fs-read` / `--allow-fs-write`. Denied sibling dir not granted.  
No network targets, no production hosts.

| ID | Control point | Status | Observed |
| --- | --- | --- | --- |
| NJ-1 | Permission API present when enabled | **present (partial surface)** | with `--permission`, `process.permission` is object with `has`; `drop` not on this surface |
| NJ-2 | FS read gate | **present** | denied path -> `ERR_ACCESS_DENIED` / restricted message |
| NJ-3 | FS write gate | **present** | denied path write -> `ERR_ACCESS_DENIED` |
| NJ-4 | Symlink gate | **not runtime-checked this pass** | needs explicit symlink case; optional follow-up |
| NJ-5 | Grant trees read/write separate | **present (behavior)** | `has('fs.read'/'fs.write')` true only for allowed path |
| NJ-6 | Threat-model / opt-in behavior | **present** | without `--permission`, `process.permission` undefined and denied path is readable/writable |

### Permission-enabled run (summary)

- `hasFsReadAllowed=true`, `hasFsReadDenied=false`
- `hasFsWriteAllowed=true`, `hasFsWriteDenied=false`
- read/write allowed: ok
- read/write denied: fail closed with `ERR_ACCESS_DENIED`

### Baseline without `--permission`

- permission object absent
- both allowed and denied paths succeed (expected: model is opt-in, not default sandbox)

## 3. Residual hypotheses

**None** for bounty-grade core issues from this smoke.

Controls hold on the installed runtime for the checked matrix rows.  
Absence of source tree means we did **not** diff C++/JS implementation paths line-by-line; this is runtime residual, not full SOURCE_FACTS source-diff.

Optional non-vuln notes (do not report as vulns by themselves):

1. `process.permission.drop` not exposed on the observed runtime surface keys (`has` only). Treat as API-surface inventory, not a vulnerability, unless docs claim otherwise for this version.
2. Permission model remains operator opt-in; default Node is not a sandbox (matches SECURITY.md class of statement).

## 4. Gates

| Gate | Result |
| --- | --- |
| R0 Safety | **Pass** (local temp only) |
| R1 Version pin | **Pass** (v24.15.0) |
| R2 Control matrix | **Pass** for NJ-1/2/3/5/6; NJ-4 deferred |
| R3 Hypothesis quality | **Pass** (zero residual claims) |
| R4 Human | pending your glance; submission blocked |

## 5. What this means for Mythos G13

- Still no GitLab/WordPress local instance residual.
- Node path: **runtime residual started and controls hold**.
- Hunter package `my-h1-nodejs` full-refute remains consistent with a guarded permission model.
- Next high-value options:
  1. Optional NJ-4 symlink local check
  2. Shallow clone Node source for line-level SOURCE_FACTS diff (large download; only if you want)
  3. Or stop residual expansion and do H7 human sheet on educational retain packs

Raw machine output kept at `%TEMP%\mythos-node-residual\result.json` (ephemeral temp).
