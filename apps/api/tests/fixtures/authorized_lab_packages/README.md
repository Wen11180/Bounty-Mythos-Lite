# Authorized Lab Packages

These packages are **outside** the locked 24-case candidate hunter release suite.

They exercise the G13 trust gate:

```text
user-supplied authorized local package
  scope + policy + api + har + code
-> candidate hunter loop
-> H1-H7 operator scorecard
```

## Rules

1. Local / user-authorized artifacts only. No public target scanning.
2. `contains_real_user_data: false` and `contains_secrets: false` required.
3. Authorization flag required: `authorized_for_local_research` or `authorized_for_local_benchmark`.
4. Code must use a supported source suffix: `.py`, `.ts`, `.tsx`, `.mts`, `.cts`, `.java`, `.go`, `.rb`, `.cs`, `.php`, `.kt`, `.rs`, or `.scala`.
5. Scope must use `${STAGED_CODE_ROOT}` for `allowed_repos`.
6. Do not register packages into `suite-manifest.json`.
7. Avoid literal text `real user data`, bearer/cookie/token shapes, or external `http(s)://` URLs in package files (fail-closed fixture sanitizer).

## Layout

```text
package-id/
  package.json   # or case.json
  gold.json      # optional
  inputs/
    scope.json
    policy.md
    api.json
    traffic.har.json
    code.ts
```

## Included packages

| Path | Role |
| --- | --- |
| `lab-authz-unguarded-notes/` | G13 harness smoke (retain path) |
| `lab-owasp-bola-invoice-export/` | Educational BOLA package (OWASP A01 pattern derivation; non-suite) |
| `_template/` | Copy-and-fill skeleton for a user-owned package |

## Run smoke

```powershell
$base = "apps\api\.pytest-tmp"; $env:TEMP=$base; $env:TMP=$base; $env:PYTHONPATH="apps\api"
.\.venv\Scripts\python.exe apps/api/scripts/run_ab_operator_trial.py --package-root apps/api/tests/fixtures/authorized_lab_packages/lab-authz-unguarded-notes
```

## Run your package later

1. Copy `_template` to a new directory (outside or under this folder).
2. Replace route/code/policy with authorized local artifacts only.
3. Keep safety flags false.
4. Run:

```powershell
.\.venv\Scripts\python.exe apps/api/scripts/run_ab_operator_trial.py --package-root PATH\TO\YOUR\PACKAGE
```

Without a user-owned package, A+B product trust remains open; engineering harness is ready.
