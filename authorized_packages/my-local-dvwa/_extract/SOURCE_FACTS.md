# SOURCE_FACTS — local DVWA (mythos-dvwa)

Pin: container `mythos-dvwa` image `vulnerables/web-dvwa`, bound 127.0.0.1:8080.
Authorization class: researcher-owned intentionally vulnerable local lab (DVWA).
Not a public production target. Not a bounty submission package.

## Control points observed in container sources

| ID | Module | Level | Observation |
| --- | --- | --- | --- |
| DV-FI-1 | File Inclusion | low | `$file = $_GET['page']` then `include($file)` with no allow-list |
| DV-FI-2 | File Inclusion | impossible | allow-list only include.php / file1..3.php before include |
| DV-CSRF-1 | CSRF password change | low | password update with no anti-CSRF token check |
| DV-CSRF-2 | CSRF password change | impossible | checkToken + current password + prepared statements |
| DV-ID-1 | SQLi user lookup | low | `user_id` from request used in query with no ownership boundary (also injection class) |
| DV-AUTH-1 | page startup | all lab modules | `dvwaPageStartup(authenticated)` — session required, not object ownership |

## Modeling choice for hunter package

Hunter A+B currently scores authorization / object-ownership style gaps best on TS Express-shaped sinks (`send_file` / `export_file` / `update` / `delete` without `verify_*_access`).

Package `inputs/code.ts` models:

1. **Retain surface**: low-level user record read/export by id with **no** ownership guard (DV-ID-1 class, object access).
2. **Retain surface**: low-level profile update sink without CSRF/state-change guard modeled as unguarded update (DV-CSRF-1 class, state change).
3. **Refute surface**: impossible-level allow-listed include path with verify helper (DV-FI-2 class).

Raw PHP excerpts stay in `_upstream/` for residual compare only.

## Residual questions (local only)

1. Is security cookie still low for the researcher session under test?
2. Does impossible mode still enforce the FI allow-list?
3. Are any alternate include entrypoints outside vulnerabilities/fi/index.php?
4. No remote host, no real user data, no auto-submit.

## Trial result (2026-07-12)

- Package simplified to single unguarded export sink for decision quality.
- Operator trial: finals=1 retain; safety blocked; submission blocked.
