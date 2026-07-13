# A+B Local Residual — DVWA (mythos-dvwa)

Date: 2026-07-12
Package: `authorized_packages/my-local-dvwa`
Method: read-only `docker exec` of container PHP sources; hunter trial on modeled excerpt.
No live exploit payloads, no credential stuffing, no internet target.

## Version pin

| Field | Value |
| --- | --- |
| Container | `mythos-dvwa` |
| Image | `vulnerables/web-dvwa` |
| Bind | `127.0.0.1:8080` only |
| Auth class | researcher-owned intentionally vulnerable lab |

## Control matrix

| ID | Control / defect | Observed | Unexpected residual? |
| --- | --- | --- | --- |
| DV-FI-1 | FI low: unguarded `page` include | present | no (intentional lab) |
| DV-FI-2 | FI impossible: allow-list | present | no |
| DV-CSRF-1 | CSRF low: no token on password change | present | no (intentional lab) |
| DV-CSRF-2 | CSRF impossible: token + current password | present | no |
| DV-ID-1 | SQLi/id low: id param without ownership | present | no (intentional lab) |

## Hunter trial link

- Scorecard: `docs/hunter-ab-my-local-dvwa-trial.md`
- Result: **1 retained** final on modeled export path; safety flags fail-closed
- Read: pipeline can retain real local-lab unguarded modeling; residual does not invent production vulns

## Stop conditions honored

1. Local lab only
2. No real user private data in package
3. No auto validation / submit
4. Teaching defects labeled intentional, not bounty claims