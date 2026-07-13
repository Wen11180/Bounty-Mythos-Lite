# RESIDUAL_CHECKLIST — my-local-dvwa

| ID | Expected (low / impossible) | Local observe | Residual hypothesis? |
| --- | --- | --- | --- |
| DV-FI-1 | low: unguarded include of page param | present in container source | no (known lab intentional) |
| DV-FI-2 | impossible: allow-list | present in container source | no |
| DV-CSRF-1 | low: no token | present | no (known lab intentional) |
| DV-CSRF-2 | impossible: token + current password | present | no |
| DV-ID-1 | low: id param without ownership | present | no (known lab intentional) |

Fill date: 2026-07-12
Method: read-only `docker exec` of container PHP sources; no live exploit payloads against the service.
Result: **0 unexpected residual** beyond intentional DVWA teaching defects. Package hunter trial expects retain on unguarded modeled paths.