# Gitea GT-R3 dual-unit live matrix

Updated: 2026-07-12T18:30:00Z

| Field | Value |
| --- | --- |
| Version | **1.26.4** |
| Host | researcher-owned `127.0.0.1:3002` |
| Repo class | **private** org lab (public would collapse unit gates) |
| Principals | Issues-only team vs Pulls-only team |
| Secrets in docs | **no** |
| Destructive ops | **no** (owner setup writes only; matrix is GET) |

## Hard gates (held)

| Check | Result |
| --- | --- |
| Issues-only → PR JSON / pulls list | **404** |
| Pulls-only → issue JSON / issues list | **404** |
| Unauth private issue | **404** |

## Soft residual (confirmed observation, not a final)

| Check | Result |
| --- | --- |
| Issues-only → PR timeline/assets/subscriptions | **200** while PR issue JSON **404** |
| Pulls-only → issue timeline/assets/subscriptions | **200** while issue JSON **404** |

Matches static handler gap: soft surfaces omit `CanReadIssuesOrPulls(isPull)` re-check after parent OR middleware.

## Disposition

- Residual note upgraded from "not run" → **run + soft residual confirmed**
- Still **not** a confirmed vulnerability report
- Submission remains **blocked**
- Human review required before any claim language

Related:
- `authorized_packages/my-gh-gitea/_extract/RESIDUAL_CHECKLIST.md`
- `docs/hunter-ab-gitea-live-residual-depth.md`
