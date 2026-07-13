# Gitea GitHub package residual

Updated: 2026-07-12T17:45:00Z

Package: `authorized_packages/my-gh-gitea`
Trial: 1 decision / 0 finals / refuted (faithful issue GET guards)
Local pin: Docker `gitea/gitea:1.26.4` @ `127.0.0.1:3002` (researcher-owned)

## What this proves
- A+B can acquire authorized research material from **public GitHub OSS** without H1 API.
- Faithful modeling of Gitea issue read path refutes naive missing-ownership claims.
- Owned-instance pin confirms runtime version matches release **1.26.4**.
- Live residual depth: unauth fail-closed + public-issue family consistency + private-repo non-disclosure.

## Residual results (GT-R1..R5)

| ID | Result |
| --- | --- |
| GT-R1 | **held** — GetIssueWithAttrsByIndex(repo.ID, index) |
| GT-R2 | **held** — CanReadIssuesOrPulls before JSON |
| GT-R3 | **mostly held** — comments/search/deps/reactions re-check; soft multi-unit nuance still needs dual-unit account matrix |
| GT-R4 | **held** — public-only token fail-closed on private repo issue (prior local check) + unauth private guess 404 |
| GT-R5 | **held** — composite repoID+index / GetCommentWithRepoID |

Details: `authorized_packages/my-gh-gitea/_extract/RESIDUAL_CHECKLIST.md`

## Live residual depth (2026-07-12, researcher-owned loopback)

Non-destructive GET only. No credentials used this pass. No secrets stored. Base: `http://127.0.0.1:3002`.

### A. Unauth / missing-target fail-closed

| Path | Status | Notes |
| --- | --- | --- |
| GET /api/v1/version | **200** | `{"version":"1.26.4"}` pin confirmed |
| GET /api/v1/user | **401** | unauthenticated fail-closed |
| GET /api/v1/user/repos | **401** | |
| GET /api/v1/user/orgs | **401** | |
| GET /api/v1/user/emails | **401** | |
| GET /api/v1/notifications | **401** | |
| GET /api/v1/admin/users | **401** | |
| GET /api/v1/admin/orgs | **401** | |
| GET /api/v1/admin/emails | **401** | |
| GET /api/v1/repos/search?limit=10 | **200** | public only; private_visible=0 |
| GET /api/v1/settings/api|attachment|repository|ui | **200** | public settings metadata only |
| GET /api/v1/repos/nosuch/nosuch/* issue family | **404** | issues/comments/timeline/assets/subscribers/deps/blocks/reactions |
| GET /api/v1/repos/nosuch/nosuch/pulls/1 | **404** | |
| Private-name guesses (no auth) | **404** | no private metadata leak |

### B. Public lab repo issue family (expected readable)

Lab fixture repo present on owned instance (public). Status codes only; bodies not stored in residual docs.

| Relative path under public lab repo | Status | Notes |
| --- | --- | --- |
| (repo root) | **200** | public metadata |
| /issues | **200** | list |
| /issues/1 | **200** | issue JSON present |
| /issues/1/comments | **200** | empty or list |
| /issues/1/timeline | **200** | empty/list (no unauth crash) |
| /issues/1/assets | **200** | |
| /issues/1/dependencies | **200** | |
| /issues/1/blocks | **200** | |
| /issues/1/reactions | **200** | |
| /issues/1/labels | **200** | |
| /issues/1/subscribers | **404** | route/not-found class (not a body leak) |
| /pulls | **200** | empty list |
| /pulls/1 | **404** | no PR at index 1 |
| /contents /branches | **200** | public content surfaces |
| /collaborators /hooks /keys /teams | **401** | unauth protected management |

### C. GT-R3 multi-unit soft note (unchanged honesty)

Static review still shows timeline/assets/subscribers may omit handler-level `CanReadIssuesOrPulls(isPull)` and rely on parent unit middleware (Issues **or** Pulls).

**Live status this pass:** only unauth + public-issue family exercised. **No dual-unit account matrix** (Issues-only vs Pulls-only principal) was available without storing credentials in the residual workflow. Soft residual remains **documented, not confirmed vuln, not a final**.

### D. users/search privacy residual (documented)

Unauth `GET /api/v1/users/search` returns **200** with user objects. Field set may include `email` depending on instance user privacy settings. Residual rule: **do not store email values or usernames beyond necessary lab labels in Mythos packages**. Treat as product privacy configuration residual, not automatic bounty without policy review.

### E. Probe hygiene

Timeouts under multi-request PowerShell bursts are **not** security findings. Prefer single requests with short timeout.

## Security disclosure path
If a real residual is ever confirmed on researcher-owned instance / public source:
report privately to security@gitea.io (SECURITY.md). Mythos remains submission-blocked.

## Do not
- Attack third-party Gitea hosts
- Invent unguarded package inputs contradicting SOURCE_FACTS
- Store raw tokens, cookies, or real emails from local instance in package docs
- Treat soft multi-unit nuance as confirmed bounty without dual-unit evidence matrix