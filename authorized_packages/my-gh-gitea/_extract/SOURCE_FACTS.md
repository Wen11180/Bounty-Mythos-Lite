# SOURCE_FACTS — Gitea (go-gitea/gitea)

Authorization class: public GitHub open-source + researcher-owned self-hosted instance (loopback only).
Not a public multi-tenant SaaS attack package. Report submission blocked in Mythos by default.
Upstream security contact: security@gitea.io

## Version pin

- Release / Docker: **v1.26.4** (`gitea/gitea:1.26.4`)
- Local pin: `127.0.0.1:3002` container `mythos-gitea`; `GET /api/v1/version` => **1.26.4**
- Static excerpts: `tmp/gitea_upstream_v1.26.4/` from tag **v1.26.4**
- Research mode: static modeling + optional non-destructive owned-instance checks

## Control points (issue read path)

| ID | Control | Observation (v1.26.4) |
| --- | --- | --- |
| GT-1 | Repo assignment | API issue group uses `repoAssignment()` before handlers |
| GT-2 | Issue load scope | `GetIssueWithAttrsByIndex(ctx, ctx.Repo.Repository.ID, index)` / `GetIssueByIndex(repoID, index)` — composite key, not global index |
| GT-3 | Unit permission | `GetIssue`: `ctx.Repo.CanReadIssuesOrPulls(issue.IsPull)` before JSON; deny => not found |
| GT-4 | Pull vs issue unit | `CanReadIssuesOrPulls` maps isPull -> TypePullRequests else TypeIssues |
| GT-5 | Token scopes | Issue group: `tokenRequiresScopes(Issue)` + `checkTokenPublicOnly()`; PublicOnly fails closed on private repos |
| GT-6 | Not-found fail mode | missing issue / missing unit read typically API not found (no body leak) |
| GT-7 | Comments | `GetCommentWithRepoID(repoID, id)` + CanReadIssuesOrPulls on comment.Issue |
| GT-8 | Search | SearchIssues builds accessible repo ID list; ApplyPublicOnly on public-only tokens |
| GT-9 | Cross-repo deps | dependency/block lists re-check permission per other repo |

## Soft residual (not a confirmed vulnerability)

Handlers that load issue by repo-scoped index but omit isPull unit re-check (timeline, attachments via getIssueFromContext, some subscription reads) still sit under `mustEnableIssuesOrPulls` (Issues **or** Pulls). Difference vs GetIssue only matters when unit permissions are split. Not modeled as hunter final without multi-unit evidence.

## Research implication

Faithful issue GET path is **repository-scoped + unit-permission gated**.
Naive missing object ownership check on issue index candidates should **refute**.
Residual GT-R1..R5 closed on v1.26.4 pin except soft multi-unit nuance under R3 (optional future matrix).

Updated: 2026-07-12T11:01:17Z
