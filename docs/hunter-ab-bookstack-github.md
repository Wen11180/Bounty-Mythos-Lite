# Hunter A+B — BookStack GitHub package

Updated: 2026-07-12T12:54:22Z

## Package
- Path: uthorized_packages/my-gh-bookstack
- Package id: my-gh-bookstack-page-authz-lab
- Upstream: BookStackApp/BookStack **v26.05.2**
- Authorization: public OSS + local static / researcher-owned self-host only

## Why this target
- Firefly III acquisition blocked (GitHub API 403; controller raw paths incomplete)
- BookStack has explicit multi-user page visibility + ownable permission model
- Same non-teaching pattern as Gitea / new-api

## Model surface
| Route | Upstream control |
| --- | --- |
| GET /api/pages/{id} | findVisibleByIdOrFail (scopes visible) |
| PUT /api/pages/{id} | visible load + checkOwnablePermission(PageUpdate) |
| DELETE /api/pages/{id} | visible load + checkOwnablePermission(PageDelete) |

## Trial
- docs/hunter-ab-my-gh-bookstack-trial.md
- Result: **3/0 refuted** (decision_quality pass)

## Residual
Static BS-R1..R4 held. Live residual optional on researcher loopback only (ports 8080/3000/3001/3002 in use).

## Safety
No production multi-tenant attacks. No auto-submit. No secrets in inputs.