# Hunter A+B — Vikunja GitHub package

Updated: 2026-07-12T13:10:12Z

## Package
- Path: `authorized_packages/my-gh-vikunja`
- Package id: `my-gh-vikunja-task-authz-lab`
- Upstream: go-vikunja/vikunja **v2.3.0**
- Authorization: public OSS + local static / researcher-owned self-host only

## Why this target
- Highest-value next path after listmonk: new non-teaching authorized surface
- Task object inherits project ownership/write boundary (not pure admin-global)
- README Security Reports private contact present

## Model surface
| Route | Upstream control |
| --- | --- |
| GET /tasks/{id} | Task.CanRead -> Project.CanRead (owner or permission) |
| PUT /tasks/{id} | canDoTask -> Project.CanWrite |
| DELETE /tasks/{id} | canDoTask -> Project.CanWrite |

## Trial
- `docs/hunter-ab-vikunja-trial.md` / `docs/hunter-ab-vikunja-trial.json`
- Result: **3/0 refuted** (decision_quality pass)
- Evidence refs: `code:code.ts:owner_id_filter`

## Residual
Static VK-R1..R4 held. VK-R5 bulk/attachments optional. Live residual optional on researcher loopback only.

## Safety
No production multi-tenant attacks. No auto-submit. No secrets in inputs.

## Note
Operator-trial empty-decision bug fixed: package id containing `task-authz` no longer false-positive secret redaction.
