# Hunter A+B — Mealie GitHub package

Updated: 2026-07-12T13:42:59Z

## Package
- Path: uthorized_packages/my-gh-mealie
- Package id: my-gh-mealie-recipe-authz-lab
- Upstream: mealie-recipes/mealie **v3.20.1**
- Authorization: public OSS + local static / researcher-owned self-host only

## Why this target
- Highest-value next path after Vikunja: new non-teaching authorized surface
- Recipe object has multi-user owner / household / group ACL (not pure admin-global)
- SECURITY.md private vulnerability reporting present

## Model surface
| Route | Upstream control |
| --- | --- |
| GET /recipes/{slug} | group-scoped repository load (group_id) |
| PUT /recipes/{slug} | _pre_update_check -> can_update (owner / lock / household policy) |
| DELETE /recipes/{slug} | can_delete (owner or admin) |

## Trial
- docs/hunter-ab-mealie-trial.md / docs/hunter-ab-mealie-trial.json
- Result: **3/0 refuted** (decision_quality pass)
- Evidence refs: code:code.ts:owner_id_filter, code:code.ts:group_id_filter

## Residual
Static ML-R1..R4 held. ML-R5 bulk/last-made optional. Live residual optional on researcher loopback only.

## Safety
No production multi-tenant attacks. No auto-submit. No secrets in inputs.
