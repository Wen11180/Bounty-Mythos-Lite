# Hunter A+B — Plane GitHub package

Updated: 2026-07-12T14:28:00Z

## Package
- Path: authorized_packages/my-gh-plane
- Package id: my-gh-plane-issue-authz-lab
- Upstream: makeplane/plane **v1.3.1**
- Authorization: public OSS + local static / researcher-owned self-host only

## Why this target
- Highest-value next path after Documenso: new non-teaching authorized surface
- Issue object has multi-user project role + creator (created_by) ACL
- SECURITY.md private contact security@plane.so present

## Model surface
| Route | Upstream control |
| --- | --- |
| GET issues/{id} | allow_permission ADMIN/MEMBER/GUEST or creator |
| PATCH issues/{id} | allow_permission ADMIN/MEMBER or creator |
| DELETE issues/{id} | allow_permission ADMIN or creator |

Project membership modeled as group_id.

## Trial
- docs/hunter-ab-plane-trial.md / docs/hunter-ab-plane-trial.json
- Result: **3/0 refuted** (decision_quality pass)
- Evidence refs: code:code.ts:owner_id_filter

## Residual
Static PLANE-R1..R4 held. PLANE-R5 guest list filter optional. Live residual optional on researcher loopback only.

## Safety
No production multi-tenant attacks. No auto-submit. No secrets in inputs.