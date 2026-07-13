# Hunter A+B — NocoDB GitHub package

Updated: 2026-07-12T14:07:01Z

## Package
- Path: authorized_packages/my-gh-nocodb
- Package id: my-gh-nocodb-record-authz-lab
- Upstream: nocodb/nocodb **v2026.06.1**
- Authorization: public OSS + local static / researcher-owned self-host only

## Why this target
- Highest-value next path after Immich: new non-teaching authorized surface
- Table records have multi-user base membership + ProjectRoles ACL (VIEWER list vs EDITOR write)
- SECURITY.md private contact security@nocodb.com present

## Model surface
| Route | Upstream control |
| --- | --- |
| GET tables/{id}/records | GlobalGuard + @Acl dataList (ProjectRoles.VIEWER+) |
| PATCH tables/{id}/records | GlobalGuard + @Acl dataUpdate (ProjectRoles.EDITOR+) |
| DELETE tables/{id}/records | GlobalGuard + @Acl dataDelete (ProjectRoles.EDITOR+) |

Base membership modeled as group_id for hunter recognition.

## Trial
- docs/hunter-ab-nocodb-trial.md / docs/hunter-ab-nocodb-trial.json
- Result: **3/0 refuted** (decision_quality pass)
- Evidence refs: code:code.ts:group_id_filter

## Residual
Static NC-R1..R4 held. NC-R5 bulk/nested optional. Live residual optional on researcher loopback only.

## Safety
No production multi-tenant attacks. No auto-submit. No secrets in inputs.