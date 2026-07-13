# Hunter A+B — paperless-ngx GitHub package

Updated: 2026-07-12T14:00:13Z

## Package
- Path: uthorized_packages/my-gh-paperless
- Package id: my-gh-paperless-doc-authz-lab
- Upstream: paperless-ngx/paperless-ngx **v2.9.0**
- Authorization: public OSS + local static / researcher-owned self-host only

## Why this target
- Highest-value next path after Mealie: new non-teaching authorized surface
- Document object has multi-user owner / guardian ACL (not pure admin-global)
- SECURITY.md private GitHub Security Advisory reporting present

## Model surface
| Route | Upstream control |
| --- | --- |
| GET /documents/{id} | PaperlessObjectPermissions (owner or view object perm) |
| PUT /documents/{id} | owner or change object perm |
| DELETE /documents/{id} | owner or delete object perm |
| List | ObjectOwnedOrGrantedPermissionsFilter |

## Trial
- docs/hunter-ab-paperless-trial.md / docs/hunter-ab-paperless-trial.json
- Result: **3/0 refuted** (decision_quality pass)
- Evidence refs: code:code.ts:owner_id_filter

## Residual
Static PL-R1..R4 held. PL-R5 bulk/share-link optional. Live residual optional on researcher loopback only.

## Safety
No production multi-tenant attacks. No auto-submit. No secrets in inputs.
