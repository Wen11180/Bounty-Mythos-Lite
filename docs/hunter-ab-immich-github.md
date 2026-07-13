# Hunter A+B — Immich GitHub package

Updated: 2026-07-12T14:02:21Z

## Package
- Path: uthorized_packages/my-gh-immich
- Package id: my-gh-immich-asset-authz-lab
- Upstream: immich-app/immich **v2.7.5**
- Authorization: public OSS + local static / researcher-owned self-host only

## Why this target
- Highest-value next path after paperless: new non-teaching authorized surface
- Asset object has multi-user owner / album / partner ACL (not pure admin-global)
- SECURITY.md private contact security@immich.app present

## Model surface
| Route | Upstream control |
| --- | --- |
| GET /assets/{id} | requireAccess AssetRead (owner/album/partner) |
| PUT /assets/{id} | requireAccess AssetUpdate (owner only) |
| DELETE assets | requireAccess AssetDelete (owner only) |

## Trial
- docs/hunter-ab-immich-trial.md / docs/hunter-ab-immich-trial.json
- Result: **3/0 refuted** (decision_quality pass)
- Evidence refs: code:code.ts:owner_id_filter

## Residual
Static IM-R1..R4 held. IM-R5 bulk/metadata optional. Live residual optional on researcher loopback only.

## Safety
No production multi-tenant attacks. No auto-submit. No secrets in inputs.
