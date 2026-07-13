# Hunter A+B — HedgeDoc GitHub package

Updated: 2026-07-12T14:11:01Z

## Package
- Path: authorized_packages/my-gh-hedgedoc
- Package id: my-gh-hedgedoc-note-authz-lab
- Upstream: hedgedoc/hedgedoc **v1.11.0**
- Authorization: public OSS + local static / researcher-owned self-host only

## Why this target
- Highest-value next path after NocoDB: new non-teaching authorized surface
- Note object has multi-user permission modes with owner-only private/locked/protected write
- SECURITY.md private OpenPGP reporting present

## Model surface
| Route | Upstream control |
| --- | --- |
| GET notes/{id} | findNote + checkViewPermission (private = owner) |
| PUT notes/{id} | mayEdit (private/locked/protected = owner) |
| DELETE notes/{id} | owner-only for private note model |

## Trial
- docs/hunter-ab-hedgedoc-trial.md / docs/hunter-ab-hedgedoc-trial.json
- Result: **3/0 refuted** (decision_quality pass)
- Evidence refs: code:code.ts:owner_id_filter

## Residual
Static HD-R1..R4 held. HD-R5 permission socket optional. Live residual optional on researcher loopback only.

## Safety
No production multi-tenant attacks. No auto-submit. No secrets in inputs.