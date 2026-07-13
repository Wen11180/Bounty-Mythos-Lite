# Hunter A+B — listmonk GitHub package

Updated: 2026-07-12T12:57:36Z

## Package
- Path: `authorized_packages/my-gh-listmonk`
- Package id: `my-gh-listmonk-campaign-authz-lab`
- Upstream: knadh/listmonk **v6.2.0**
- Authorization: public OSS + local static / researcher-owned self-host only

## Why this target
- Highest-value next path after BookStack: new non-teaching authorized surface
- Campaign object has multi-user list-scoped ACL (not pure admin-global)
- SECURITY.md + security-reports docs present

## Model surface
| Route | Upstream control |
| --- | --- |
| GET campaign/{id} | checkCampaignPerm(get) before body |
| PUT/DELETE campaign/{id} | checkCampaignPerm(manage) |
| Non-all users | CampaignHasLists vs permitted lists |

## Trial
- `docs/hunter-ab-my-gh-listmonk-trial.md`
- Result: **3/0 refuted** (decision_quality pass expected)

## Residual
Static LM-R1..R4 held. Live residual optional on researcher loopback only.

## Safety
No production multi-tenant attacks. No auto-submit. No secrets in inputs.