# Hunter A+B — Documenso GitHub package

Updated: 2026-07-12T14:20:00Z

## Package
- Path: authorized_packages/my-gh-documenso
- Package id: my-gh-documenso-document-authz-lab
- Upstream: documenso/documenso **v2.14.0**
- Authorization: public OSS + local static / researcher-owned self-host only

## Why this target
- Highest-value next path after HedgeDoc: new non-teaching authorized surface
- Document/envelope has multi-user owner OR team membership + visibility map ACL
- SECURITY.md private GitHub advisory / security@documenso.com present

## Model surface
| Route | Upstream control |
| --- | --- |
| GET documents/{id} | getEnvelopeWhereInput (owner or team visibility) |
| PUT documents/{id} | updateEnvelope via getEnvelopeById |
| DELETE documents/{id} | hasDeleteAccess via getEnvelopeWhereInput |

## Trial
- docs/hunter-ab-documenso-trial.md / docs/hunter-ab-documenso-trial.json
- Result: **3/0 refuted** (decision_quality pass)
- Evidence refs: code:code.ts:owner_id_filter

## Residual
Static DG-R1..R4 held. DG-R5 recipient self-hide optional. Live residual optional on researcher loopback only.

## Safety
No production multi-tenant attacks. No auto-submit. No secrets in inputs.