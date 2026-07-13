# Hunter A+B — Joplin Server GitHub package

## Package
- Path: `authorized_packages/my-gh-joplin`
- package_id: `my-gh-joplin-note-authz-lab`
- Upstream: laurent22/joplin (packages/server)
- Version pin: **v3.7.1**
- Expected disposition: **refute**

## Model
Item get/delete via `user_items` membership + `owner_id` + shared-item `checkIfAllowed`; share get via `owner_id`.

## Trial
- `docs/hunter-ab-joplin-trial.json` / `.md`
- **3 decisions / 0 finals / all refuted** / decision_quality **pass**
- Evidence refs: `code:code.ts:owner_id_filter`

## Residuals
See `authorized_packages/my-gh-joplin/_extract/RESIDUAL_CHECKLIST.md` (JP-R1..R5).

## Notes
- Live residual only on researcher-owned self-hosted Joplin Server.
- Security contact: GitHub private vulnerability reporting with PoC.