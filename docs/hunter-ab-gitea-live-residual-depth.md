# Gitea live residual depth scorecard

Updated: 2026-07-12T18:30:00Z

| Check | Result |
| --- | --- |
| Version pin live | **1.26.4** |
| Unauth identity/admin surfaces | **401** fail-closed |
| Missing repo issue family | **404** fail-closed |
| Unauth private repo disclosure | **none observed** (404 / not listed) |
| Public issue family consistency | **200** where expected for public lab issue |
| Protected repo management unauth | **401** (collaborators/hooks/keys/teams) |
| GT-R3 dual-unit matrix | **run** on private org repo (Issues-only vs Pulls-only) |
| GT-R3 hard unit gates | **held** (cross-unit primary JSON 404) |
| GT-R3 soft residual | **confirmed** (timeline/assets/subscriptions 200 vs hard 404) |
| Secrets stored in residual docs | **no** |

Package trial remains: **1/0 refuted** (static faithful model).

Related:
- `docs/hunter-ab-gitea-github-residual.md`
- `docs/hunter-ab-gitea-dual-unit-matrix.md`
- `authorized_packages/my-gh-gitea/_extract/RESIDUAL_CHECKLIST.md`
