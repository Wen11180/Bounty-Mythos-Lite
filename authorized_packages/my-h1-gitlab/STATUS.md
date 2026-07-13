# my-h1-gitlab status

## Acquisition push result
- Public CE-style sources fetched to `_upstream/` (export, helpers, repositories, snippets)
- Faithful guarded modeling written to `inputs/code.ts`
- Residual paths added: export_relations, repository archive, job-auth hooks
- Trial: loop=ready, decisions=5, **finals=0**, all **refuted**

## Product read
G13 advanced:
- Source-backed package demonstrates correct refute behavior on expanded surface
- Not just scaffold retain demo

Still open only for live instance residual verification, not for "can we load a real authorized package".

Residual: see `_extract/RESIDUAL_CHECKLIST.md` and `docs/hunter-ab-residual-runbook.md`.

## Local residual (Docker CE 19.1.0) 2026-07-12

- Container `gitlab-test` / `gitlab/gitlab-ce:latest` / CE **19.1.0**
- Static residual: GL-1..GL-7 **present**; **zero residual hypotheses**
- Report: `docs/hunter-ab-gitlab-local-residual.md`
- Method: read-only inspection of container Rails API sources (no live exploit exercise)
