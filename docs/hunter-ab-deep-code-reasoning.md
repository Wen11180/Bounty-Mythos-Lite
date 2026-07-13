# Deep Code Reasoning (V4 first-class)

Status: **green** (package-ingest plan/export only)

## What it is

First-class permission-model and cross-file (controller -> service -> DAO) deep
code reasoning planner for the factory bridge path. Complements variant
analysis and vuln chain builder with structured path plans, evidence needs,
and human refutation questions ? never execution.

- Inputs: hypotheses, retained candidates, report drafts, confirmed findings,
  residual gates, optional vuln_chain_builder chains / variant_analysis
  variants, offline `inputs/deep_code*.json` / `permission*.json` /
  `cross_file*.json` / `reasoning*.json`
- Outputs: permission models + multi-layer cross-file path plans with evidence
  needs, broken-invariant notes, safe validation outlines (plan only)
- Optional export under package `_export/deep_code_reasoning/` with
  `--allow-deep-code-reasoning-export`

## Safety floor (always false)

- execution_allowed
- validation_allowed
- report_submission_allowed
- confirmed_vulnerability
- finding_promotion_allowed
- network_access
- live_validation
- process_spawn_allowed

## Wiring

| Surface | Detail |
| --- | --- |
| Module | `apps/api/app/deep_code_reasoning/__init__.py` |
| Bridge | `attach_deep_code_reasoning_to_bridge_result` after vuln chain builder, before first deeper MEV |
| CLI | `--allow-deep-code-reasoning-export` |
| Console | `dcr=` / `dcrn=` / `dcrpm=` / `dcrs=` / `dcrx=` |
| MEV | `ENGINE_DEEP_CODE_REASONING` + `signal_from_deep_code_reasoning` |
| Scheduler | **T-013d** / **B-010d** (`deep_code_reasoning_agent`); T-014/T-015 depend on T-013d |
| Tests | `apps/api/tests/test_deep_code_reasoning.py` |

## Dual-lab smoke (after this slice)

| Package | dcr status | paths | permission_models | mevenc |
| --- | --- | --- | --- | --- |
| my-local-ssrf-retain | plan_ready | 14 | 1 | **30** |
| my-gh-mealie-inject | plan_ready | 16 | 1 | **29** |

(Previous post-VCB baseline: 29 / 28.)

## Not claimed

- Not live e2e / H1 submission (H1 still `blocked_401`)
- Not confirmed vulnerabilities
- Not auto-validation or auto-submit
- Nested deep_research PermissionModel / `_cross_file_reasoning` stubs remain
  present but are superseded for the factory attach path by this module
