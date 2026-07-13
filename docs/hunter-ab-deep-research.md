# Deep Research (V4 multi-stage plan industrializer)

## Purpose

Final-scheme V4 Deep Research:

- Build **plan-only** multi-stage vulnerability chains, variant analysis, long-horizon queues, refutation matrices
- Optional patch-diff advisory learning + knowledge artifacts (`v4_advisory_knowledge`)
- Optional offline config under package `inputs/`
- Optional export under `package/_export/deep_research/` with human flag
- **Never** executes chains, never exploits/PoCs, never auto-validates, never submits, never grants ranking permission

This slice industrializes the existing `build_deep_research_plan` core onto the A+B report bridge residual stack while live H1 e2e human gates remain blocked (`h1_api=blocked_401`).

## Safety floor

Always forced false / blocked:

- `execution_allowed`
- `validation_allowed`
- `report_submission_allowed`
- `confirmed_vulnerability`
- `finding_promotion_allowed`
- `ranking_permission_granted`
- `network_access`
- `live_validation`
- exploit / PoC generation

## Offline ingest paths

| Path | Role |
| --- | --- |
| `inputs/deep_research.json` | Preferred plan context |
| `inputs/deep_research/plan.json` | Split plan file |
| `inputs/v4_deep_research.json` | Alias for V4 context |
| `inputs/deep_research/*.json` | Split fragments |

Bridge also derives hypotheses from package `drafts` + non-FP residual gates when offline artifacts are absent.

## Pipeline position

```text
agent memory (T-010)
  -> continuous scan (T-011)
  -> patch validation (T-012)
  -> deep research (T-013)  [this module]
  -> final MEV re-deepen (includes deep_research engine)
```

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# default: dres=deep_research_plan_ready (or waiting/empty) with dresc/dresv/dresu/dresx

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> \
  --allow-deep-research-export
# writes package/_export/deep_research/<stamp>/ ; still never executes/exploits
```

Console fields: `dres`, `dresc`, `dresv`, `dresu`, `dresx`.

## Multi-engine

Engine id: `deep_research` (`ENGINE_DEEP_RESEARCH`).

`signal_from_deep_research` is advisory plan evidence only. Unsafe execute / validate / submit / ranking flags force blocked.

Dual-lab smoke after this slice: `mevenc=19`, both packages `submission_blocked=True`.

## Scheduler

- **T-013** `deep_research_agent` depends on `T-006b,T-010,T-011,T-012`
- **B-010** parallel batch: `["T-013"]`
- status `advisory_plan_ready`, `execution_allowed=False`
- Never unlocks submit or execution

## Module API

- `run_deep_research(...)` / `build_deep_research(...)`
- `attach_deep_research_to_bridge_result(...)`
- `build_deep_research_plan(...)` (core V4 planner)
- `build_knowledge_artifact(...)` → `artifact_type=v4_advisory_knowledge`, `status=requires_human_review`

## Tests

`apps/api/tests/test_deep_research.py`

Focused residual suite (deep_research + continuous_scan + patch_validation + agent_memory + human_gate + scheduler + multi_engine): **57 passed**.

Verified: 2026-07-12T19:37:34Z