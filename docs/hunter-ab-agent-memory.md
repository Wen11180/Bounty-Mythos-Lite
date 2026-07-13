# Agent Memory (V3 advisory ranking)

## Purpose

Final-scheme V3 Agent Memory (scheme ?5.x / ?7 knowledge / V3 continuous intelligence):

- Ingest offline package memory/knowledge artifacts under `inputs/`
- Derive FP / retain / severity-hint signals from bridge residual gates + drafts + multi-engine posture
- Emit **candidate rank hints only** (`action_hint=human_review_priority_only`)
- Optional export under `package/_export/agent_memory/` with human flag
- **Never** grants execution, validation, submit, promote, or `ranking_permission_granted`

This slice advances the factory while live H1 e2e human gates remain blocked (`h1_api=blocked_401`).

## Safety floor

Always forced false / blocked:

- `execution_allowed`
- `validation_allowed`
- `report_submission_allowed`
- `confirmed_vulnerability`
- `finding_promotion_allowed`
- `ranking_permission_granted`
- `live_validation`
- `network_access`

Secret-like text in offline artifacts is scrubbed before retention.

## Offline ingest paths

| Path | Role |
| --- | --- |
| `inputs/agent_memory.json` | Preferred memory bundle |
| `inputs/memory.json` | Alternate memory bundle |
| `inputs/knowledge.json` | Knowledge patterns |
| `inputs/memory/*.json` | Split memory files |
| `inputs/knowledge/*.json` | Split knowledge files |

Bridge-derived entries are merged with offline artifacts (deduped by topic/kind).

## Pipeline position

```text
report draft (T-007)
  -> residual runner (T-007b)
  -> multi-engine deepen (T-006b)
  -> offline human-gate dry-run (T-009)
  -> agent memory (T-010)  [this module]
  -> final MEV re-deepen (includes agent_memory engine)
```

## Bridge

```text
python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg>
# default: amem=agent_memory_ready (or empty) with amenn/amemfp/amemh/amemx

python apps/api/scripts/run_ab_report_bridge.py --package-root <authorized_pkg> \
  --allow-agent-memory-export
# writes package/_export/agent_memory/<stamp>/ ; still never execute/submit
```

Console fields: `amem`, `amenn`, `amemfp`, `amemh`, `amemx`.

## Multi-engine

Engine id: `agent_memory` (`ENGINE_AGENT_MEMORY`).

`signal_from_agent_memory` is advisory evidence only. Unsafe execute/submit/promote/`ranking_permission_granted` flags force blocked.

Bridge order: first MEV deepen -> human-gate dry-run -> agent memory attach -> re-deepen so MEV can include memory posture.

## Scheduler

- **T-010** `agent_memory_agent` depends on report/residual/MEV/human-gate dry-run stages
- **B-007** parallel batch: `["T-010"]`
- Never unlocks submit or execution

## Module API

```python
from app.agent_memory import (
    run_agent_memory,
    build_agent_memory,
    attach_agent_memory_to_bridge_result,
)
```

Statuses: `agent_memory_ready` | `agent_memory_empty` | `agent_memory_package_missing` | `agent_memory_export_written`.

## What this is not

- Not confirmed vulnerability memory
- Not automatic triage decisions
- Not permission to run validation or open PRs
- Not a substitute for live H1 human gates
