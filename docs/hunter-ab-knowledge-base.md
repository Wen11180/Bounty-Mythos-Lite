# Knowledge Base (final-scheme section 7 / V4)

Updated: 2026-07-12T19:56:51Z

## Purpose

Consolidate audit experience into **structured vulnerability patterns** (not free-text dumps), matching final-scheme section 7:

```json
{
  "pattern_id": "WEB-IDOR-001",
  "name": "Object ownership check missing",
  "category": "authorization",
  "cwe": "CWE-639",
  "applies_to": ["REST API"],
  "code_signals": ["..."],
  "verification_strategy": ["..."],
  "fix_strategy": ["..."],
  "false_positive_checks": ["..."]
}
```

This closes V4 criterion **"能把经验沉淀进知识库"** at plan/catalog depth.

## Safety floor (always false)

- `execution_allowed`
- `validation_allowed`
- `report_submission_allowed`
- `confirmed_vulnerability`
- `finding_promotion_allowed`
- `ranking_permission_granted`
- `auto_learn_live_sources`
- `network_access`
- `live_validation`

## Inputs

1. Bridge residual stack (preferred after long_horizon):
   - drafts / residual gates
   - deep_research knowledge_updates / queue / variants / patch_diff_learner
   - agent_memory entries
   - long_horizon reflections
   - patch_validation presence
2. Optional offline:
   - `inputs/knowledge_base.json`
   - `inputs/knowledge.json`
   - `inputs/v4_knowledge.json`
   - `inputs/patterns.json`
   - `inputs/knowledge/*.json`
   - `inputs/patterns/*.json`

## Outputs

- Bridge fields: `knowledge_base`, `knowledge_base_status`, `knowledge_base_pattern_count`, `knowledge_base_offline_artifact_count`, `knowledge_base_derived_pattern_count`, `knowledge_base_export_written`, `knowledge_base_ranking_permission_granted=false`
- Optional export (human flag): `_export/knowledge_base/<stamp>/catalog.json` + `patterns.json` + `summary.json`
- MEV engine: `knowledge_base` (`ENGINE_KNOWLEDGE_BASE`)
- Scheduler: **T-015** / **B-012** (`knowledge_base_agent`)

## Bridge attach order (residual tail)

```text
... -> deep_research -> long_horizon -> knowledge_base -> final MEV re-deepen
```

## CLI

```text
python apps/api/scripts/run_ab_report_bridge.py \
  --package-root authorized_packages/<authorized-lab> \
  [--allow-knowledge-base-export]
```

## Dual-lab smoke (expected)

| Field | Expected |
| --- | --- |
| `kbase` | `knowledge_base_ready` or export written |
| `kbasep` | >= 1 |
| `kbasex` | False without export flag |
| `mevenc` | 21 (includes knowledge_base) |
| prior residual stack | still green |
| `submission_blocked` | True |

## Dual-lab smoke (verified 2026-07-12T19:56:51Z)

| package | kbase | kbasep | kbasex | mevenc | lhor | submission_blocked |
| --- | --- | --- | --- | --- | --- | --- |
| my-local-ssrf-retain | knowledge_base_ready | 15 | False | 21 | long_horizon_plan_ready | True |
| my-gh-cal-ssrf | knowledge_base_ready | 15 | False | 21 | long_horizon_plan_ready | True |

Bridge attach order fixed: long_horizon -> knowledge_base -> final MEV re-deepen.

## Tests

```text
$env:PYTHONPATH="apps/api"
.\venv\Scripts\python.exe -m pytest apps/api/tests/test_knowledge_base.py -q
```

## Honest gap after this module

- Catalog consolidation is offline/bridge-derived only; not live CWE/NVD/H1 corpus ingestion
- Patterns never auto-promote ranking permission
- True multi-hour agent loop + H1 e2e human gates remain separate gaps
