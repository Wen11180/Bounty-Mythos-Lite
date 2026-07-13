# Finding Dedup / Risk Prioritization (V3 first-class)

Status: **green** (package-ingest plan/export only)

## What it is

First-class finding deduplication + risk prioritization planner for the factory
bridge path. Supersedes thin industrial_scheduler helpers for the attach path
while keeping scheduler DAG tasks T-005 / T-006.

- Inputs: drafts, retained candidates, hypotheses, findings, residual gates,
  multi-engine verdicts, optional offline `inputs/finding_dedup*.json` /
  `risk_prioritization.json` / `dedup.json` / `risk_queue.json`
- Outputs: finding clusters (component + vuln type + root cause + evidence ref)
  and a human-review risk queue (impact, confidence, evidence quality,
  duplicate risk, policy risk)
- Optional export under package `_export/finding_dedup_risk/` with
  `--allow-finding-dedup-risk-export`

## Safety floor (always false)

- execution_allowed
- validation_allowed
- report_submission_allowed
- confirmed_vulnerability
- finding_promotion_allowed
- ranking_permission_granted
- network_access
- live_validation
- process_spawn_allowed

## Wiring

| Surface | Detail |
| --- | --- |
| Module | `apps/api/app/finding_dedup_risk/__init__.py` |
| Bridge | `attach_finding_dedup_risk_to_bridge_result` after deep code reasoning, before deeper MEV |
| CLI | `--allow-finding-dedup-risk-export` |
| Console | `fdr=` / `fdrn=` / `fdrq=` / `fdrs=` / `fdrx=` |
| MEV | `ENGINE_FINDING_DEDUP_RISK` + `signal_from_finding_dedup_risk` |
| Scheduler | **T-005** / **T-006** (`dedup_agent` / `risk_prioritizer`) ? already present |
| Tests | `apps/api/tests/test_finding_dedup_risk.py` |

## Dual-lab smoke (after this slice)

| Package | fdr status | clusters | queue | seeds | mevenc |
| --- | --- | --- | --- | --- | --- |
| my-local-ssrf-retain | plan_ready | 2 | 2 | 2 | **31** |
| my-gh-mealie-inject | plan_ready | 2 | 2 | 2 | **30** |

(Previous post-DCR baseline: 30 / 29.)

## Not claimed

- Not live e2e / H1 submission (H1 still `blocked_401`)
- Not confirmed vulnerabilities
- Not auto-validation, auto-submit, or ranking permission that unlocks execute
