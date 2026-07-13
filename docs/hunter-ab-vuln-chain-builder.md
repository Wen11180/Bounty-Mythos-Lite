# Vulnerability Chain Builder (V4 first-class)

Status: **green** (package-ingest plan/export only)

## What it is

First-class multi-stage vulnerability chain planner superseding the thin nested
deep_research._vulnerability_chains stub for the factory bridge path.

- Inputs: hypotheses, retained candidates, report drafts, confirmed findings,
  residual gates, optional ariant_analysis.variants, offline inputs/chain*.json
- Outputs: multi-stage chain plans with evidence needs, refutation questions,
  safe validation outlines (plan only)
- Optional export under package _export/vuln_chain_builder/ with
  --allow-vuln-chain-builder-export

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
| Module | pps/api/app/vuln_chain_builder/__init__.py |
| Bridge | ttach_vuln_chain_builder_to_bridge_result after variant analysis |
| CLI | --allow-vuln-chain-builder-export |
| Console | cb= / cbn= / cbs= / cbx= |
| MEV | ENGINE_VULN_CHAIN_BUILDER + signal_from_vuln_chain_builder |
| Scheduler | **T-013c** / **B-010c** (uln_chain_builder_agent) |
| Tests | pps/api/tests/test_vuln_chain_builder.py |

## Dual-lab smoke (after this slice)

| Package | vcb status | chains | mevenc |
| --- | --- | --- | --- |
| my-local-ssrf-retain | plan_ready | 7 | **29** |
| my-gh-mealie-inject | plan_ready | 8 | **28** |

(Previous post-VA baseline: 28 / 27.)

## Not claimed

- Not live e2e / H1 submission (H1 still locked_401)
- Not confirmed vulnerabilities
- Not auto-validation or auto-submit
