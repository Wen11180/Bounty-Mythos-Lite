# Multi-Engine Verifier (deeper factory stack)

Updated: 2026-07-12T18:06:59Z

Beyond-A+B factory stage. Non-executing Verifier Agent that aggregates local static and plan-only engines.

## Hard safety

- Never executes live validation
- Never submits reports
- Never sets confirmed_vulnerability=true
- Never auto-promotes findings
- Default blockers: execute_live_validation, touch_real_user_data, submit_report, auto_promote_finding
- Deepen pass still forces execution/validation/submission/promotion false

## Engines

| Engine | Role |
| --- | --- |
| hunter_loop | A+B disposition retain/refute/dedupe |
| codebase_map | gap vs control static facts |
| report_bridge | submission-blocked draft posture |
| human_evidence | optional redacted notes (never secrets) |
| semgrep_advisory | offline Semgrep/SARIF advisory |
| codeql_advisory | offline CodeQL/SARIF advisory |
| crs_fuzzing | plan-only parser/harness candidates |
| residual_runner | local residual static probes (approval-gated) |
| authorized_web_api | plan-only role-diff / API surface |
| human_residual_gate | residual gate disposition |
| semgrep_runner / codeql_runner | local CLI runner posture |

## Verdicts

| Status | Meaning |
| --- | --- |
| needs_verification | insufficient engine signals |
| local_static_consistent | engines agree candidate is still unverified but worth human review |
| needs_human_review | disagreement or partial support |
| false_positive_likely | engines oppose candidate |
| blocked | scope/safety/engine block |

`local_static_consistent` is **not** exploit verification.

## Deepen API

```python
from app.multi_engine_verifier import (
    deepen_multi_engine_verdict,
    attach_deeper_multi_engine_to_bridge_result,
    signal_from_crs_fuzzing,
)

deep = deepen_multi_engine_verdict(
    base_verdict,
    candidate=card,
    crs_fuzzing=crs_payload,
    residual_runner=residual_payload,
    authorized_web_api=web_payload,
    residual_gates=gates,
)
assert deep.execution_allowed is False
assert deep.confirmed_vulnerability is False
```

## Bridge

`run_ab_report_bridge.py` calls `attach_deeper_multi_engine_to_bridge_result` after CRS/residual/Web/API/patch attaches.

Console: `mevdeep=` / `mevenc=`

Package fields:

- `multi_engine_deep`
- `multi_engine_engine_count`
- `multi_engine_engines`
- per-verdict `deep_stack_attached`, `engine_count`

## Scheduler

- Task `T-006b` agent `verifier_agent` / batch `B-003b`
- `T-007` depends on `T-006b`
- Always `requires_human_review=True`, `execution_allowed=False`

## Tests

`apps/api/tests/test_multi_engine_verifier.py` (includes deepen + attach safety floor).

## Done in this slice

- Deeper multi-engine signals from CRS / residual / Web-API / residual-gate / local runners
- Bridge second-pass attach after factory stack
- Scheduler verifier task
- Safety floor preserved

## Not done yet

- Verified exploit state (intentionally never from static agreement alone)
- Approved local fuzz sandbox execution under human gate
- End-to-end human gates with valid H1 when unblocked
