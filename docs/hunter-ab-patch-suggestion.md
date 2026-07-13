# Patch Suggestion Scaffold (v0)

Final-scheme **Patch Agent** seed: root-cause-oriented fix and regression guidance.

## Hard safety

- Advisory only (`status=advisory_patch_suggestion`)
- `patch_ready=false` always in this stage
- `auto_pr_allowed=false` / `pr_opened=false`
- `exploit_poc_included=false`
- Never executes validation
- Never unlocks report submission
- Never sets `confirmed_vulnerability=true`

## Families covered (playbooks)

| Family | Root-cause direction |
| --- | --- |
| ssrf | Shared URL validation / private-IP block before outbound fetch |
| authorization | Object ownership / permission checks in shared service layer |
| path_traversal | Canonicalize + root confinement |
| mass_assignment | Explicit allowlist / DTO mapping |
| injection | Parameterized / safe APIs at shared sinks |
| generic | Human must confirm root cause first |

Anti-patterns follow final scheme 5.11 (no frontend-only, no single-payload filters).

## API

```python
from app.patch_suggestion import (
    build_patch_suggestion,
    attach_patch_suggestions_to_bridge_result,
)

suggestion = build_patch_suggestion(
    package_id="pkg",
    candidate=card,
    multi_engine_verdict=verdict,
)
assert suggestion.auto_pr_allowed is False
assert suggestion.exploit_poc_included is False

out = attach_patch_suggestions_to_bridge_result(bridge_result)
assert out["report_submission_allowed"] is False
```

## Wiring

- `build_submission_blocked_report_bundle` attaches `patch_suggestion`
- `run_ab_report_bridge.py` calls `attach_patch_suggestions_to_bridge_result`
- Industrial scheduler DAG includes advisory `T-008 patch_agent` after report agent

## Module / tests

- `apps/api/app/patch_suggestion`
- `apps/api/tests/test_patch_suggestion.py`