# Human Residual Gate (v0)

Final-scheme Human Review gate seed between multi-engine verdicts / report drafts and any human submission decision.

## Hard safety

- Never auto-submits
- Never executes live validation
- Never sets confirmed_vulnerability=true
- human_approved only clears residual checklist context; submission still blocked

## Statuses

| Status | Meaning |
| --- | --- |
| hold_for_human | open residual questions remain |
| ready_for_human_review | residuals answered/waived or none open; human still decides |
| blocked | scope/safety flags |
| human_rejected_or_fp | human closed as FP / not pursued |

## Package residual checklist auto-ingest

Optional offline files (missing is OK):

| Path | Format |
| --- | --- |
| `_extract/RESIDUAL_CHECKLIST.md` | Markdown table or bullets |
| `RESIDUAL_CHECKLIST.md` | Markdown |
| `inputs/residual_checklist.md` | Markdown |
| `inputs/residual.json` / `inputs/residual_checklist.json` | JSON list or `{items:[...]}` |
| `inputs/residual/*.json` | JSON |

Markdown tables commonly used:

```text
| ID | Question | Static status |
| --- | --- | --- |
| PKG-R1 | Is ownership enforced? | **held** |
| PKG-R2 | Soft residual? | **not checked** |
```

Status mapping (fail-soft):

- `held` / `yes` / `present` → `answered`
- `held_documented` / `intentional` / `absent (intentional)` → `waived`
- `not checked` / `pending` / `open` / soft residual → `open`

Filenames containing `secret` / `token` / `cookie` / `credential` / `password` / `apikey` are skipped.

## API

```python
from app.human_residual_gate import (
    build_human_residual_gate,
    attach_human_residual_gates_to_bridge_result,
    load_package_residual_checklist,
)

bundle = load_package_residual_checklist("authorized_packages/my-local-ssrf-retain")
gate = build_human_residual_gate(
    package_id="pkg",
    candidate=card,
    multi_engine_verdict=verdict,
    residual_checklist=bundle["items"] if bundle["present"] else None,
)
assert gate.report_submission_allowed is False

# Bridge auto-loads from package_root / trial residual_checklist_bundle:
out = attach_human_residual_gates_to_bridge_result(
    bridge_result,
    package_root="authorized_packages/my-local-ssrf-retain",
)
assert out["report_submission_allowed"] is False
```

## Module

`apps/api/app/human_residual_gate`

## Tests

`apps/api/tests/test_human_residual_gate.py`